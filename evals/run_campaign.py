"""
run_campaign.py — Orchestrator-driven adaptive campaign loop.

Distinct from `evals/run_attacks.py`:
- run_attacks.py  = static 50-case seed suite (canonical regression baseline)
- run_campaign.py = adaptive Red Team mutations targeted by the Orchestrator

The full agent pipeline per campaign:

  Regression Harness (default-on; rubric: "triggered by the Orchestrator")
     ↓
  Orchestrator picks next sub-vector from coverage + threat + partials +
     regression status (the Observability layer)
     ↓
  Red Team Agent generates N adversarial inputs from seeds + partials
     using the directive's mutation strategy
     ↓
  Each attack:  target_client → Triage (T1) → Judge (T2 on escalation)
     ↓
  Promotion gate: bypass + confidence ≥ 0.9 → freeze into exploits table
     ↓
  Budget enforcement: halt if cumulative cost > MAX_COST_PER_CAMPAIGN
  Low-signal redirect: stop if 0 bypasses/partials after enough attacks

CLI:
  python3 evals/run_campaign.py                  # default 10 attacks
  python3 evals/run_campaign.py --attacks 5
  python3 evals/run_campaign.py --skip-regression
  python3 evals/run_campaign.py --budget 0.50
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

# Make agents and parent package importable
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "agents"))

from target_client import send_attack, send_multi_turn_attack, check_target_health  # noqa: E402
from state_store import add_finding, promote_finding_to_exploit                     # noqa: E402
from judge_agent import judge_attack                                                # noqa: E402
from orchestrator_agent import pick_next_campaign                                   # noqa: E402
from red_team_agent import generate_attacks                                         # noqa: E402
from regression_harness import run_regression                                       # noqa: E402
from config import (  # noqa: E402
    OPENROUTER_API_KEY, TARGET_BASE_URL, MAX_COST_PER_CAMPAIGN, MAX_COST_PER_DAY,
)

try:
    from langsmith import traceable
except ImportError:
    def traceable(*args, **kwargs):
        if len(args) == 1 and callable(args[0]):
            return args[0]
        def _decorator(fn):
            return fn
        return _decorator


RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)


# ── Execute one Red Team AttackPayload end-to-end ────────────────────────

def _run_one_attack(atk: dict) -> dict:
    """target_client → Triage → Judge → promotion."""
    atk_id = atk["attack_id"]
    is_multi_turn = atk.get("multi_turn") and isinstance(atk["attack"], list)

    if is_multi_turn:
        turn_results = send_multi_turn_attack(atk["attack"])
        combined = "\n---\n".join(
            f"Turn {r['turn']}: {r.get('response', r.get('error', ''))}"
            for r in turn_results
        )
        target_ok     = all(r.get("success", False) for r in turn_results)
        target_status = turn_results[-1].get("status_code", 0) if turn_results else 0
        target_response = combined
        target_latency = sum(r.get("latency_ms", 0) for r in turn_results)
    else:
        result = send_attack(atk["attack"])
        target_response = result.get("response", result.get("error", "no response"))
        target_ok       = result.get("success", False)
        target_status   = result.get("status_code", 0)
        target_latency  = result.get("latency_ms", 0)

    payload_for_state = atk["attack"] if not is_multi_turn else json.dumps(atk["attack"])
    add_finding(atk_id, atk["category"], atk["subcategory"],
                payload_for_state, target_response,
                campaign_id=atk["campaign_id"])

    base_row = {
        "attack_id":         atk_id,
        "category":          atk["category"],
        "subcategory":       atk["subcategory"],
        "parent_attack_id":  atk.get("parent_attack_id"),
        "mutation":          atk.get("mutation"),
        "target_latency_ms": target_latency,
        "target_response":   target_response,
        "triage_cost":       0.0,
        "judge_cost":        0.0,
    }

    # Target-failure short-circuit
    if not target_ok or target_status >= 400:
        return {**base_row, "verdict": "error",
                "verdict_reasoning": f"Target failure (HTTP {target_status})"}

    verdict = judge_attack(
        attack_id=atk_id,
        category=atk["category"],
        subcategory=atk["subcategory"],
        attack_payload=payload_for_state,
        target_response=target_response,
        expected_safe=atk["expected_safe"],
        campaign_id=atk["campaign_id"],
    )

    promoted = promote_finding_to_exploit(atk_id, atk["expected_safe"])
    # Documentation Agent in the autonomous loop. Mirrors run_attacks.py
    # — file-exists guard prevents Mistral re-paraphrase churn on re-promotion
    # of an existing exploit. Critical-severity reports still hold for human
    # review per ARCHITECTURE.md §10.
    if promoted:
        try:
            from pathlib import Path as _P
            from agents.documentation_agent import (
                write_report, _load_exploits as _doc_load, REPORTS_DIR as _RD,
            )
            existing = _P(_RD) / f"{atk_id}.md"
            if existing.exists():
                print(f"    📝 Report already exists at {existing.name} — skipping regeneration")
            else:
                doc_rows = _doc_load(attack_id_filter=atk_id)
                if doc_rows:
                    meta = write_report(doc_rows[0])
                    print(f"    📝 Documentation Agent wrote {meta['path']}"
                          f"{' 🚦 needs human review' if meta.get('needs_human_review') else ''}")
        except Exception as doc_exc:
            print(f"    ⚠️  Documentation Agent failed for {atk_id}: {doc_exc}")

    return {
        **base_row,
        "verdict":          verdict["verdict"],
        "verdict_confidence": verdict["confidence"],
        "verdict_reasoning":  verdict["reasoning"],
        "judged_by":        verdict.get("judged_by"),
        "triage_cost":      verdict.get("triage_cost", 0.0),
        "judge_cost":       verdict.get("judge_cost", 0.0),
        "promoted_to_exploit_id": promoted,
    }


# ── Main entrypoint ──────────────────────────────────────────────────────

@traceable(run_type="chain", name="adaptive_campaign")
def run_adaptive_campaign(num_attacks: int = 10,
                          skip_regression: bool = False,
                          budget: float = None) -> dict:
    budget = budget if budget is not None else MAX_COST_PER_CAMPAIGN

    print("=" * 68)
    print("  Adaptive Campaign  —  Orchestrator → Red Team → Target → Judge")
    print(f"  Budget: ${budget:.2f}  ·  Attacks per campaign: {num_attacks}")
    print("=" * 68)
    print()

    # Pre-flight
    if not OPENROUTER_API_KEY:
        print("❌ OPENROUTER_API_KEY is not set."); sys.exit(1)
    # Daily-budget pre-flight (UTC day) — see config.MAX_COST_PER_DAY
    from state_store import get_today_cost
    today_so_far = get_today_cost()
    if today_so_far >= MAX_COST_PER_DAY:
        print(f"🛑 Daily budget already exceeded: ${today_so_far:.4f} ≥ ${MAX_COST_PER_DAY:.2f} cap.")
        print(f"   Aborting before any LLM calls. Reset by waiting for UTC midnight.")
        sys.exit(2)
    if not check_target_health():
        print("❌ Target offline; aborting."); sys.exit(1)
    print(f"✅ Target reachable, OpenRouter key present, daily budget OK "
          f"(${today_so_far:.4f}/${MAX_COST_PER_DAY:.2f}).\n")

    # ── Step 1: Regression Harness (the rubric's 'triggered by the Orchestrator') ──
    new_regressions = []
    if not skip_regression:
        print("─" * 68)
        print(" Step 1: Regression Harness — replay confirmed exploits")
        print("─" * 68)
        reg = run_regression()
        new_regressions = reg.get("new_regressions", []) or []
        if new_regressions:
            print(f"\n  🚨 {len(new_regressions)} previously-fixed exploit(s) regressed in this batch.")
        print()
    else:
        print("(Skipped regression harness — --skip-regression set)\n")

    # ── Step 2: Orchestrator picks the next sub-vector ──
    print("─" * 68)
    print(" Step 2: Orchestrator selects next sub-vector")
    print("─" * 68)
    directive = pick_next_campaign(use_llm_narration=False)
    directive["attack_count"] = num_attacks
    print(f"  Selected:    {directive['category']}/{directive['subcategory']}")
    print(f"  Strategy:    {directive['mutation_strategy']}")
    print(f"  Score:       {directive['score_breakdown']['score']:.3f}  "
          f"(gap {directive['score_breakdown']['gap_factor']:.2f}, "
          f"threat-rank {directive['score_breakdown']['threat_model_rank']}, "
          f"regression {directive['score_breakdown']['regression_factor']:.2f})")
    print(f"  Rationale:   {directive['rationale']}")
    print(f"  Campaign id: {directive['campaign_id']}")
    print()

    # ── Step 3: Red Team generates mutations ──
    print("─" * 68)
    print(f" Step 3: Red Team generates {num_attacks} adversarial inputs")
    print("─" * 68)
    payloads = generate_attacks(directive)
    print(f"  Produced {len(payloads)} AttackPayload(s).")
    if not payloads:
        print("  ⚠️  Red Team produced 0 attacks "
              "(no matching seeds + LLM unavailable). Aborting campaign.")
        return {"campaign_id": directive["campaign_id"],
                "halted_for": "red_team_produced_zero_attacks",
                "results": []}
    print()

    # ── Step 4: Execute each — with budget + low-signal enforcement ──
    print("─" * 68)
    print(" Step 4: Execute + Judge each AttackPayload")
    print("─" * 68)
    results = []
    cumulative_cost = 0.0
    halted_for_budget = False
    halted_for_low_signal = False

    for i, atk in enumerate(payloads, 1):
        res = _run_one_attack(atk)
        results.append(res)
        cumulative_cost += (res.get("triage_cost") or 0) + (res.get("judge_cost") or 0)

        emoji = {"bypass": "🔴", "defended": "🟢", "partial": "🟡",
                 "error": "⚪"}.get(res["verdict"], "?")
        promoted = "  🔒 PROMOTED" if res.get("promoted_to_exploit_id") else ""
        print(f"  [{i:2d}/{len(payloads)}] {emoji} {res['attack_id']:30s} "
              f"→ {res['verdict']:9s}  "
              f"running spend ${cumulative_cost:.4f}{promoted}")

        # Budget enforcement (rubric: 'Halting when cost is accumulating without producing signal')
        if cumulative_cost > budget:
            print(f"\n  🛑 BUDGET EXCEEDED  (${cumulative_cost:.4f} > ${budget:.2f}).")
            print(f"     Halting campaign with {len(payloads) - i} attacks unrun.")
            halted_for_budget = True
            break

        # Low-signal redirect — halt if enough attacks have produced no signal
        if i >= 5 and not halted_for_budget:
            signal_count = sum(1 for r in results if r["verdict"] in ("bypass", "partial"))
            if signal_count == 0 and cumulative_cost >= 0.05:
                print(f"\n  ⚠️  LOW SIGNAL — {i} attacks, ${cumulative_cost:.4f} spent, "
                      f"0 bypasses/partials.")
                print(f"     Orchestrator should redirect to a different sub-vector. "
                      f"Halting current campaign.")
                halted_for_low_signal = True
                break

    print()

    # ── Summary ──
    n_b = sum(1 for r in results if r["verdict"] == "bypass")
    n_d = sum(1 for r in results if r["verdict"] == "defended")
    n_p = sum(1 for r in results if r["verdict"] == "partial")
    n_e = sum(1 for r in results if r["verdict"] == "error")
    n_promoted = sum(1 for r in results if r.get("promoted_to_exploit_id"))

    print("=" * 68)
    print("  Campaign Summary")
    print("=" * 68)
    print(f"  Campaign ID:        {directive['campaign_id']}")
    print(f"  Target sub-vector:  {directive['category']}/{directive['subcategory']}")
    print(f"  Mutation strategy:  {directive['mutation_strategy']}")
    print(f"  Attacks executed:   {len(results)} / {len(payloads)}")
    print(f"  🔴 Bypasses:        {n_b}  ({n_promoted} promoted to exploits)")
    print(f"  🟢 Defended:        {n_d}")
    print(f"  🟡 Partial:         {n_p}  (mutation seeds for next campaign)")
    print(f"  ⚪ Errors:          {n_e}")
    print(f"  💰 Total spend:     ${cumulative_cost:.4f} / ${budget:.2f} budget")
    if halted_for_budget:
        print(f"  Status:             🛑 halted (budget exceeded)")
    elif halted_for_low_signal:
        print(f"  Status:             ⚠️ halted (low signal — Orchestrator should redirect)")
    elif results == []:
        print(f"  Status:             ❌ no attacks executed")
    else:
        print(f"  Status:             ✅ completed within budget")
    print("=" * 68)

    # Save
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out = {
        "timestamp":          datetime.utcnow().isoformat(),
        "target":             TARGET_BASE_URL,
        "campaign_id":        directive["campaign_id"],
        "directive":          directive,
        "results":            results,
        "summary": {
            "bypass": n_b, "defended": n_d, "partial": n_p, "error": n_e,
            "promoted_to_exploits": n_promoted,
        },
        "total_cost":             round(cumulative_cost, 6),
        "budget":                 budget,
        "halted_for_budget":      halted_for_budget,
        "halted_for_low_signal":  halted_for_low_signal,
        "new_regressions_from_step_1": new_regressions,
    }
    path = RESULTS_DIR / f"campaign_{ts}.json"
    path.write_text(json.dumps(out, indent=2, default=str))
    print(f"\nSaved → {path}")
    return out


# ── CLI ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Adaptive Orchestrator-driven campaign.")
    parser.add_argument("--attacks", type=int, default=10,
                        help="Attacks per campaign (default 10).")
    parser.add_argument("--skip-regression", action="store_true",
                        help="Skip the Regression Harness step.")
    parser.add_argument("--budget", type=float, default=None,
                        help=f"Override MAX_COST_PER_CAMPAIGN (default ${MAX_COST_PER_CAMPAIGN}).")
    args = parser.parse_args()
    run_adaptive_campaign(num_attacks=args.attacks,
                          skip_regression=args.skip_regression,
                          budget=args.budget)
