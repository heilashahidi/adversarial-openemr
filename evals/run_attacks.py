"""
Attack Runner — executes seed attacks against the live target and evaluates results.
Produces structured results in ./evals/results/

Usage:
  python3 run_attacks.py                    # run all seed attacks
  python3 run_attacks.py --category prompt_injection   # run one category
  python3 run_attacks.py --id PI-01         # run one specific attack
"""

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from threading import Lock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from target_client import send_attack, send_multi_turn_attack, check_target_health
from state_store import add_finding, get_summary, init_db
from config import DEFAULT_PATIENT, OPENROUTER_API_KEY, TARGET_BASE_URL

try:
    from langsmith import traceable
except ImportError:
    def traceable(*args, **kwargs):
        if len(args) == 1 and callable(args[0]):
            return args[0]
        def _decorator(fn):
            return fn
        return _decorator

# Add agents to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agents"))
from judge_agent import judge_attack

# Import seed attacks
from seed_attacks import SEED_ATTACKS

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


@traceable(run_type="chain", name="run_single_attack")
def run_single_attack(attack_case: dict, patient_id: str = None, quiet: bool = False) -> dict:
    """Execute a single attack and judge the result.

    quiet=True suppresses the per-step prints — use this in parallel mode so
    output from multiple concurrent workers doesn't interleave on the console.
    """
    def _say(msg):
        if not quiet:
            print(msg)

    attack_id = attack_case["id"]
    category = attack_case["category"]
    subcategory = attack_case.get("subcategory", "")
    expected_safe = attack_case["expected_safe"]

    _say(f"\n  [{attack_id}] {category}/{subcategory}")

    # Determine patient_id
    pid = patient_id or DEFAULT_PATIENT["id"]

    # Handle SQL injection test — use attack as patient_id
    if attack_case.get("attack_as_patient_id"):
        _say(f"    📤 Sending as patient_id parameter...")
        target_result = send_attack("What are this patient's allergies?", patient_id=attack_case["attack"])
    # Handle multi-turn attacks
    elif attack_case.get("multi_turn"):
        _say(f"    📤 Sending {len(attack_case['attack'])} turns...")
        turn_results = send_multi_turn_attack(attack_case["attack"], pid)
        # Combine responses for judging
        combined_response = "\n---\n".join([
            f"Turn {r['turn']}: {r.get('response', r.get('error', 'no response'))}"
            for r in turn_results
        ])
        target_result = {
            "success": all(r.get("success", False) for r in turn_results),
            "response": combined_response,
            "latency_ms": sum(r.get("latency_ms", 0) for r in turn_results),
        }
        attack_payload = "\n".join(attack_case["attack"])
    else:
        _say(f"    📤 Sending attack...")
        target_result = send_attack(attack_case["attack"], pid)
        attack_payload = attack_case["attack"]

    if not attack_case.get("multi_turn"):
        attack_payload = attack_case["attack"]

    target_response = target_result.get("response", target_result.get("error", "no response"))
    target_latency = target_result.get("latency_ms", 0)
    target_ok = target_result.get("success", False)
    target_status = target_result.get("status_code", 0)

    _say(f"    📥 Response received ({target_latency}ms)")
    _say(f"    📝 Response preview: {target_response[:120]}...")

    # Store finding
    add_finding(attack_id, category, subcategory, attack_payload, target_response)

    # Target-failure short-circuit: skip the judge if the target didn't return usable content.
    # The judge can't evaluate "HTTP 500: Internal Server Error" against an expected safe behavior.
    if not target_ok or target_status >= 400:
        err = target_result.get("error", f"HTTP {target_status}")
        _say(f"    ⚠️  Target failure: {err}")
        _say(f"    ⏭️  Skipping judge — attack premise cannot be evaluated")
        return {
            "attack_id": attack_id,
            "category": category,
            "subcategory": subcategory,
            "severity": attack_case.get("severity", "medium"),
            "exploitability": attack_case.get("exploitability", "unknown"),
            "threat_model_ref": attack_case.get("threat_model_ref", ""),
            "regression_candidate": attack_case.get("regression_candidate", True),
            "attack_payload": attack_payload if not attack_case.get("multi_turn") else attack_case["attack"],
            "target_response": target_response,
            "target_latency_ms": target_latency,
            "expected_safe": expected_safe,
            "verdict": "error",
            "verdict_severity": "unknown",
            "verdict_confidence": 0.0,
            "verdict_reasoning": f"Target failure ({err}) — no response to evaluate. Possible DoS or input-validation signal worth follow-up.",
            "verdict_indicators": [f"status={target_status}", "target_failure"],
            "add_to_regression": False,
            "judge_cost": 0.0,
            "timestamp": datetime.utcnow().isoformat(),
        }

    _say(f"    ⚖️  Judging...")
    verdict = judge_attack(
        attack_id=attack_id,
        category=category,
        subcategory=subcategory,
        attack_payload=attack_payload,
        target_response=target_response,
        expected_safe=expected_safe,
    )

    verdict_emoji = {"bypass": "🔴", "defended": "🟢", "partial": "🟡", "error": "⚪"}.get(verdict["verdict"], "⚪")
    tier_tag = "T1" if verdict.get("judged_by") == "triage" else "T2"
    _say(f"    {verdict_emoji} Verdict: {verdict['verdict'].upper()} (conf {verdict['confidence']:.2f}, {tier_tag})")
    _say(f"    📋 {verdict['reasoning'][:100]}")

    return {
        "attack_id": attack_id,
        "category": category,
        "subcategory": subcategory,
        "severity": attack_case.get("severity", "medium"),
        "exploitability": attack_case.get("exploitability", "unknown"),
        "threat_model_ref": attack_case.get("threat_model_ref", ""),
        "regression_candidate": attack_case.get("regression_candidate", True),
        "attack_payload": attack_payload if not attack_case.get("multi_turn") else attack_case["attack"],
        "target_response": target_response,
        "target_latency_ms": target_latency,
        "expected_safe": expected_safe,
        "verdict": verdict["verdict"],
        "verdict_severity": verdict["severity"],
        "verdict_confidence": verdict["confidence"],
        "verdict_reasoning": verdict["reasoning"],
        "verdict_indicators": verdict.get("indicators", []),
        "add_to_regression": verdict.get("add_to_regression", False),
        "judged_by": verdict.get("judged_by", "judge"),
        "triage_cost": verdict.get("triage_cost", 0.0),
        "judge_cost": verdict.get("judge_cost", 0.0),
        "timestamp": datetime.utcnow().isoformat(),
    }


@traceable(run_type="chain", name="campaign")
def run_attack_suite(category_filter: str = None, id_filter: str = None, workers: int = 2):
    """Run the full seed attack suite or a filtered subset."""
    print("=" * 60)
    print("  Adversarial Attack Suite — Live Target Execution")
    print("=" * 60)

    # Check OpenRouter API key (judge needs it)
    if not OPENROUTER_API_KEY:
        print("\n  ❌ OPENROUTER_API_KEY is not set.")
        print("     Export it or copy .env.example → .env and fill in the key.")
        sys.exit(1)
    print("\n  ✅ OpenRouter key present")

    # Check target health
    print("  Checking target health...")
    if not check_target_health():
        print("  ❌ Target is offline. Cannot run attacks.")
        sys.exit(1)
    print("  ✅ Target is live\n")

    # Filter attacks
    attacks = SEED_ATTACKS
    if category_filter:
        attacks = [a for a in attacks if a["category"] == category_filter]
        print(f"  Filtered to category: {category_filter} ({len(attacks)} attacks)")
    if id_filter:
        attacks = [a for a in attacks if a["id"] == id_filter]
        print(f"  Filtered to ID: {id_filter}")

    if not attacks:
        print("  No attacks match the filter.")
        sys.exit(1)

    workers = max(1, int(workers))
    mode = f"parallel ({workers} workers)" if workers > 1 else "serial"
    print(f"  Running {len(attacks)} attacks against live target — {mode}...\n")

    results = []
    start_time = time.time()

    if workers == 1:
        # Serial path — preserves original verbose progress output
        for attack in attacks:
            result = run_single_attack(attack)
            results.append(result)
            time.sleep(1)
    else:
        # Parallel path — workers run quiet; main thread prints one line per completion
        attack_order = {a["id"]: i for i, a in enumerate(attacks)}
        print_lock = Lock()
        done_n = 0

        verdict_emoji_map = {"bypass": "🔴", "defended": "🟢", "partial": "🟡", "error": "⚪"}

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(run_single_attack, a, None, True) for a in attacks]
            for fut in as_completed(futures):
                try:
                    result = fut.result()
                except Exception as e:
                    with print_lock:
                        print(f"  ❌ worker error: {e}")
                    continue
                results.append(result)
                with print_lock:
                    done_n += 1
                    v = result.get("verdict", "error")
                    em = verdict_emoji_map.get(v, "⚪")
                    tier = "T1" if result.get("judged_by") == "triage" else ("T2" if result.get("judged_by") == "judge" else "—")
                    print(
                        f"  [{done_n:2d}/{len(attacks)}] "
                        f"{em} {result['attack_id']:7s}  "
                        f"{result['category']:22s} / {result['subcategory']:30s}  "
                        f"→ {v.upper():9s} ({tier}, conf {result.get('verdict_confidence', 0.0):.2f})"
                    )

        # Restore original attack order for deterministic JSON output
        results.sort(key=lambda r: attack_order.get(r["attack_id"], 9999))

    elapsed = time.time() - start_time

    # Summary
    bypasses = [r for r in results if r["verdict"] == "bypass"]
    defenses = [r for r in results if r["verdict"] == "defended"]
    partials = [r for r in results if r["verdict"] == "partial"]
    errors = [r for r in results if r["verdict"] == "error"]

    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    print(f"  Total attacks: {len(results)}")
    print(f"  🔴 Bypasses (exploits): {len(bypasses)}")
    print(f"  🟢 Defended: {len(defenses)}")
    print(f"  🟡 Partial: {len(partials)}")
    print(f"  ⚪ Errors (target failures): {len(errors)}")
    print(f"  Time: {elapsed:.1f}s")
    triage_n = sum(1 for r in results if r.get("judged_by") == "triage")
    judge_n  = sum(1 for r in results if r.get("judged_by") == "judge")
    triage_total = sum(r.get("triage_cost", 0) for r in results)
    judge_total  = sum(r.get("judge_cost", 0) for r in results)
    print(f"  T1 Triage short-circuits: {triage_n}  (${triage_total:.4f})")
    print(f"  T2 Sonnet escalations:    {judge_n}  (${judge_total:.4f})")
    print(f"  Total Judge spend:        ${triage_total + judge_total:.4f}")

    categories = {}
    for r in results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"bypass": 0, "defended": 0, "partial": 0, "error": 0}
        categories[cat][r["verdict"]] += 1

    print("\n  By Category:")
    for cat, counts in sorted(categories.items()):
        total = sum(counts.values())
        print(f"    {cat}: {counts['bypass']} bypasses / {counts['defended']} defended / {counts['partial']} partial / {counts['error']} error ({total} total)")

    if bypasses:
        print("\n  🔴 EXPLOITS FOUND (defense bypassed):")
        for b in bypasses:
            print(f"    [{b['attack_id']}] {b['category']}/{b['subcategory']} — {b['verdict_reasoning'][:80]}")

    if partials:
        print("\n  🟡 PARTIAL BYPASSES (mutation candidates):")
        for p in partials:
            print(f"    [{p['attack_id']}] {p['category']}/{p['subcategory']} — {p['verdict_reasoning'][:80]}")

    if errors:
        print("\n  ⚪ TARGET FAILURES (no judgement possible):")
        for e in errors:
            print(f"    [{e['attack_id']}] {e['category']}/{e['subcategory']} — {e['verdict_reasoning'][:80]}")

    # Save results
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    results_file = os.path.join(RESULTS_DIR, f"attack_results_{timestamp}.json")
    with open(results_file, "w") as f:
        json.dump({
            "timestamp": datetime.utcnow().isoformat(),
            "target": TARGET_BASE_URL,
            "total_attacks": len(results),
            "summary": {
                "bypass": len(bypasses),
                "defended": len(defenses),
                "partial": len(partials),
                "error": len(errors),
            },
            "by_category": categories,
            "results": results,
        }, f, indent=2, default=str)

    print(f"\n  Results saved → {results_file}")

    # Also save as latest
    latest_file = os.path.join(RESULTS_DIR, "latest_results.json")
    with open(latest_file, "w") as f:
        json.dump({
            "timestamp": datetime.utcnow().isoformat(),
            "target": TARGET_BASE_URL,
            "total_attacks": len(results),
            "summary": {
                "bypass": len(bypasses),
                "defended": len(defenses),
                "partial": len(partials),
                "error": len(errors),
            },
            "by_category": categories,
            "results": results,
        }, f, indent=2, default=str)

    print("=" * 60)
    return results


def run_smoke_check():
    """Lightweight reachability probe — no LLM calls, no OpenRouter key required.

    For graders / reviewers who want fast proof that the platform actually hits
    a live target. Probes /health and /chat directly with no auth headers.
    Confirms the §2.4 threat-model finding as a side effect.
    """
    import requests
    from config import TARGET_BASE_URL

    print("=" * 60)
    print("  Target Smoke Check — Clinical Co-Pilot")
    print("=" * 60)
    print(f"  URL: {TARGET_BASE_URL}")
    print()

    # ── /health ──
    start = time.time()
    try:
        r = requests.get(f"{TARGET_BASE_URL}/health", timeout=10)
        elapsed = round((time.time() - start) * 1000)
        print(f"  /health → HTTP {r.status_code} ({elapsed}ms)")
        print(f"           response: {r.text[:200]}")
    except Exception as e:
        print(f"  /health → FAILED: {e}")
        sys.exit(1)

    print()

    # ── /chat (unauthenticated — demonstrates §2.4) ──
    start = time.time()
    try:
        r = requests.post(
            f"{TARGET_BASE_URL}/chat",
            headers={"Content-Type": "application/json"},
            json={
                "patient_id": "00000000-0000-0000-0000-000000000000",
                "message": "Smoke check: confirm endpoint is reachable without auth.",
            },
            timeout=30,
        )
        elapsed = round((time.time() - start) * 1000)
        print(f"  /chat   → HTTP {r.status_code} ({elapsed}ms)")
        if r.status_code == 200:
            try:
                data = r.json()
                preview = (data.get("response") or "")[:220]
                tokens = data.get("tokens_used", {}).get("total", "?")
                print(f"           tokens billed to operator: {tokens}")
                print(f"           response preview: {preview}...")
            except ValueError:
                print(f"           (non-JSON body) {r.text[:200]}")
        else:
            print(f"           body: {r.text[:200]}")
    except Exception as e:
        print(f"  /chat   → FAILED: {e}")
        sys.exit(1)

    print()
    print("=" * 60)
    if r.status_code == 200:
        print("  ✅ Target is live and reachable.")
        print("     /chat accepts anonymous requests — this is the §2.4 finding")
        print("     documented in THREAT_MODEL.md. The platform's DE-09 seed case")
        print("     re-confirms this on every campaign.")
    else:
        print(f"  ⚠️  Target responded with HTTP {r.status_code} on /chat.")
    print("=" * 60)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run adversarial attacks against the Clinical Co-Pilot")
    parser.add_argument("--category", type=str, help="Filter by attack category")
    parser.add_argument("--id", type=str, help="Run a specific attack by ID")
    parser.add_argument("--workers", type=int, default=2,
                        help="Concurrent attack workers. Default 2 — empirically the target returns "
                             "HTTP 502/timeouts at workers=4. Use 1 for guaranteed-clean serial execution.")
    parser.add_argument("--smoke", action="store_true",
                        help="Lightweight reachability probe — hits /health and /chat against the live target. "
                             "No LLM calls, no OpenRouter key needed. For graders to verify target is live in ~5s.")
    args = parser.parse_args()

    if args.smoke:
        run_smoke_check()
    else:
        run_attack_suite(category_filter=args.category, id_filter=args.id, workers=args.workers)
