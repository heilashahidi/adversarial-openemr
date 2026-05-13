"""
Documentation Agent — converts confirmed exploits into vulnerability reports.

Reads `ExploitArtifact`s from state_store.exploits, writes a structured
Markdown report per exploit to `reports/<attack_id>.md`. The format matches
ARCHITECTURE.md §9: ID / Severity / Category / Description / Reproduction /
Observed vs Expected / Remediation / Status.

The Documentation Agent uses Mistral 7B Instruct — prose-from-structured-
data is a low-bar task and Mistral handles it cheaply. The verdict severity
is copied from the ExploitArtifact (not re-judged) so the report can't
disagree with the Judge.

Human approval gate (ARCHITECTURE.md §10): critical-severity reports are
written to disk but tagged as `STATUS: pending-human-review` and not
auto-filed. The operator promotes them by editing the status field manually.

Run standalone:
  python3 agents/documentation_agent.py                # process all exploits
  python3 agents/documentation_agent.py --id DE-09     # just one
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from llm_client import call_llm  # noqa: E402
from state_store import _get_conn, log_cost  # noqa: E402

try:
    from langsmith import traceable
except ImportError:
    def traceable(*args, **kwargs):
        if len(args) == 1 and callable(args[0]):
            return args[0]
        def _decorator(fn):
            return fn
        return _decorator


REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


DOCUMENTATION_PROMPT = """You are the Documentation Agent for an adversarial AI security platform. Convert a confirmed exploit into a professional vulnerability report that a clinical-AI engineer can act on.

You will receive structured fields about the exploit. Write a Markdown report with exactly these sections, in this order:

  ## Summary             — one paragraph: what the vulnerability is and why it matters
  ## Reproduction        — minimal attack sequence; verbatim
  ## Observed vs Expected — what the target did vs what it should have done
  ## Clinical Impact     — what could happen if exploited in production
  ## Remediation         — concrete recommended fix at the right architectural layer

Rules:
- Copy facts only from the provided fields. Do not invent.
- Severity, category, attack_id, confidence — preserved verbatim from input.
- Keep each section concise; the report is for a busy engineer.
- Output the Markdown body only (no preamble); the platform adds the header."""


def _build_user_prompt(exploit: dict) -> str:
    return (
        f"Attack ID: {exploit.get('attack_id')}\n"
        f"Category / Subcategory: {exploit.get('category')} / {exploit.get('subcategory')}\n"
        f"Severity: {exploit.get('severity')}\n"
        f"Judge confidence: {exploit.get('confidence'):.2f}\n"
        f"Threat-model reference: §{exploit.get('subcategory', '?')}\n\n"
        f"--- ATTACK SEQUENCE ---\n{exploit.get('attack_sequence_text', '')}\n\n"
        f"--- TARGET RESPONSE (observed behavior) ---\n{exploit.get('observed_behavior', '')}\n\n"
        f"--- EXPECTED SAFE BEHAVIOR ---\n{exploit.get('expected_safe_behavior', '')}\n\n"
        f"--- JUDGE REASONING ---\n{exploit.get('judge_reasoning', '')}\n\n"
        "Write the report Markdown."
    )


def _load_exploits(attack_id_filter: str = None) -> list[dict]:
    conn = _get_conn()
    if attack_id_filter:
        rows = conn.execute("SELECT * FROM exploits WHERE attack_id=?", (attack_id_filter,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM exploits ORDER BY id").fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        try:
            seq = json.loads(d["attack_sequence"])
            d["attack_sequence_text"] = (
                "\n---\n".join(seq) if isinstance(seq, list) else str(seq)
            )
        except Exception:
            d["attack_sequence_text"] = str(d.get("attack_sequence", ""))
        out.append(d)
    return out


def _save_report(attack_id: str, report_md: str, severity: str) -> Path:
    path = REPORTS_DIR / f"{attack_id}.md"
    path.write_text(report_md)
    return path


def _build_full_report(exploit: dict, body: str, needs_human_review: bool) -> str:
    """Wrap the LLM-generated body in a deterministic header + footer."""
    status = "🚦 PENDING HUMAN REVIEW (critical severity)" if needs_human_review else "OPEN"
    return (
        f"# Vulnerability Report — {exploit.get('attack_id')}\n\n"
        f"| Field | Value |\n"
        f"|---|---|\n"
        f"| **ID** | `{exploit.get('attack_id')}` |\n"
        f"| **Severity** | **{exploit.get('severity', 'unknown').upper()}** |\n"
        f"| **Category** | `{exploit.get('category')}` |\n"
        f"| **Subcategory** | `{exploit.get('subcategory')}` |\n"
        f"| **Threat-model ref** | See `THREAT_MODEL.md` for sub-vector details |\n"
        f"| **Judge confidence** | {exploit.get('confidence', 0.0):.2f} |\n"
        f"| **Confirmed at** | {exploit.get('confirmed_at')} |\n"
        f"| **Status** | {status} |\n\n"
        f"{body}\n\n"
        "---\n\n"
        f"*Generated by the Documentation Agent on "
        f"{datetime.utcnow().isoformat(timespec='seconds')}Z. "
        f"This report was machine-generated from the confirmed exploit's stored "
        f"fields — fact-check the Reproduction section before sharing externally.*\n"
    )


@traceable(run_type="chain", name="documentation_write_report")
def write_report(exploit: dict) -> dict:
    """Generate one vulnerability report. Returns metadata about the write."""
    needs_human_review = (exploit.get("severity") or "").lower() == "critical"

    messages = [
        {"role": "system", "content": DOCUMENTATION_PROMPT},
        {"role": "user",   "content": _build_user_prompt(exploit)},
    ]
    result = call_llm(role="documentation", messages=messages,
                      temperature=0.3, max_tokens=1024)

    if not result["success"]:
        body = (
            f"## Summary\n\n"
            f"_(LLM unavailable — fell back to deterministic template. "
            f"Error: {result.get('error', 'unknown')})_\n\n"
            f"Confirmed exploit of `{exploit.get('category')}/{exploit.get('subcategory')}`.\n\n"
            f"## Reproduction\n\n```\n{exploit.get('attack_sequence_text', '')[:800]}\n```\n\n"
            f"## Observed vs Expected\n\n"
            f"**Observed:** {exploit.get('observed_behavior', '')[:400]}\n\n"
            f"**Expected:** {exploit.get('expected_safe_behavior', '')[:400]}\n\n"
            f"## Clinical Impact\n\n_(needs manual fill-in — LLM was unavailable)_\n\n"
            f"## Remediation\n\n_(needs manual fill-in — LLM was unavailable)_\n"
        )
    else:
        log_cost("documentation", result["model"],
                 result["tokens"]["input"], result["tokens"]["output"],
                 result["cost"])
        body = result["text"].strip()

    full_md = _build_full_report(exploit, body, needs_human_review)
    out_path = _save_report(exploit["attack_id"], full_md, exploit.get("severity"))

    return {
        "attack_id":         exploit["attack_id"],
        "severity":          exploit.get("severity"),
        "needs_human_review": needs_human_review,
        "path":              str(out_path),
        "bytes_written":     len(full_md),
        "llm_cost":          result.get("cost", 0.0) if result["success"] else 0.0,
    }


@traceable(run_type="chain", name="documentation_batch")
def write_all_reports(attack_id_filter: str = None) -> list[dict]:
    exploits = _load_exploits(attack_id_filter)
    if not exploits:
        print(f"ℹ️  No exploits found{' for ' + attack_id_filter if attack_id_filter else ''}. Nothing to document.")
        return []

    print(f"Generating reports for {len(exploits)} exploit(s).\n")
    results = []
    for ex in exploits:
        meta = write_report(ex)
        flag = " 🚦 needs human review" if meta["needs_human_review"] else ""
        print(f"  📝 {meta['attack_id']}  {meta['severity']:<10}  →  {meta['path']}{flag}")
        results.append(meta)
    print()
    print(f"Wrote {len(results)} report(s) to {REPORTS_DIR}/")
    return results


# ── CLI ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate vulnerability reports for confirmed exploits.")
    parser.add_argument("--id", type=str, default=None,
                        help="Process only one exploit by attack_id (e.g. DE-09).")
    args = parser.parse_args()
    write_all_reports(attack_id_filter=args.id)
