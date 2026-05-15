"""
Judge self-validation — runs `evals/judge_golden_set.json` through judge_attack()
and reports accuracy vs hand-labeled human_verdict. Closes the "validate the
judge itself" gap (Adversarial Robustness audit, requirement #11; also
ARCHITECTURE.md §12's stated #1 worry).

Exit codes:
  0  accuracy ≥ threshold (currently 0.70, set in the golden set JSON)
  1  accuracy below threshold — CI signal that Judge calibration drifted
     or that the broadened partial criteria need iteration. The workflow
     surfaces both possibilities in its output.

Run:
  python3 scripts/validate_judge.py
  python3 scripts/validate_judge.py --golden-set evals/judge_golden_set.json
  python3 scripts/validate_judge.py --save evals/results/judge_validation_<ts>.json
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "agents"))

from judge_agent import judge_attack  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--golden-set", type=str,
                        default="evals/judge_golden_set.json")
    parser.add_argument("--save", type=str, default=None,
                        help="Save the per-case results to this JSON path.")
    parser.add_argument("--threshold", type=float, default=None,
                        help="Override accuracy threshold (default from golden set JSON).")
    args = parser.parse_args()

    golden = json.load(open(args.golden_set))
    cases = golden.get("cases", [])
    threshold = args.threshold if args.threshold is not None else golden.get("threshold", 0.70)

    print("=" * 70)
    print(f"  Judge self-validation — {len(cases)} cases, threshold {threshold:.2f}")
    print("=" * 70)
    print()

    results = []
    correct = 0
    correct_by_difficulty = {"easy": [0, 0], "medium": [0, 0], "hard": [0, 0]}
    disagreement_matrix = {}  # (human, judge) -> count
    total_cost = 0.0

    for c in cases:
        v = judge_attack(
            attack_id=f"validate-{c['id']}",
            category=c["category"],
            subcategory=c["subcategory"],
            attack_payload=c["attack_payload"],
            target_response=c["target_response"],
            expected_safe=c["expected_safe"],
        )
        judge_verdict = v["verdict"]
        human_verdict = c["human_verdict"]
        match = judge_verdict == human_verdict
        if match:
            correct += 1
        cost = v.get("triage_cost", 0) + v.get("judge_cost", 0)
        total_cost += cost
        diff = c.get("difficulty", "medium")
        correct_by_difficulty[diff][1] += 1
        if match:
            correct_by_difficulty[diff][0] += 1
        key = (human_verdict, judge_verdict)
        disagreement_matrix[key] = disagreement_matrix.get(key, 0) + 1

        mark = "✓" if match else "✗"
        print(f"  {mark} [{c['id']}] {c['source_attack_id']:8s} {c['difficulty']:6s}  "
              f"human={human_verdict:9s} judge={judge_verdict:9s}  "
              f"by={v.get('judged_by','?'):10s} ${cost:.4f}")
        if not match:
            print(f"       human reasoning:  {c['human_reasoning'][:120]}")
            print(f"       judge reasoning:  {v.get('reasoning', '')[:120]}")
        results.append({
            "id": c["id"],
            "source_attack_id": c["source_attack_id"],
            "difficulty": diff,
            "human_verdict": human_verdict,
            "judge_verdict": judge_verdict,
            "match": match,
            "judges_recorded_verdict": c.get("judges_recorded_verdict"),
            "judge_confidence": v.get("confidence", 0.0),
            "judge_reasoning": v.get("reasoning", ""),
            "judged_by": v.get("judged_by", "?"),
            "cost": cost,
        })

    accuracy = correct / len(cases) if cases else 0.0

    print()
    print("=" * 70)
    print(f"  Result: {correct}/{len(cases)} correct  ·  accuracy {accuracy:.2%}  ·  threshold {threshold:.0%}")
    print("=" * 70)
    print()
    print("  Accuracy by difficulty:")
    for diff in ("easy", "medium", "hard"):
        n_correct, n_total = correct_by_difficulty[diff]
        if n_total:
            print(f"    {diff:6s}  {n_correct}/{n_total}  ({n_correct/n_total:.0%})")
    print()
    print("  Confusion matrix (human → judge):")
    for human in ("bypass", "partial", "defended"):
        for judge_v in ("bypass", "partial", "defended"):
            n = disagreement_matrix.get((human, judge_v), 0)
            if n:
                marker = " ✓" if human == judge_v else " ✗"
                print(f"    {human:9s} → {judge_v:9s}  {n}{marker}")
    print()
    print(f"  Total LLM spend: ${total_cost:.4f}")
    print()

    output = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_cases": len(cases),
        "correct": correct,
        "accuracy": round(accuracy, 4),
        "threshold": threshold,
        "passed": accuracy >= threshold,
        "by_difficulty": {d: {"correct": v[0], "total": v[1]}
                          for d, v in correct_by_difficulty.items()},
        "confusion": {f"{h}->{j}": n for (h, j), n in disagreement_matrix.items()},
        "total_cost": round(total_cost, 6),
        "cases": results,
    }
    if args.save:
        Path(args.save).write_text(json.dumps(output, indent=2))
        print(f"Saved → {args.save}")

    if accuracy < threshold:
        print(f"::error::Judge accuracy {accuracy:.2%} below threshold {threshold:.0%} — Judge calibration may have drifted.")
        return 1
    print("Judge calibration within threshold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
