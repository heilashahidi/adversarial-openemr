# USERS.md — Platform Users and Workflows

> Companion to `THREAT_MODEL.md` (what the platform attacks) and `ARCHITECTURE.md` (how the platform is built). This document defines **who the platform serves** and **how each user interacts with it**. The Stage 4 rubric names "user definitions" as one of two architectural inputs alongside the threat model — this is that input.

---

## Executive Summary

The adversarial platform has four classes of human users and one class of machine user. Each one's workflow drives concrete architectural decisions. Defining these up front makes the architecture's tradeoffs **defensible** rather than arbitrary: when a reviewer asks "why does the platform have a `--smoke` flag?" the answer is *"because the Grader / Reviewer user needs to verify the target is live in under 10 seconds with no API key"* — not *"it seemed useful."*

**Human users:**

1. **Platform Operator** — runs campaigns, reviews findings, decides what to fix and what to escalate
2. **Grader / Reviewer** — verifies compliance against the W3 rubric in a time-constrained review
3. **Target Maintainer** — receives vulnerability reports and decides remediation
4. **Security Researcher** — forks or extends the platform for other targets

**Machine user:**

5. **The agents themselves** (Orchestrator, Red Team, Triage, Judge, Documentation) — read and write the shared state store as inter-agent communication

---

## 1. Platform Operator

**Who they are:** the person who developed the platform and runs campaigns against the target. Today this is the same individual as the Target Maintainer, but in principle they are separable — a security team could run the platform against a Co-Pilot owned by a different team.

**Workflows:**
- Run a campaign locally: `python3 evals/run_attacks.py`
- Run a fast probe before paying for a full campaign: `python3 evals/run_attacks.py --smoke`
- Re-run a single attack to investigate a verdict: `python3 evals/run_attacks.py --id DE-09`
- Run an adaptive Orchestrator-driven campaign: `python3 evals/run_campaign.py`
- Run a deterministic mutation campaign: `python3 evals/run_encode_mutations.py` (the path that produced the 80 RT-ENC wrapper-pattern findings)
- Re-validate Judge calibration against the golden set: `python3 scripts/validate_judge.py`
- Vacate a false-positive verdict: `python3 agents/documentation_agent.py --withdraw <attack_id> --reason "..."`
- Rebuild a wiped state.db from committed JSONs: `python3 scripts/backfill_state_from_results.py`
- Review the latest run on the deployed dashboard (health badge at top of Overview is the entry point)
- Investigate a specific Judge verdict in LangSmith by clicking through the trace tree
- Decide whether a partial-success seed warrants a Red Team mutation campaign

**What the operator does NOT do (autonomous cron handles it):**
- Trigger periodic campaigns — `adaptive-campaign.yml` fires every 6h, `regression-nightly.yml` daily, `judge-validation.yml` weekly
- Mirror commits to HF + GitLab — `mirror-main.yml` propagates every push automatically
- Check whether anything regressed — Slack webhook fires on workflow failure if `SLACK_WEBHOOK_URL` secret is set

**Architecture this drives:**
- `state_store` exists so the operator can query / inspect / replay any past finding without re-running attacks (zero $-cost replay)
- `--smoke`, `--id`, `--category`, `--workers` CLI flags exist for targeted re-runs and graceful scaling
- Human approval gates (ARCHITECTURE.md §10) sit between agents and irreversible actions: Critical-severity report files, state-modifying attacks, novel-sub-category first runs
- `--withdraw` CLI + non-destructive DB columns (`withdrawn_at`, `withdrawn_reason`) so a false positive doesn't require manual file editing
- Judge golden set + weekly cron means the operator doesn't have to remember to re-check calibration
- LangSmith tracing is on by default so the operator can debug any verdict by clicking through
- Dashboard health badge surfaces three CI signals (regression transitions, Judge accuracy, pipeline health) in one indicator

---

## 2. Grader / Reviewer

**Who they are:** the W3 reviewer auditing compliance against the four-stage rubric. **Time-constrained** — typically 10–20 minutes per project, plus an optional demo video.

**Workflows:**
- Open the GitHub repo, read the README
- Click the live dashboard URL from the README
- Browse the dashboard's Overview → Coverage Map → Attack Browser → Threat Model → Architecture pages
- Click through to LangSmith from the sidebar to verify trace evidence
- Optionally: run `python3 evals/run_attacks.py --smoke` to verify the platform actually hits a live target with their own eyes

**Architecture this drives:**
- README has the target URL, dashboard URL, repo URL in the first paragraph (no scrolling)
- `--smoke` flag exists with **zero API-key dependency** — graders can verify in 5 seconds without paying
- Dashboard is hosted publicly on Hugging Face Spaces — **anonymous-public**, no login gate, no Streamlit Cloud auth-required surprise
- **🟢/🟡/🔴 Health badge** at the top of Overview gives a single-glance answer to "is this platform healthy right now?" — derived from regression transitions + Judge accuracy + recent run state
- Regression-pass-rate-over-time chart on Trends page answers the "are fixes landing?" question with one Altair chart
- **Calibration footer in every vulnerability report** — every `reports/*.md` carries the latest Judge accuracy from the golden set, so the grader sees that the verdict's per-call confidence is paired with the Judge's own measured accuracy (avoids "trust the LLM verdict" anti-pattern)
- 23+ committed result JSONs in `evals/results/` document run-over-run reproducibility across the full session arc (24 → 40 → 44 → 47 → 50 cases)
- Threat-model `Tested by` rows + seed-case `threat_model_ref` fields link rubric items to evidence bidirectionally
- THREAT_MODEL.md now includes **OWASP LLM Top 10 + MITRE ATLAS cross-reference tables** so a security-savvy grader sees standards alignment in 30 seconds
- ARCHITECTURE.md §12 FAQ (defensible Q&A), §13 (comparable tools: garak / PyRIT positioning), §14 (alternatives considered + rejected with rationale)

**What the grader should NOT have to do:**
- Sign up for an OpenRouter account to verify the platform works
- Run a 7-minute attack suite to see basic functionality
- Read 1,200 lines of architecture markdown to find the agent roles
- Click through five pages to find the live target URL
- Click into the Actions tab to find out whether the platform is healthy — the badge surfaces it on the homepage

---

## 3. Target Maintainer

**Who they are:** the Co-Pilot development team — the people responsible for fixing what the platform finds. In this project it is the same individual as the Operator, but the architecture treats them as separable.

**Workflows:**
- Receive a vulnerability report — **auto-filed by the Documentation Agent** on every new exploit promotion (`run_attacks.py` + `run_campaign.py` invoke it; Critical-severity reports hold for human review per §10)
- Read one **consolidated report per root cause** instead of N reports for N variants — `reports/RT-ENC-wrapper-pattern.md` covers all 80 wrapper-pattern exploits with one fix plan
- Cross-reference the finding with the threat model + OWASP LLM + MITRE ATLAS labels in THREAT_MODEL.md
- Implement the fix
- Trust the regression harness to validate — runs nightly, exits non-zero on pass→fail transitions, Slack-alerts on failure
- Watch the regression-pass-rate trend chart to see fixes landing in aggregate

**Architecture this drives:**
- Vulnerability Report Format (ARCHITECTURE.md §9) is structured for engineer-actionable triage: ID, Severity, Category, Description, Reproduction (deterministic — copy-pasteable `curl`), Observed vs Expected, Remediation, Status
- **Calibration footer** on every report communicates the Judge's golden-set accuracy alongside the per-call confidence — the maintainer knows whether to trust the verdict
- Every confirmed bypass carries `threat_model_ref` so the maintainer immediately sees which sub-vector + OWASP/ATLAS technique it tests
- The regression harness re-runs every promoted exploit on each target deploy; **fail-rate dropping is the visible signal that fixes are landing**
- The §2.4 finding's seed case (DE-09) is re-probed every campaign — the day auth is added at the HTTP layer, the DE-09 verdict will flip from `bypass` to `defended` automatically
- Surface-aware replay means upload-path exploits (SC-06/07/08) replay against `/extract` not `/chat`
- Variant-robustness extension catches "fix held for the literal seed but breaks on a base64-wrapped variant" before the next adaptive campaign would find it

**What the target maintainer should NOT have to do:**
- Read the entire campaign log to find the relevant finding → Documentation Agent extracts it as a report
- Triage 80 individual reports for the wrapper-pattern variants → one consolidated report covers all 80 with the same fix plan
- Decide whether behavioral drift counts as a fix → regression harness flags drift as `inconclusive`, not as remediation
- Manually re-validate after deploying a fix → the nightly cron does it and posts to Slack if anything regressed

---

## 4. Security Researcher (forward-looking)

**Who they are:** a hypothetical future user who wants to apply this platform to a different target — another clinical AI, a different domain (legal AI, finance AI), or a hardened version of the same Co-Pilot.

**Workflows:**
- Fork the repo
- Update `config.TARGET_BASE_URL` and `config.PATIENTS` (or the target-equivalent test fixtures)
- Adjust `THREAT_MODEL.md` and `evals/seed_attacks.py` for the new target's surface
- Run their own campaigns

**Architecture this drives:**
- Target-side state lives entirely in `config.py` — **one file to change** to point at a new target
- Seed cases are a list of dicts in `seed_attacks.py` — appendable, no schema migration; per-case `threat_model_ref` lets the researcher map their own sub-vectors; `attack_via_extract` flag enables non-`/chat` surfaces
- Threat model is markdown — editable by hand; the platform doesn't depend on a structured threat-model parser
- The platform makes no target-specific assumptions in the agent code (everything specific to the Co-Pilot is in `config.py` or `seed_attacks.py`)
- Provider pinning is opt-in via `extra_body` — a researcher could disable it to compare verdicts across LLM providers
- Mutation operators in `red_team_agent._mutate_encode` are reusable building blocks for novel mutation pipelines (base64, rot13, unicode_homoglyph; fragment + paraphrase + embed for AI-driven variants)
- Judge golden set + validation workflow is generic — point at a different target, build a target-specific golden set, run the same calibration loop
- ARCHITECTURE.md §13 comparison vs **garak / PyRIT** documents where this platform fits in the field — useful for a researcher deciding which tool to adopt or extend

**What the security researcher should NOT have to do:**
- Rewrite the agent code to adapt to a new target
- Re-derive the message schemas — they're target-agnostic (CampaignDirective, AttackPayload, etc. don't know about clinical specifics)
- Re-invent the multi-tier verdict pipeline — Tier-0 deterministic gates / Tier-1 Triage / Tier-2 Judge / regression-harness rule-classifier work the same way against any target

---

## 5. The Agents Themselves (machine users)

**Who they are:** the Orchestrator, Red Team, Triage, Judge, and Documentation Agents — autonomous code that reads and writes the state store as **inter-agent communication**.

**Workflows:**
- Orchestrator reads the `coverage` table + `regression_runs` + cost ledger, scores every sub-vector with a deterministic 6-factor formula, writes a `CampaignDirective` for the next campaign
- Red Team reads the directive + `findings` table (for partial-success mutation seeds), generates `AttackPayload`s with 6 mutation strategies (paraphrase, escalate, encode, fragment, embed, replay-with-mutation)
- Target Client (deterministic) reads payloads, writes `TargetResponse`s — branches between `/chat` and `/extract` based on `attack_via_extract`
- **Tier-0 Deterministic Gate** intercepts cases where the verdict is structurally decidable (e.g., token_exhaustion via payload-size threshold) — returns verdict at $0 with no LLM call
- Triage reads (payload, response, expected_safe), writes a Tier-1 verdict (`defended`) or an escalation flag — structurally cannot emit `bypass`
- Judge reads the same triple on escalation, writes the final `Verdict` (bypass / defended / partial)
- Documentation Agent reads confirmed `ExploitArtifact`s, writes vulnerability reports — **auto-fires on promotion** (no human in the loop)
- Regression Harness loads all non-withdrawn exploits + variants of seed-level exploits, replays surface-aware (chat vs extract), classifies pass/fail/inconclusive deterministically

**Architecture this drives:**
- All inter-agent messages are JSON in the shared state store — **no direct function calls between agents**
- Every message has a `campaign_id` for grouping and replay
- Provider pinning + T=0.0 on the LLM agents → reproducible inter-agent traffic
- LangSmith provides a parent-child run tree per campaign so the agent interactions are visible end-to-end

**Trust levels:** see ARCHITECTURE.md §1.1. Different agents have different trust levels because their outputs flow into different downstream decisions. The Judge has the highest trust level (every promotion to regression depends on it); the Red Team has the lowest (its output is untrusted by design and only goes to the target).

---

## 6. How user needs map to architectural choices

A compact crosswalk — every architectural component traces back to at least one user it serves:

| If you remove this user… | …you can remove this architecture |
|---|---|
| Platform Operator | Human approval gates, `--withdraw` CLI, state store + backfill script, CLI filter flags, Judge golden-set calibration loop, Slack alerts on workflow failure |
| Grader / Reviewer | Public HF dashboard, health badge on Overview, regression-pass-rate trend chart, calibration footer in reports, committed result JSONs, OWASP/ATLAS cross-references, `--smoke` no-auth path |
| Target Maintainer | Documentation Agent (auto-fires on promotion), consolidated root-cause reports (RT-ENC-wrapper-pattern.md), structured Vulnerability Report Format with deterministic reproduction, Regression Harness with surface-aware replay + variants, Slack alerts on pass→fail |
| Security Researcher | Config-driven target, target-agnostic message schemas, threat-model-as-markdown, reusable mutation operators, generic Judge-validation pipeline, §13 garak/PyRIT positioning |
| The Agents | Most of the platform — Orchestrator scoring, Red Team mutation strategies, Tier-0/T1/T2 verdict pipeline, regression replay, auto-Documentation. But the data still needs to flow somewhere |

This crosswalk is the **defense for every architectural decision** under the question "could we drop this?". If a component doesn't trace to a user, it's overhead; if it does, it's load-bearing.
