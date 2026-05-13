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
- Review the latest run on the deployed dashboard
- Investigate a specific Judge verdict in LangSmith by clicking through the trace tree
- Decide whether a partial-success seed warrants a Red Team mutation campaign
- Approve a critical-severity report before filing
- Approve a state-modifying attack before execution

**Architecture this drives:**
- `state_store` exists so the operator can query / inspect / replay any past finding without re-running attacks (zero $-cost replay)
- `--smoke`, `--id`, `--category`, `--workers` CLI flags exist for targeted re-runs and graceful scaling
- Human approval gates (ARCHITECTURE.md §10) sit between agents and irreversible actions
- LangSmith tracing is on by default so the operator can debug any verdict by clicking through
- Dashboard exists as a read-only operational view — fast situational awareness without rerunning

**What the operator should NOT have to do:**
- Manually classify obvious clean refusals → Triage agent handles this
- Manually score sub-vector priorities → Orchestrator's deterministic scoring does this (ARCHITECTURE.md §3.1)
- Manually write vulnerability reports → Documentation Agent does this (designed; not yet built)

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
- Committed result JSONs in `evals/results/` document run-over-run reproducibility (6+ runs, consistent verdicts)
- Threat-model `Tested by` rows and seed-case `threat_model_ref` fields link rubric items to evidence bidirectionally — graders can audit either direction
- ARCHITECTURE.md §12 FAQ exists specifically to answer "why did you do X?" in 60 seconds

**What the grader should NOT have to do:**
- Sign up for an OpenRouter account to verify the platform works
- Run a 7-minute attack suite to see basic functionality
- Read 1,200 lines of architecture markdown to find the agent roles
- Click through five pages to find the live target URL

---

## 3. Target Maintainer

**Who they are:** the Co-Pilot development team — the people responsible for fixing what the platform finds. In this project it is the same individual as the Operator, but the architecture treats them as separable.

**Workflows:**
- Receive a vulnerability report from the Documentation Agent (designed; not yet implemented)
- Cross-reference the finding with the threat model and risk matrix
- Decide remediation priority
- Implement the fix
- Trigger the regression harness to confirm the fix holds (designed; not yet implemented)

**Architecture this drives:**
- Vulnerability Report Format (ARCHITECTURE.md §9) is structured for engineer-actionable triage: ID, Severity, Category, Description, Reproduction sequence, Observed vs Expected, Remediation, Status
- Every confirmed bypass carries `threat_model_ref` so the maintainer reads the report and immediately sees which sub-vector it tests
- The regression harness (ARCHITECTURE.md §4.3) re-runs every promoted exploit on each target deploy — "is this fix done?" is mechanically answerable, not opinion-based
- The platform attacks the **deployed** target, not a mock — fixes are validated against the exact surface clinicians use
- The §2.4 finding's seed case (DE-09) is re-probed every campaign — the day auth is added at the HTTP layer, the DE-09 verdict will flip from `bypass` to `defended` automatically

**What the target maintainer should NOT have to do:**
- Read the entire campaign log to find the relevant finding → Documentation Agent extracts the actionable subset
- Decide whether behavioral drift counts as a fix → regression harness flags drift as `inconclusive`, not as remediation

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
- Seed cases are a list of dicts in `seed_attacks.py` — appendable, no schema migration; per-case `threat_model_ref` lets the researcher map their own sub-vectors
- Threat model is markdown — editable by hand; the platform doesn't depend on a structured threat-model parser
- The platform makes no target-specific assumptions in the agent code (everything specific to the Co-Pilot is in `config.py` or `seed_attacks.py`)
- Provider pinning is opt-in via `extra_body` — a researcher could disable it to compare verdicts across LLM providers

**What the security researcher should NOT have to do:**
- Rewrite the agent code to adapt to a new target
- Re-derive the message schemas — they're target-agnostic (CampaignDirective, AttackPayload, etc. don't know about clinical specifics)

---

## 5. The Agents Themselves (machine users)

**Who they are:** the Orchestrator, Red Team, Triage, Judge, and Documentation Agents — autonomous code that reads and writes the state store as **inter-agent communication**.

**Workflows:**
- Orchestrator reads the `coverage` table, scores every sub-vector, writes a `CampaignDirective` for the next campaign
- Red Team reads the directive + `findings` table (for partial-success mutation seeds), generates `AttackPayload`s
- Target Client (deterministic) reads payloads, writes `TargetResponse`s
- Triage reads (payload, response, expected_safe), writes a Tier-1 verdict (`defended`) or an escalation flag
- Judge reads the same triple on escalation, writes the final `Verdict` (bypass / defended / partial)
- Documentation Agent reads confirmed `ExploitArtifact`s, writes vulnerability reports

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
| Platform Operator | Human approval gates (no human to approve), state store (no replay needed), CLI filter flags |
| Grader / Reviewer | Public HF dashboard, `--smoke` no-auth path, target URL in README, committed result JSONs |
| Target Maintainer | Documentation Agent, structured Vulnerability Report Format, Regression Harness |
| Security Researcher | Config-driven target, target-agnostic message schemas, threat-model-as-markdown |
| The Agents | Most of the platform (but the data still needs to flow somewhere) |

This crosswalk is the **defense for every architectural decision** under the question "could we drop this?". If a component doesn't trace to a user, it's overhead; if it does, it's load-bearing.
