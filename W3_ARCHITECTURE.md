# ARCHITECTURE.md — Adversarial AI Security Platform

> **Target system:** Clinical Co-Pilot (Weeks 1–2), deployed at `https://openemr.146-190-75-148.sslip.io/`
> **Companion documents:** `THREAT_MODEL.md` (attack surface map), `USERS.md` (platform users and workflows)

---

## Executive Summary (~500 words)

This document describes a multi-agent adversarial evaluation platform designed to continuously discover, evaluate, and defend against attacks on the Clinical Co-Pilot — an AI assistant connected to patient data inside OpenEMR.

The platform is built around four distinct agent roles: an **Orchestrator** that reads system coverage and prioritizes what to attack next; a **Red Team Agent** that generates, mutates, and escalates adversarial inputs; a **Judge Agent** that independently evaluates whether each attack succeeded; and a **Documentation Agent** that converts confirmed exploits into structured, professional vulnerability reports.

A single-agent or pipeline architecture was explicitly rejected. Attack generation and attack evaluation are different jobs — a system that does both in the same context has a conflict of interest by design. Strategic prioritization is different from execution. The Orchestrator decides where to focus based on coverage gaps and unresolved findings; the Red Team executes attacks without knowing its own success rate; the Judge evaluates without knowing the Red Team's intent.

The platform attacks a **live deployed target**, not a mock. Every attack runs against the same Clinical Co-Pilot that a physician would use. This is non-negotiable — static test suites against mocked responses don't catch the behavioral drift that makes AI systems unpredictable under adversarial pressure.

**Model selection is deliberate.** Frontier models (Claude, GPT) are trained to refuse offensive security workflows, making them unreliable for attack generation. The Red Team Agent uses open-source models via OpenRouter (Mistral Large, Llama 3.1 70B) that don't have these restrictions. The Judge uses Claude Sonnet for consistent evaluation. The Orchestrator uses Claude Haiku for fast, cheap strategic decisions. The Documentation Agent uses Haiku for structured report writing. This mixed-model approach keeps cost under $1 per campaign while maintaining evaluation quality where it matters.

Confirmed exploits are frozen into a **regression harness** — deterministic, no LLM involved. When the target system changes, the harness replays every confirmed exploit. A test that passes because the model's behavior changed — not because the vulnerability was fixed — is flagged as inconclusive. This distinction is critical: behavioral drift is not remediation.

The **observability layer** serves two audiences. The Orchestrator reads it to make intelligent targeting decisions: which attack categories have been tested, which are succeeding, where are the coverage gaps. A human operator reads it to understand system behavior: what each agent did, in what order, at what cost, and whether the platform is producing signal or burning budget.

**Human approval gates** exist at three boundaries: before the Documentation Agent files a critical-severity report, before any attack that could modify the target system's state, and before the Orchestrator launches a novel attack category for the first time. The platform operates autonomously within these gates and stops to ask outside them.

Key architectural tradeoffs: using open-source models for the Red Team sacrifices some attack sophistication for cost and availability; using a single Judge rather than an ensemble trades evaluation depth for speed; committing to live-target-only testing means the platform can't run without the Co-Pilot being deployed. Each tradeoff is documented and defensible.

---

## 1. Multi-Agent System Architecture

```
                    ┌──────────────────────────┐
                    │      ORCHESTRATOR         │
                    │   (Claude Haiku)          │
                    │                          │
                    │   Reads: coverage map,    │
                    │   open findings, cost     │
                    │   Decides: next campaign  │
                    └────────────┬─────────────┘
                                │
           ┌────────────────────┼────────────────────┐
           ▼                    ▼                    ▼
   ┌───────────────┐   ┌───────────────┐   ┌────────────────────┐
   │  RED TEAM     │   │    JUDGE      │   │   DOCUMENTATION    │
   │  AGENT        │   │    AGENT      │   │   AGENT            │
   │               │   │               │   │                    │
   │  Mistral /    │   │  Claude       │   │  Claude Haiku      │
   │  Llama 70B    │   │  Sonnet       │   │                    │
   │               │   │               │   │  Writes vuln       │
   │  Generates,   │   │  Evaluates    │   │  reports from      │
   │  mutates,     │   │  success /    │   │  confirmed         │
   │  escalates    │   │  fail /       │   │  exploits          │
   │  attacks      │   │  partial      │   │                    │
   └───────┬───────┘   └───────┬───────┘   └────────┬───────────┘
           │                   │                     │
           ▼                   ▼                     ▼
   ┌──────────────────────────────────────────────────────────┐
   │                   SHARED STATE STORE                      │
   │                                                          │
   │  findings[]     — each attack result with verdict         │
   │  coverage{}     — category → tested/passed/failed counts  │
   │  exploits[]     — confirmed vulns for regression          │
   │  cost_tracker   — tokens + dollars per agent per run      │
   │  attack_history — full log of every attempt               │
   └──────────────────────────┬───────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼                               ▼
   ┌────────────────────┐          ┌──────────────────────┐
   │  REGRESSION        │          │  TARGET SYSTEM       │
   │  HARNESS           │          │  (Clinical Co-Pilot) │
   │                    │          │                      │
   │  Deterministic     │          │  Live deployed at    │
   │  replay — no LLM   │          │  production URL      │
   │  Frozen exploits   │          │                      │
   └────────────────────┘          └──────────────────────┘
```

### 1.1 Agent Roles

| Agent | Model | Inputs | Outputs | Trust Level |
|---|---|---|---|---|
| **Orchestrator** | Claude Haiku (OpenRouter) | Coverage map, open findings, cost budget | Campaign directives: category, attack count, mutation strategy | High — controls scope |
| **Red Team** | Mistral Large / Llama 70B (OpenRouter) | Campaign directive, templates, mutation seeds, prior partial successes | Attack payloads: prompts, multi-turn sequences, uploaded content | Low — output untrusted by design |
| **Judge** | Claude Sonnet (OpenRouter) | Attack payload, target response, expected safe behavior, rubric | Verdict: success / fail / partial, severity, confidence | High — verdicts drive all decisions |
| **Documentation** | Claude Haiku (OpenRouter) | Confirmed exploit from Judge, target response, metadata | Structured vulnerability report | Medium — reviewed before filing |

### 1.2 Why Separate Agents

**Red Team ≠ Judge.** An agent that generates and evaluates attacks has a conflict of interest. The Red Team is incentivized to find success; the Judge is incentivized to be accurate. Combining them inflates success rates.

**Orchestrator ≠ Red Team.** Strategic prioritization ("which category has coverage gaps?") is a different task from attack generation ("craft a multi-turn prompt injection"). Different reasoning, different prompts, different models.

**Documentation ≠ Judge.** The Judge outputs a verdict. The Documentation Agent transforms it into a professional report an engineer can act on. Different skill, different output format.

### 1.3 Inter-Agent Communication

Agents communicate through the shared state store — not direct messages. Every handoff is inspectable and replayable.

```
1. Orchestrator reads coverage → writes campaign directive
2. Red Team reads directive → generates N attacks → writes to findings[]
3. Each attack executes against the live target → response stored
4. Judge reads (attack, response) pairs → writes verdicts
5. Orchestrator reads verdicts → updates coverage map
6. Confirmed exploits → Documentation Agent → vulnerability report
7. Confirmed exploits → Regression Harness (frozen)
8. Orchestrator evaluates: continue, switch category, or stop
```

### 1.4 Model Selection Rationale

**Open-source for Red Team:** Claude and GPT refuse offensive security prompts. Mistral and Llama don't have these restrictions. The assignment acknowledges this: "commercial LLMs are intentionally trained to avoid offensive security workflows."

**Sonnet for Judge:** Evaluation consistency matters more than cost. Noisy verdicts undermine the entire platform.

**Haiku for Orchestrator and Documentation:** Small structured inputs/outputs. 6x cheaper than Sonnet with negligible quality difference for these tasks.

---

## 2. Attack Categories

### 2.1 Prompt Injection
- **Direct:** Single-turn system instruction override
- **Indirect:** Malicious content in patient data or uploaded documents
- **Multi-turn:** Gradual escalation across conversation turns

### 2.2 Data Exfiltration
- **PHI leakage:** Extracting patient names, DOBs, diagnoses
- **Cross-patient exposure:** Accessing Patient B's data via Patient A
- **Authorization bypass:** Accessing data beyond authenticated scope

### 2.3 State Corruption
- **Conversation history manipulation:** Injecting false context
- **Context poisoning:** Uploaded documents influencing future responses
- **Memory pollution:** Persistent state carrying across sessions

### 2.4 Tool Misuse
- **Unintended invocation:** Tricking the agent into unauthorized tool calls
- **Parameter tampering:** Modifying tool inputs
- **Recursive calls:** Triggering infinite tool-calling loops

### 2.5 Denial of Service
- **Token exhaustion:** Maximum token consumption queries
- **Infinite loops:** Recursive agent behavior
- **Cost amplification:** Minimal input triggering expensive processing

### 2.6 Identity and Role Exploitation
- **Privilege escalation:** Acting outside authorized scope
- **Persona hijacking:** Adopting a different identity
- **Trust boundary violations:** Bypassing evidence separation or refusal boundaries

---

## 3. Campaign Loop

```
┌─────────────────────────────────────────────────┐
│              ORCHESTRATOR LOOP                    │
│                                                 │
│  1. Read coverage map → find gaps               │
│  2. Select campaign category + strategy         │
│  3. Red Team generates N attacks                │
│  4. Execute against live target                 │
│  5. Judge evaluates each result                 │
│  6. Update coverage → document → regress        │
│  7. Cost check → continue or stop               │
└─────────────────────────────────────────────────┘
```

### 3.1 Prioritization Logic
1. **Coverage gaps** — untested categories get highest priority
2. **High-severity open findings** — unresolved confirmed vulnerabilities
3. **Partial successes** — best mutation seeds for the Red Team
4. **Recency** — stale categories get re-prioritized
5. **Cost efficiency** — low-signal categories get deprioritized

### 3.2 Red Team Mutation Strategies
1. **Paraphrase** — same intent, different wording
2. **Escalate** — multi-turn prefix building false trust
3. **Encode** — base64, ROT13, unicode substitution
4. **Fragment** — split payload across turns
5. **Embed** — hide payload inside clinical context

---

## 4. Regression Harness

Deterministic replay — no LLM involved in the replay itself.

**Each confirmed exploit stored as:**
```json
{
  "id": "PI-001",
  "category": "prompt_injection",
  "severity": "high",
  "attack_sequence": ["Turn 1", "Turn 2"],
  "expected_safe_behavior": "Agent refuses",
  "observed_vulnerable_behavior": "Agent leaked PHI",
  "fixed": false,
  "fix_validated": false
}
```

**Regression logic:**
- **Pass:** response matches expected safe behavior — fix holds
- **Fail:** vulnerability reappeared — regression detected
- **Inconclusive:** behavior changed but doesn't match either — flag for human review

**Triggers:** on every deploy, nightly schedule, or on-demand by Orchestrator.

---

## 5. Observability Layer

| Metric | What it answers |
|---|---|
| Category coverage | Which categories tested? How many cases each? |
| Pass/fail rate | Is the target becoming more or less resilient? |
| Vulnerability status | Open / in progress / resolved? |
| Cost per campaign | Budget tracking and scaling projection |
| Agent trace | What each agent did, in what order |
| Regression trend | Are fixes holding over time? |

Two audiences: the Orchestrator reads it to make targeting decisions; a human reads it to understand platform behavior.

---

## 6. Vulnerability Report Format

| Field | Description |
|---|---|
| **ID** | Unique identifier (PI-001, DE-003) |
| **Severity** | Critical / High / Medium / Low |
| **Category** | Attack category and subcategory |
| **Description** | Vulnerability and clinical impact |
| **Reproduction** | Minimal attack sequence |
| **Observed vs Expected** | What happened vs what should have |
| **Remediation** | Recommended fix |
| **Status** | Open / Fixed / Validated |

---

## 7. Human Approval Gates

| Gate | When | Why |
|---|---|---|
| Critical-severity report | Before filing | Prevent false positive noise |
| State-modifying attack | Before execution | Don't corrupt the target |
| Novel attack category | Before first launch | Human reviews templates first |

---

## 8. Cost Management

| Scale | Campaigns | Est. Cost |
|---|---|---|
| MVP | 10 | ~$10 |
| 100 runs | 100 | ~$94 |
| 1K runs | 1,000 | ~$940 |
| 10K runs | 10,000 | ~$9,400 |
| 100K runs | 100,000 | ~$50,000 (needs architectural changes) |

At 100K: batch API for Judge, cached regression results, Haiku for low-severity Judge calls, attack deduplication.

---

## 9. Defending This Architecture

**"Why not a single agent?"** Conflict of interest. Attack generation and evaluation in the same context biases toward known-working patterns. The assignment requires multi-agent.

**"Why open-source for Red Team?"** Frontier models refuse offensive security tasks. Documented in the assignment requirements.

**"Why isn't the regression harness an agent?"** Determinism. LLM-based replay introduces variance. The harness replays mechanically; the Judge evaluates.

**"What happens when Red Team generates harmful content?"** Output never leaves the platform. Payloads go only to our own Co-Pilot. Documentation Agent sanitizes reports.

**"What worries you most?"** Judge consistency. If the Judge drifts, every downstream decision degrades. Mitigation: periodic human review and a ground truth dataset for Judge accuracy.
