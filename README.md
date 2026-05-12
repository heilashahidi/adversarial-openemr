---
title: Adversarial Platform — Clinical Co-Pilot
emoji: 🛡️
colorFrom: red
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
license: mit
---

# adversarial-openemr

Multi-agent adversarial evaluation platform that continuously attacks a live deployed Clinical Co-Pilot built on OpenEMR.

## Target (Stage 1)

- **Live target URL:** https://openemr.146-190-75-148.sslip.io
- **Health check:** `GET /health` → `200`
- **Attack surface:** `POST /chat` (synthesis pipeline), `POST /extract` (VLM document ingestion)
- **Live dashboard:** https://heilashahidi-adversarial-openemr.hf.space/
- **Source repo:** https://github.com/heilashahidi/adversarial-openemr

Every attack the platform produces is sent to that URL — there is **no mock target**. The dashboard's Overview page shows the latency, token counts, and full target responses from the most recent live run. The `target_client.py` health check fires before every campaign and aborts if the target is unreachable.

### Target state and changes made for testability

The Clinical Co-Pilot is the unmodified deployment from the Weeks 1–2 case study, hosted on DigitalOcean. **No platform-side changes to the target were required to bring it into a testable state.** Concretely:

| Aspect | State |
|---|---|
| **Deployment** | DigitalOcean droplet, reachable via Caddy → uvicorn → FastAPI (`server: uvicorn · via: 1.1 Caddy`). Same hosting as Weeks 1-2. |
| **Endpoints** | `/chat` (agent pipeline: supervisor → chart_lookup / evidence_retriever / synthesis), `/extract` (VLM), `/health`. All reachable. |
| **Test patients** | Pre-seeded with known UUIDs in OpenEMR. The platform pins `config.DEFAULT_PATIENT` to David Nakamura (multi-comorbid case); all 6 known patients are in `config.PATIENTS`. |
| **Co-Pilot model** | Anthropic Sonnet (target-side), invoked by the synthesis worker. Unchanged from Weeks 1-2. |
| **Auth posture** | **`/chat` accepts unauthenticated requests** — confirmed via direct probe on 2026-05-11. Documented as a Critical finding in `THREAT_MODEL.md` §2.4. This was discovered *because of* the platform, not introduced by it. |
| **Rate limits** | None observed at the application layer. Platform self-rate-limits at 1 rps for politeness. |

The unauth posture (§2.4) is the only material environmental fact discovered while bringing the system into a testable state. It is not a change we made — it is a property of the existing deployment.

## What this platform does

Four-stage W3 deliverable:

| Stage | Artifact | Status |
|---|---|---|
| 1 — Stand up the target | Live URL above, this section | ✅ |
| 2 — Threat Model | [`THREAT_MODEL.md`](./THREAT_MODEL.md) — 26 sub-vectors across 6 categories, OWASP LLM mapping, risk matrix | ✅ |
| 3 — Seed Attack Suite + Agent Prototype | [`evals/seed_attacks.py`](./evals/seed_attacks.py) (40 cases, 100% sub-vector coverage), [`agents/judge_agent.py`](./agents/judge_agent.py), [`agents/triage_agent.py`](./agents/triage_agent.py) | ✅ |
| 4 — Platform Architecture | [`ARCHITECTURE.md`](./ARCHITECTURE.md) — 5-agent design, message schemas, scoring formula, regression pipeline | ✅ |

## Dashboard pages

The hosted dashboard is a read-only viewer of committed run artifacts:

- **Overview** — headline stats from the latest attack run (bypasses / defended / partial / errors, T1 vs T2 cost split)
- **Coverage Map** — heatmap showing all 26 threat-model sub-vectors and their tested-vs-untested status
- **Attack Browser** — every adversarial case with prompt, target response, and judge verdict + reasoning
- **Threat Model** — full attack-surface map
- **Architecture** — multi-agent platform design

## Run the suite locally

```bash
git clone https://github.com/heilashahidi/adversarial-openemr.git
cd adversarial-openemr
pip install -r requirements.txt
cp .env.example .env   # then fill in OPENROUTER_API_KEY (and optionally LANGSMITH keys)
python3 evals/run_attacks.py
```

Outputs land in `evals/results/attack_results_<timestamp>.json` and update `latest_results.json`. The dashboard picks them up on next `git push`.

## Latest live-run results

40 attacks · 38 defended (≥0.92 confidence) · 1 confirmed bypass (DE-09 §2.4 unauthenticated endpoint) · 1 target error (PI-04 HTTP 500 on base64) · Two-tier Judge (Haiku 4.5 → Sonnet 4.5) at ~$0.003/attack · LangSmith traces grouped per campaign.

See the dashboard for the full breakdown.
