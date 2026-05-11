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

Multi-agent adversarial evaluation platform for the Clinical Co-Pilot built on OpenEMR.

The hosted dashboard is a read-only viewer of committed run artifacts. Click the sidebar pages to see:

- **Overview** — headline stats from the latest attack run
- **Coverage Map** — which of the 26 threat-model sub-vectors have been tested
- **Attack Browser** — every adversarial case with prompt, target response, and judge verdict + reasoning
- **Threat Model** — full attack-surface map (`THREAT_MODEL.md`)
- **Architecture** — multi-agent platform design (`ARCHITECTURE.md`)

Source: https://github.com/heilashahidi/adversarial-openemr
