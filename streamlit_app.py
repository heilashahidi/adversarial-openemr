"""
Adversarial Platform Dashboard

Read-only viewer for the Clinical Co-Pilot adversarial evaluation platform.
Reads committed artifacts only — no live target or LLM calls:
  - evals/results/latest_results.json
  - THREAT_MODEL.md
  - ARCHITECTURE.md
  - config.ATTACK_SUBCATEGORIES

Deploy: share.streamlit.io → connect GitHub repo → point at streamlit_app.py
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent))


TARGET_URL = "https://openemr.146-190-75-148.sslip.io"
REPO_URL = "https://github.com/heilashahidi/adversarial-openemr"

VERDICT_EMOJI = {
    "bypass":   "🔴",
    "defended": "🟢",
    "partial":  "🟡",
    "error":    "⚪",
}


# ── Data loaders ──

@st.cache_data
def load_results():
    path = Path("evals/results/latest_results.json")
    if not path.exists():
        return None
    return json.loads(path.read_text())


@st.cache_data
def load_markdown(name: str) -> str:
    p = Path(name)
    return p.read_text() if p.exists() else f"_(missing: {name})_"


@st.cache_data
def load_subcategories():
    try:
        from config import ATTACK_CATEGORIES, ATTACK_SUBCATEGORIES
        return list(ATTACK_CATEGORIES), dict(ATTACK_SUBCATEGORIES)
    except Exception:
        return [], {}


# ── Page setup ──

st.set_page_config(
    page_title="Adversarial Platform — Clinical Co-Pilot",
    page_icon="🛡️",
    layout="wide",
)

st.sidebar.title("🛡️ Adversarial Platform")
st.sidebar.markdown(f"[🎯 Target]({TARGET_URL}) · [📦 Repo]({REPO_URL})")
st.sidebar.divider()

page = st.sidebar.radio(
    "Navigation",
    ["Overview", "Coverage Map", "Attack Browser", "Threat Model", "Architecture"],
    label_visibility="collapsed",
)

st.sidebar.divider()
st.sidebar.caption(
    "Read-only viewer of committed artifacts. "
    "Update what's shown here by running `python3 evals/run_attacks.py` "
    "locally and committing the new results JSON."
)


results = load_results()
categories, subcategories = load_subcategories()


# ── Page: Overview ──

if page == "Overview":
    st.title("Adversarial AI Security Platform")
    st.caption(f"**Target:** Clinical Co-Pilot at `{TARGET_URL}`")

    if not results:
        st.warning(
            "No run results found at `evals/results/latest_results.json`. "
            "Run the attack suite locally and commit the JSON output to populate this view."
        )
        st.stop()

    summary = results.get("summary", {})
    by_cat = results.get("by_category", {})
    rs = results.get("results", [])

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total attacks", results.get("total_attacks", 0))
    c2.metric("🔴 Bypasses", summary.get("bypass", 0))
    c3.metric("🟢 Defended", summary.get("defended", 0))
    c4.metric("🟡 Partial", summary.get("partial", 0))
    c5.metric("⚪ Errors", summary.get("error", 0))

    judge_cost = sum(r.get("judge_cost", 0) for r in rs)
    st.caption(
        f"Last run: `{results.get('timestamp', 'unknown')}` · "
        f"Judge cost: ${judge_cost:.4f} · "
        f"Source: `evals/results/latest_results.json`"
    )

    st.divider()
    st.subheader("What this run tells us")

    bypasses = summary.get("bypass", 0)
    defenses = summary.get("defended", 0)
    errors = summary.get("error", 0)
    total = results.get("total_attacks", 0)

    if total == 0:
        st.info("No attacks in the latest results file.")
    elif bypasses == 0:
        st.markdown(
            f"""
The target's behavioral defenses held against **{defenses} of {total}** well-formed
seed attacks at confidence ≥ 0.95. **{errors}** attack(s) produced a target failure
(HTTP 500 / timeout) — these short-circuit the Judge and surface as signals worth
investigating, not defenses.

The Red Team Agent's role is to mutate these clean-defense baselines into the harder
variants the threat model enumerates: encoding bypasses, indirect injection via
patient data, multi-turn escalation, retrieval-output injection.
            """
        )
    else:
        st.error(
            f"**{bypasses} confirmed bypass(es)** — defense broken. "
            "See the Attack Browser tab for prompts, responses, and Judge reasoning."
        )

    st.divider()
    st.subheader("By category")

    cat_rows = []
    for cat, counts in sorted(by_cat.items()):
        cat_rows.append({
            "Category": cat,
            "🔴 Bypass": counts.get("bypass", 0),
            "🟢 Defended": counts.get("defended", 0),
            "🟡 Partial": counts.get("partial", 0),
            "⚪ Error": counts.get("error", 0),
            "Total": sum(counts.values()),
        })
    if cat_rows:
        st.dataframe(pd.DataFrame(cat_rows), use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("Target failures (no Judge verdict possible)")

    errs = [r for r in rs if r.get("verdict") == "error"]
    if not errs:
        st.caption("None in this run.")
    else:
        for e in errs:
            st.markdown(
                f"- **[{e['attack_id']}]** `{e['category']}/{e['subcategory']}` — "
                f"{e.get('verdict_reasoning', '')[:160]}"
            )


# ── Page: Coverage Map ──

elif page == "Coverage Map":
    st.title("Coverage Map")
    st.caption(
        "Per-(category × subcategory) coverage from the latest run. "
        "Sub-vectors come from `THREAT_MODEL.md` and `config.ATTACK_SUBCATEGORIES` — "
        "rows that show `Untested` are gaps the Orchestrator should target next."
    )

    if not results:
        st.warning("No run data available.")
        st.stop()

    coverage = defaultdict(lambda: {"bypass": 0, "defended": 0, "partial": 0, "error": 0})
    for r in results.get("results", []):
        key = (r.get("category", "?"), r.get("subcategory", "?"))
        coverage[key][r.get("verdict", "error")] += 1

    total_subs = sum(len(subs) for subs in subcategories.values())
    tested = sum(1 for k, v in coverage.items() if sum(v.values()) > 0)

    c1, c2, c3 = st.columns(3)
    c1.metric("Sub-vectors total", total_subs)
    c2.metric("Tested", tested)
    c3.metric("Coverage gap", total_subs - tested)

    st.divider()

    for cat in categories:
        subs = subcategories.get(cat, [])
        cat_total = sum(sum(coverage.get((cat, s), {}).values()) for s in subs)
        st.subheader(f"{cat}  ·  {cat_total} attack(s)")

        rows = []
        for sub in subs:
            counts = coverage.get((cat, sub), {"bypass": 0, "defended": 0, "partial": 0, "error": 0})
            total = sum(counts.values())
            rows.append({
                "Subcategory": sub,
                "🔴 Bypass":   counts["bypass"],
                "🟢 Defended": counts["defended"],
                "🟡 Partial":  counts["partial"],
                "⚪ Error":    counts["error"],
                "Total":      total,
                "Status":     "✅ Tested" if total > 0 else "⬜ Untested",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


# ── Page: Attack Browser ──

elif page == "Attack Browser":
    st.title("Attack Browser")
    st.caption("Every adversarial test case, the target's response, and the Judge's verdict.")

    if not results:
        st.warning("No run data available.")
        st.stop()

    rs = results.get("results", [])

    c1, c2, c3, c4 = st.columns(4)
    f_category = c1.selectbox("Category", ["(all)"] + sorted({r.get("category", "?") for r in rs}))
    f_verdict = c2.selectbox("Verdict", ["(all)", "bypass", "defended", "partial", "error"])
    f_severity = c3.selectbox("Severity", ["(all)", "critical", "high", "medium", "low"])
    search = c4.text_input("Search payload / response")

    filtered = []
    for r in rs:
        if f_category != "(all)" and r.get("category") != f_category:
            continue
        if f_verdict != "(all)" and r.get("verdict") != f_verdict:
            continue
        if f_severity != "(all)" and r.get("severity", "").lower() != f_severity:
            continue
        if search:
            blob = (str(r.get("attack_payload", "")) + " " + str(r.get("target_response", ""))).lower()
            if search.lower() not in blob:
                continue
        filtered.append(r)

    st.caption(f"Showing **{len(filtered)}** of **{len(rs)}** attacks")
    st.divider()

    for r in filtered:
        verdict = r.get("verdict", "error")
        emoji = VERDICT_EMOJI.get(verdict, "⚪")
        confidence = r.get("verdict_confidence", 0.0)

        header = (
            f"{emoji} **[{r.get('attack_id')}]** "
            f"`{r.get('category')}/{r.get('subcategory')}` — "
            f"{verdict.upper()} (conf {confidence:.2f})"
        )

        with st.expander(header):
            meta_cols = st.columns(3)
            with meta_cols[0]:
                st.markdown(f"**Severity:** {r.get('severity', '?')}")
                st.markdown(f"**Latency:** {r.get('target_latency_ms', 0)} ms")
            with meta_cols[1]:
                st.markdown(f"**Judge confidence:** {confidence:.2f}")
                st.markdown(f"**Judge cost:** ${r.get('judge_cost', 0):.5f}")
            with meta_cols[2]:
                st.markdown(f"**Add to regression:** {'yes' if r.get('add_to_regression') else 'no'}")
                indicators = r.get("verdict_indicators", [])
                if indicators:
                    st.markdown(f"**Indicators:** `{', '.join(map(str, indicators))}`")

            st.divider()

            st.markdown("**Attack payload**")
            payload = r.get("attack_payload", "")
            if isinstance(payload, list):
                for i, turn in enumerate(payload, 1):
                    st.code(f"Turn {i}: {turn}", language=None, wrap_lines=True)
            else:
                st.code(payload, language=None, wrap_lines=True)

            st.markdown("**Target response**")
            st.code(r.get("target_response", ""), language=None, wrap_lines=True)

            st.markdown("**Expected safe behavior**")
            st.write(r.get("expected_safe", ""))

            st.markdown("**Judge reasoning**")
            reasoning = r.get("verdict_reasoning", "")
            if reasoning:
                st.info(reasoning)
            else:
                st.caption("(no reasoning provided)")


# ── Page: Threat Model ──

elif page == "Threat Model":
    st.title("Threat Model")
    st.caption(f"Full text from [THREAT_MODEL.md]({REPO_URL}/blob/main/THREAT_MODEL.md) — 26 sub-vectors across 6 categories.")
    st.markdown(load_markdown("THREAT_MODEL.md"))


# ── Page: Architecture ──

elif page == "Architecture":
    st.title("Platform Architecture")
    st.caption(f"Full text from [ARCHITECTURE.md]({REPO_URL}/blob/main/ARCHITECTURE.md) — 4-agent design, message schemas, decision algorithms.")
    st.markdown(load_markdown("ARCHITECTURE.md"))
