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

import altair as alt
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).parent))


TARGET_URL = "https://openemr.146-190-75-148.sslip.io"
REPO_URL = "https://github.com/heilashahidi/adversarial-openemr"
LANGSMITH_PROJECT_URL = "https://smith.langchain.com/o/personal/projects/p/adversarial-openemr"

VERDICT_EMOJI = {
    "bypass":   "🔴",
    "defended": "🟢",
    "partial":  "🟡",
    "error":    "⚪",
}

VERDICT_COLOR_HEX = {
    "Bypass":   "#dc2626",   # red-600
    "Defended": "#16a34a",   # green-600
    "Partial":  "#ca8a04",   # amber-600
    "Error":    "#9ca3af",   # gray-400
    "Untested": "#e5e7eb",   # gray-200
}

VERDICT_COLOR_TAG = {
    "bypass":   "red",
    "defended": "green",
    "partial":  "orange",
    "error":    "gray",
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
st.sidebar.markdown(
    f"[🎯 Target]({TARGET_URL}) · [📦 Repo]({REPO_URL}) · [🔭 Traces]({LANGSMITH_PROJECT_URL})"
)
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
    st.markdown(
        f"""
        <div style="display:inline-block;background:#dc2626;color:white;
                    padding:4px 14px;border-radius:12px;font-size:0.85em;
                    font-weight:600;letter-spacing:0.02em;margin-bottom:8px;">
            🎯 LIVE TARGET · {TARGET_URL.replace("https://", "")}
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not results:
        st.warning(
            "No run results found at `evals/results/latest_results.json`. "
            "Run the attack suite locally and commit the JSON output to populate this view."
        )
        st.stop()

    summary = results.get("summary", {})
    by_cat = results.get("by_category", {})
    rs = results.get("results", [])
    judge_cost = sum(r.get("judge_cost", 0) for r in rs)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total attacks", results.get("total_attacks", 0))
    c2.metric("🔴 Bypasses", summary.get("bypass", 0))
    c3.metric("🟢 Defended", summary.get("defended", 0))
    c4.metric("🟡 Partial", summary.get("partial", 0))
    c5.metric("⚪ Errors", summary.get("error", 0))

    st.caption(
        f"Last run: `{results.get('timestamp', 'unknown')}` · "
        f"Judge cost: ${judge_cost:.4f} · "
        f"Source: `evals/results/latest_results.json`"
    )

    # ── Charts row ──
    st.divider()
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("**Verdict mix**")
        verdict_rows = [
            {"Verdict": "Bypass",   "Count": summary.get("bypass",   0)},
            {"Verdict": "Defended", "Count": summary.get("defended", 0)},
            {"Verdict": "Partial",  "Count": summary.get("partial",  0)},
            {"Verdict": "Error",    "Count": summary.get("error",    0)},
        ]
        verdict_df = pd.DataFrame([r for r in verdict_rows if r["Count"] > 0])
        if not verdict_df.empty:
            donut = (
                alt.Chart(verdict_df)
                .mark_arc(innerRadius=45, outerRadius=80, stroke="white", strokeWidth=2)
                .encode(
                    theta=alt.Theta("Count:Q"),
                    color=alt.Color(
                        "Verdict:N",
                        scale=alt.Scale(
                            domain=["Bypass", "Defended", "Partial", "Error"],
                            range=[
                                VERDICT_COLOR_HEX["Bypass"],
                                VERDICT_COLOR_HEX["Defended"],
                                VERDICT_COLOR_HEX["Partial"],
                                VERDICT_COLOR_HEX["Error"],
                            ],
                        ),
                        legend=alt.Legend(
                            orient="bottom",
                            title=None,
                            direction="horizontal",
                            columns=4,
                        ),
                    ),
                    tooltip=["Verdict", "Count"],
                )
                .properties(height=280)
                .configure_view(strokeWidth=0)
            )
            st.altair_chart(donut, use_container_width=True)

    with chart_col2:
        st.markdown("**By category**")
        cat_rows = []
        for cat, counts in by_cat.items():
            for v in ["bypass", "defended", "partial", "error"]:
                if counts.get(v, 0) > 0:
                    cat_rows.append({
                        "Category": cat,
                        "Verdict": v.capitalize(),
                        "Count": counts.get(v, 0),
                    })
        if cat_rows:
            cat_df = pd.DataFrame(cat_rows)
            stacked = (
                alt.Chart(cat_df)
                .mark_bar(stroke="white", strokeWidth=1)
                .encode(
                    x=alt.X("Count:Q", title="Attacks", stack="zero"),
                    y=alt.Y("Category:N", title=None, sort="-x"),
                    color=alt.Color(
                        "Verdict:N",
                        scale=alt.Scale(
                            domain=["Bypass", "Defended", "Partial", "Error"],
                            range=[
                                VERDICT_COLOR_HEX["Bypass"],
                                VERDICT_COLOR_HEX["Defended"],
                                VERDICT_COLOR_HEX["Partial"],
                                VERDICT_COLOR_HEX["Error"],
                            ],
                        ),
                        legend=alt.Legend(orient="bottom", title=None),
                    ),
                    tooltip=["Category", "Verdict", "Count"],
                )
                .properties(height=240)
            )
            st.altair_chart(stacked, use_container_width=True)

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
    st.subheader("Coverage at a glance")
    st.caption("Each tile is one sub-vector from the threat model. Color = worst outcome observed.")

    # Build heatmap data — one row per (category, subcategory)
    grid_rows = []
    for cat in categories:
        subs = subcategories.get(cat, [])
        for i, sub in enumerate(subs):
            counts = coverage.get((cat, sub), {"bypass": 0, "defended": 0, "partial": 0, "error": 0})
            total = sum(counts.values())
            if counts["bypass"] > 0:
                status = "Bypass"
            elif counts["partial"] > 0:
                status = "Partial"
            elif counts["error"] > 0:
                status = "Error"
            elif counts["defended"] > 0:
                status = "Defended"
            else:
                status = "Untested"
            grid_rows.append({
                "Category": cat,
                "Subcategory": sub,
                "Pos": i,
                "Status": status,
                "Attacks": total,
                "Label": f"{sub} ({total})" if total else sub,
            })

    grid_df = pd.DataFrame(grid_rows)
    heatmap = (
        alt.Chart(grid_df)
        .mark_rect(stroke="white", strokeWidth=3, cornerRadius=4)
        .encode(
            x=alt.X("Pos:O", title=None, axis=None),
            y=alt.Y("Category:N", title=None, sort=categories),
            color=alt.Color(
                "Status:N",
                scale=alt.Scale(
                    domain=["Bypass", "Partial", "Error", "Defended", "Untested"],
                    range=[
                        VERDICT_COLOR_HEX["Bypass"],
                        VERDICT_COLOR_HEX["Partial"],
                        VERDICT_COLOR_HEX["Error"],
                        VERDICT_COLOR_HEX["Defended"],
                        VERDICT_COLOR_HEX["Untested"],
                    ],
                ),
                legend=alt.Legend(orient="bottom", title=None),
            ),
            tooltip=["Category", "Subcategory", "Status", "Attacks"],
        )
        .properties(height=260)
    )
    labels = (
        alt.Chart(grid_df)
        .mark_text(fontSize=10, fontWeight=500)
        .encode(
            x=alt.X("Pos:O"),
            y=alt.Y("Category:N", sort=categories),
            text="Subcategory:N",
            color=alt.condition(
                "datum.Status == 'Untested' || datum.Status == 'Partial'",
                alt.value("#0f172a"),
                alt.value("white"),
            ),
            tooltip=["Category", "Subcategory", "Status", "Attacks"],
        )
    )
    st.altair_chart(heatmap + labels, use_container_width=True)

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
        color_tag = VERDICT_COLOR_TAG.get(verdict, "gray")
        confidence = r.get("verdict_confidence", 0.0)

        header = (
            f"{emoji} **[{r.get('attack_id')}]** "
            f"`{r.get('category')}/{r.get('subcategory')}` — "
            f":{color_tag}[**{verdict.upper()}**] (conf {confidence:.2f})"
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
