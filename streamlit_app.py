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
import re
import sys
from collections import defaultdict
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

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


@st.cache_data
def load_seed_exploitability():
    """Map attack_id → exploitability, read from the seed file as a fallback
    for results JSON files that pre-date the field."""
    try:
        sys.path.insert(0, str(Path(__file__).parent / "evals"))
        from seed_attacks import SEED_ATTACKS
        return {c["id"]: c.get("exploitability", "unknown") for c in SEED_ATTACKS}
    except Exception:
        return {}


def render_mermaid(code: str, height: int = 720):
    """Render a mermaid diagram via the official CDN inside a sandboxed iframe."""
    html = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { margin: 0; padding: 12px; background: white;
           font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; }
    .mermaid { display: flex; justify-content: center; }
    .mermaid svg { max-width: 100%; height: auto; }
  </style>
</head>
<body>
  <pre class="mermaid">__CODE__</pre>
  <script type="module">
    import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs";
    mermaid.initialize({
      startOnLoad: true,
      theme: "default",
      themeVariables: {
        fontFamily: '-apple-system, system-ui, sans-serif',
        primaryColor: '#fef2f2',
        primaryBorderColor: '#dc2626',
        lineColor: '#475569',
      },
      flowchart: { curve: 'basis', padding: 16, useMaxWidth: true }
    });
  </script>
</body>
</html>
""".replace("__CODE__", code)
    components.html(html, height=height, scrolling=True)


def render_markdown_with_mermaid(md_text: str, height: int = 720):
    """Split markdown at ```mermaid``` fences, render each fence as a real
    diagram and the surrounding markdown inline."""
    pattern = re.compile(r"```mermaid\n(.*?)\n```", re.DOTALL)
    parts = pattern.split(md_text)
    # split() with a single capture group yields: [text, code, text, code, ..., text]
    for i, part in enumerate(parts):
        if i % 2 == 0:
            if part.strip():
                st.markdown(part)
        else:
            render_mermaid(part, height=height)


# ── Page setup ──

st.set_page_config(
    page_title="Adversarial Platform — Clinical Co-Pilot",
    page_icon="🛡️",
    layout="wide",
)

# ── Global CSS for the modern card aesthetic ──
st.markdown(
    """
<style>
  /* Typography */
  html, body, [class*="css"] { font-feature-settings: "cv02","cv03","cv04","cv11"; }
  h1, h2, h3 { letter-spacing: -0.015em; }

  /* Hero banner */
  .hero {
    background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
    border: 1px solid #e2e8f0;
    border-radius: 16px;
    padding: 28px 32px;
    margin-bottom: 20px;
    box-shadow: 0 1px 3px rgba(15,23,42,0.04), 0 4px 12px rgba(15,23,42,0.04);
  }
  .hero-title {
    font-size: 1.9rem;
    font-weight: 700;
    color: #0f172a;
    margin: 0 0 4px 0;
    line-height: 1.15;
  }
  .hero-subtitle {
    font-size: 0.95rem;
    color: #64748b;
    margin: 0 0 16px 0;
  }
  .hero-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: #dc2626;
    color: white;
    padding: 5px 12px;
    border-radius: 999px;
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.02em;
    text-decoration: none;
  }
  .hero-pill code {
    background: rgba(255,255,255,0.18);
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 0.72rem;
    color: white;
  }
  .hero-meta {
    margin-top: 14px;
    font-size: 0.82rem;
    color: #94a3b8;
  }
  .hero-meta b { color: #475569; font-weight: 600; }

  /* Metric card grid */
  .card-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 16px;
  }
  .mcard {
    background: white;
    border: 1px solid #e2e8f0;
    border-top: 3px solid #94a3b8;
    border-radius: 12px;
    padding: 16px 18px;
    box-shadow: 0 1px 3px rgba(15,23,42,0.05);
    transition: transform 0.15s ease, box-shadow 0.15s ease;
  }
  .mcard:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(15,23,42,0.08);
  }
  .mcard-total    { border-top-color: #64748b; }
  .mcard-bypass   { border-top-color: #dc2626; }
  .mcard-defended { border-top-color: #16a34a; }
  .mcard-partial  { border-top-color: #ca8a04; }
  .mcard-error    { border-top-color: #94a3b8; }
  .mcard .label {
    font-size: 0.68rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #64748b;
    margin-bottom: 6px;
  }
  .mcard .value {
    font-size: 1.85rem;
    font-weight: 700;
    color: #0f172a;
    line-height: 1;
    font-variant-numeric: tabular-nums;
  }
  .mcard-bypass   .value { color: #dc2626; }
  .mcard-defended .value { color: #16a34a; }
  .mcard-partial  .value { color: #ca8a04; }

  /* Tier-cost strip */
  .tier-strip {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
    margin-bottom: 8px;
  }
  .tcard {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 12px 16px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .tcard .tlabel {
    font-size: 0.78rem;
    color: #475569;
    font-weight: 500;
  }
  .tcard .tvalue {
    font-size: 0.92rem;
    font-weight: 700;
    color: #0f172a;
    font-variant-numeric: tabular-nums;
  }
  .tcard.total { background: #fef2f2; border-color: #fecaca; }
  .tcard.total .tvalue { color: #dc2626; }

  /* Section dividers tighter */
  div[data-testid="stHorizontalBlock"] { gap: 12px !important; }
</style>
    """,
    unsafe_allow_html=True,
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
seed_exploitability = load_seed_exploitability()


# ── Page: Overview ──

if page == "Overview":
    if not results:
        st.markdown(
            f"""
<div class="hero">
  <div class="hero-title">Adversarial AI Security Platform</div>
  <div class="hero-subtitle">Multi-agent evaluation of the Clinical Co-Pilot</div>
  <a class="hero-pill" href="{TARGET_URL}" target="_blank">🎯 LIVE TARGET <code>{TARGET_URL.replace("https://", "")}</code></a>
</div>
            """,
            unsafe_allow_html=True,
        )
        st.warning(
            "No run results found at `evals/results/latest_results.json`. "
            "Run the attack suite locally and commit the JSON output to populate this view."
        )
        st.stop()

    summary = results.get("summary", {})
    by_cat = results.get("by_category", {})
    rs = results.get("results", [])
    triage_cost = sum(r.get("triage_cost", 0) for r in rs)
    judge_cost  = sum(r.get("judge_cost",  0) for r in rs)
    total_cost  = triage_cost + judge_cost
    triage_n    = sum(1 for r in rs if r.get("judged_by") == "triage")
    judge_n     = sum(1 for r in rs if r.get("judged_by") == "judge")
    total       = results.get("total_attacks", 0)

    # ── Hero banner ──
    st.markdown(
        f"""
<div class="hero">
  <div class="hero-title">Adversarial AI Security Platform</div>
  <div class="hero-subtitle">Multi-agent evaluation of the Clinical Co-Pilot — 26 threat-model sub-vectors, two-tier Judge, live target</div>
  <a class="hero-pill" href="{TARGET_URL}" target="_blank">🎯 LIVE TARGET <code>{TARGET_URL.replace("https://", "")}</code></a>
  <div class="hero-meta">
    Last run · <b>{results.get('timestamp', 'unknown')[:19].replace('T', ' ')} UTC</b>
    &nbsp;·&nbsp; <b>{total}</b> attacks
    &nbsp;·&nbsp; total judge spend <b>${total_cost:.4f}</b>
  </div>
</div>
        """,
        unsafe_allow_html=True,
    )

    # ── Verdict metric cards (5-up) ──
    st.markdown(
        f"""
<div class="card-grid">
  <div class="mcard mcard-total"><div class="label">Total attacks</div><div class="value">{total}</div></div>
  <div class="mcard mcard-bypass"><div class="label">🔴 Bypasses</div><div class="value">{summary.get('bypass', 0)}</div></div>
  <div class="mcard mcard-defended"><div class="label">🟢 Defended</div><div class="value">{summary.get('defended', 0)}</div></div>
  <div class="mcard mcard-partial"><div class="label">🟡 Partial</div><div class="value">{summary.get('partial', 0)}</div></div>
  <div class="mcard mcard-error"><div class="label">⚪ Errors</div><div class="value">{summary.get('error', 0)}</div></div>
</div>
        """,
        unsafe_allow_html=True,
    )

    # ── Tier cost strip ──
    if triage_n + judge_n > 0:
        st.markdown(
            f"""
<div class="tier-strip">
  <div class="tcard">
    <span class="tlabel">🥇 T1 Triage <span style="color:#94a3b8;">· Haiku 4.5</span></span>
    <span class="tvalue">{triage_n} · ${triage_cost:.4f}</span>
  </div>
  <div class="tcard">
    <span class="tlabel">🥈 T2 Judge <span style="color:#94a3b8;">· Sonnet 4.5</span></span>
    <span class="tvalue">{judge_n} · ${judge_cost:.4f}</span>
  </div>
  <div class="tcard total">
    <span class="tlabel">Total judge spend</span>
    <span class="tvalue">${total_cost:.4f}</span>
  </div>
</div>
            """,
            unsafe_allow_html=True,
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
        st.warning(
            "**Caveat — confirmed §2.4 finding (Critical):** the `/chat` endpoint itself "
            "accepts unauthenticated requests. Every attack above ran with **no** "
            "Authorization header. The AI-layer refusals are real, but they are the only "
            "defense — anyone on the internet can reach the agent and burn the operator's "
            "token budget. See the Threat Model tab §2.4 for evidence and remediation."
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

        judged_by = r.get("judged_by", "judge")
        tier_badge = "🥇 T1" if judged_by == "triage" else "🥈 T2"
        header = (
            f"{emoji} **[{r.get('attack_id')}]** "
            f"`{r.get('category')}/{r.get('subcategory')}` — "
            f":{color_tag}[**{verdict.upper()}**] (conf {confidence:.2f}, {tier_badge})"
        )

        with st.expander(header):
            meta_cols = st.columns(3)
            with meta_cols[0]:
                st.markdown(f"**Severity:** {r.get('severity', '?')}")
                expl = r.get("exploitability") or seed_exploitability.get(r.get("attack_id"), "?")
                st.markdown(f"**Exploitability:** {expl}")
                tm_ref = r.get("threat_model_ref") or ""
                if tm_ref:
                    st.markdown(f"**Threat model:** [{tm_ref}]({REPO_URL}/blob/main/THREAT_MODEL.md)")
                st.markdown(f"**Latency:** {r.get('target_latency_ms', 0)} ms")
            with meta_cols[1]:
                st.markdown(f"**Judge confidence:** {confidence:.2f}")
                t_cost = r.get("triage_cost", 0.0)
                j_cost = r.get("judge_cost", 0.0)
                if t_cost and j_cost:
                    st.markdown(f"**Cost:** T1 ${t_cost:.5f} + T2 ${j_cost:.5f}")
                elif t_cost:
                    st.markdown(f"**Cost:** T1 ${t_cost:.5f} (short-circuited)")
                else:
                    st.markdown(f"**Cost:** T2 ${j_cost:.5f}")
                st.markdown(f"**Judged by:** {judged_by}")
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
    st.caption(f"Full text from [ARCHITECTURE.md]({REPO_URL}/blob/main/ARCHITECTURE.md) — 5-agent design (two-tier Judge), message schemas, decision algorithms.")
    render_markdown_with_mermaid(load_markdown("ARCHITECTURE.md"), height=760)
