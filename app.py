import time
import json
import textwrap
import concurrent.futures
import sqlite3
import os
import html
from datetime import datetime

import streamlit as st
import plotly.graph_objects as go
from reports.report_generator import generate_investigation_report

_original_st_markdown = st.markdown
def _render_indented_html(body, *args, **kwargs):
    if kwargs.get("unsafe_allow_html", False) and isinstance(body, str):
        return st.html(textwrap.dedent(body))
    return _original_st_markdown(body, *args, **kwargs)
st.markdown = _render_indented_html

from modules.email_parser import parse_email
from modules.detection_engine import analyze_email
from modules.header_analyzer import analyze_headers
from modules.url_analyzer import analyze_urls
from modules.virustotal_analyzer import analyze_threat_intelligence
from modules.ai_analyzer import analyze_email_with_ai
from modules.evidence_correlator import correlate_evidence

st.set_page_config(page_title="PHISHINTEL AI | SOC Investigation", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root{--bg:#080d1a;--panel:#101a2d;--line:rgba(127,164,220,.17);--text:#edf4ff;--muted:#91a4c2;--cyan:#39d5f6;--purple:#a879ff;--red:#ff627d;--orange:#ffb454;--green:#42d6a4}
html,body,[class*="css"]{font-family:'DM Sans',sans-serif}
.stApp{background:radial-gradient(circle at 12% 0%,rgba(54,103,190,.16),transparent 30%),radial-gradient(circle at 88% 8%,rgba(138,75,220,.13),transparent 28%),linear-gradient(135deg,#080d1a 0%,#0b1222 52%,#090f1d 100%);color:var(--text)}
[data-testid="stHeader"]{background:rgba(8,13,26,.75)}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0e1729 0%,#0a1120 100%);border-right:1px solid var(--line)}
[data-testid="stSidebar"] *{color:#dce8fa}
h1,h2,h3,h4{font-family:'Space Grotesk',sans-serif!important;color:var(--text)!important}
.hero{padding:24px 28px;border:1px solid rgba(77,158,255,.25);border-radius:22px;background:linear-gradient(115deg,rgba(19,39,70,.95),rgba(26,24,59,.88));box-shadow:0 14px 45px rgba(0,0,0,.22);margin:6px 0 22px}
.eyebrow{color:var(--cyan);font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px}
.hero-title{font-family:'Space Grotesk';font-size:clamp(27px,3vw,38px);line-height:1.15;font-weight:700;color:#f4f8ff}
.hero-sub{color:#a9bbd8;font-size:14px;margin-top:9px;max-width:780px}
.section-title{font-family:'Space Grotesk';font-size:18px;font-weight:650;color:#eaf2ff;margin:14px 0 12px}
.metric-card{background:linear-gradient(145deg,rgba(19,32,55,.96),rgba(14,24,43,.96));border:1px solid var(--line);border-radius:16px;padding:17px 18px;min-height:112px}
.metric-label{color:#91a7c7;font-size:11px;font-weight:700;letter-spacing:1.1px;text-transform:uppercase}
.metric-value{color:#f3f7ff;font-family:'Space Grotesk';font-size:25px;font-weight:700;margin-top:7px;overflow-wrap:anywhere}
.metric-note{color:#91a7c7;font-size:11px;margin-top:2px}
.panel{background:rgba(16,26,45,.88);border:1px solid var(--line);border-radius:17px;padding:18px 20px;margin:8px 0 14px}
.evidence{background:rgba(18,31,54,.82);border:1px solid rgba(123,157,205,.17);border-left:3px solid var(--cyan);border-radius:12px;padding:13px 15px;margin:9px 0}
div.stButton>button{border:1px solid rgba(57,213,246,.38);background:linear-gradient(100deg,#1769a9,#5141a2);color:white;border-radius:11px;padding:.65rem 1.2rem;font-weight:700}
div.stButton>button:hover{border-color:#6ce6ff;box-shadow:0 0 20px rgba(57,213,246,.2);color:white}
.stTextArea textarea,.stTextInput input{background:#0b1425!important;color:#e8f1ff!important;border:1px solid rgba(117,155,211,.25)!important;border-radius:12px!important}
[data-testid="stTabs"] button{color:#9fb3d1}
[data-testid="stTabs"] button[aria-selected="true"]{color:#63def7!important;border-bottom-color:#39d5f6!important}
hr{border-color:rgba(127,164,220,.15)}
footer{visibility:hidden}
</style>
""", unsafe_allow_html=True)

def safe_get(obj, key, default=None):
    return obj.get(key, default) if isinstance(obj, dict) else default

def as_list(value):
    if value is None: return []
    if isinstance(value, (list, tuple)): return list(value)
    return [value]

def pretty(value):
    if value is None: return "Not available"
    if isinstance(value, (dict, list, tuple)): return json.dumps(value, indent=2, default=str)
    return str(value)


# Local SQLite investigation history
DB_DIR = "database"
DB_PATH = os.path.join(DB_DIR, "investigations.db")


def init_history_db():
    os.makedirs(DB_DIR, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigated_at TEXT NOT NULL,
                sender TEXT,
                subject TEXT,
                verdict TEXT,
                risk_level TEXT,
                risk_score INTEGER,
                raw_email TEXT,
                result_json TEXT NOT NULL,
                case_status TEXT NOT NULL DEFAULT 'Open',
                case_priority TEXT NOT NULL DEFAULT 'Medium',
                analyst_notes TEXT NOT NULL DEFAULT '',
                case_updated_at TEXT
            )
        """)
        # Backward-compatible migration for databases created by earlier versions.
        existing = {row[1] for row in conn.execute("PRAGMA table_info(investigations)").fetchall()}
        migrations = {
            "case_status": "ALTER TABLE investigations ADD COLUMN case_status TEXT NOT NULL DEFAULT 'Open'",
            "case_priority": "ALTER TABLE investigations ADD COLUMN case_priority TEXT NOT NULL DEFAULT 'Medium'",
            "analyst_notes": "ALTER TABLE investigations ADD COLUMN analyst_notes TEXT NOT NULL DEFAULT ''",
            "case_updated_at": "ALTER TABLE investigations ADD COLUMN case_updated_at TEXT",
        }
        for column, statement in migrations.items():
            if column not in existing:
                conn.execute(statement)
        conn.commit()


def save_investigation(result, raw_email):
    parsed = result.get("parsed", {}) or {}
    correlation = result.get("correlation", {}) or {}
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("""
            INSERT INTO investigations
            (investigated_at, sender, subject, verdict, risk_level, risk_score, raw_email, result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().astimezone().isoformat(timespec="seconds"),
            str(safe_get(parsed, "sender", "Unknown") or "Unknown"),
            str(safe_get(parsed, "subject", "No subject") or "No subject"),
            str(safe_get(correlation, "verdict", "Inconclusive")),
            str(safe_get(correlation, "risk_level", "Unknown")),
            int(safe_get(correlation, "risk_score", 0) or 0),
            raw_email,
            json.dumps(result, default=str)
        ))
        conn.commit()
        return cursor.lastrowid


def load_investigations():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT id, investigated_at, sender, subject, verdict, risk_level, risk_score
            FROM investigations
            ORDER BY id DESC
        """).fetchall()
    return [dict(row) for row in rows]


def load_investigation(investigation_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM investigations WHERE id = ?", (investigation_id,)
        ).fetchone()
    if row is None:
        return None
    record = dict(row)
    record["result"] = json.loads(record["result_json"])
    return record


def delete_investigation(investigation_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,))
        conn.commit()


def update_case(investigation_id, status, priority, notes):
    allowed_status = {"Open", "In Progress", "Contained", "Closed"}
    allowed_priority = {"Critical", "High", "Medium", "Low"}
    if status not in allowed_status or priority not in allowed_priority:
        raise ValueError("Invalid case status or priority.")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """UPDATE investigations
               SET case_status = ?, case_priority = ?, analyst_notes = ?,
                   case_updated_at = ?
               WHERE id = ?""",
            (status, priority, notes, datetime.now().astimezone().isoformat(timespec="seconds"),
             investigation_id)
        )
        conn.commit()


init_history_db()

def metric_card(label, value, note=""):
    label_html = html.escape(str(label))
    value_html = html.escape(str(value))
    note_html = html.escape(str(note))
    st.markdown(
        f'<div class="metric-card"><div class="metric-label">{label_html}</div>'
        f'<div class="metric-value">{value_html}</div><div class="metric-note">{note_html}</div></div>',
        unsafe_allow_html=True
    )

def verdict_color(verdict):
    value = str(verdict).lower()
    if "phishing" in value or "high" in value: return "#ff627d"
    if "suspicious" in value or "medium" in value: return "#ffb454"
    if "low risk" in value or "no strong" in value: return "#42d6a4"
    return "#39d5f6"

def make_donut(score):
    score = max(0, min(100, int(score or 0)))
    fig = go.Figure(go.Pie(values=[score, 100-score], hole=.78, marker=dict(colors=["#39d5f6","rgba(125,150,190,.16)"]), textinfo="none", sort=False))
    fig.update_layout(showlegend=False, margin=dict(l=5,r=5,t=5,b=5), height=185, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", annotations=[dict(text=f"<b>{score}</b><br><span style='font-size:10px'>/ 100</span>",x=.5,y=.5,showarrow=False,font=dict(size=25,color="#edf4ff"))])
    return fig

def render_data(data, empty="No data available."):
    if not data:
        st.info(empty)
    elif isinstance(data, dict):
        for key, value in data.items():
            with st.expander(str(key).replace("_"," ").title()):
                st.code(pretty(value), language="json")
    elif isinstance(data, list):
        for i, item in enumerate(data, 1):
            with st.expander(f"Item {i}"):
                st.code(pretty(item), language="json")
    else:
        st.code(pretty(data), language="json")

def run_investigation(raw_email):
    start = time.perf_counter()
    t = time.perf_counter(); parsed = parse_email(raw_email); t_parse = time.perf_counter()-t
    t = time.perf_counter(); rules = analyze_email(parsed); t_rules = time.perf_counter()-t
    t = time.perf_counter(); headers = analyze_headers(parsed); t_headers = time.perf_counter()-t
    urls_found = as_list(safe_get(parsed,"urls",[]))
    domains_found = as_list(safe_get(parsed,"domains",[]))
    t = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = {
            "urls": pool.submit(analyze_urls, urls_found),
            "vt": pool.submit(analyze_threat_intelligence, urls_found, domains_found),
            "ai": pool.submit(analyze_email_with_ai, parsed),
        }
        results = {}
        for name, future in futures.items():
            try: results[name] = future.result()
            except Exception as exc: results[name] = {"error": str(exc)}
    t_enrichment = time.perf_counter()-t
    t = time.perf_counter()
    correlation = correlate_evidence(parsed, rules, headers, results["urls"], results["vt"], results["ai"])
    t_correlation = time.perf_counter()-t
    timings = {
        "Email parsing": t_parse,
        "Rule detection": t_rules,
        "Header analysis": t_headers,
        "URL / DNS / VirusTotal / AI (parallel)": t_enrichment,
        "Evidence correlation": t_correlation,
        "Total elapsed": time.perf_counter()-start,
    }
    return {"parsed":parsed,"rules":rules,"headers":headers,"urls":results["urls"],"vt":results["vt"],"ai":results["ai"],"correlation":correlation,"timing":timings}

with st.sidebar:
    st.markdown('<div style="padding:8px 4px 18px"><div style="font-size:12px;letter-spacing:2px;color:#5edcf6;font-weight:800">PHISHINTEL</div><div style="font-family:Space Grotesk;font-size:25px;font-weight:700;color:#f1f6ff">AI <span style="color:#a879ff">SOC</span></div><div style="font-size:11px;color:#8298ba">EMAIL THREAT INVESTIGATION</div></div>', unsafe_allow_html=True)
    page = st.radio("WORKSPACE",["Email Investigation","Investigation History","SOC Case Management","IOC Inventory","Threat Analytics","Detection Lab","System Information"])
    st.divider()
    st.markdown("**Investigation modules**")
    for name in ["Email parsing","Rule-based detection","Header inspection","URL & DNS analysis","VirusTotal enrichment","Local AI analysis","Evidence correlation"]:
        st.markdown(f'<div style="font-size:12px;color:#9db1d0;padding:4px 0">◈ {name}</div>', unsafe_allow_html=True)
    st.divider()
    st.caption("PHISHINTEL AI · Local SOC lab")
    st.caption(datetime.now().strftime("%d %b %Y"))

st.markdown("""
<div class="hero">
 <div class="eyebrow">AI-powered security operations workspace</div>
 <div class="hero-title">Phishing Email Investigation</div>
 <div class="hero-sub">Analyze suspicious email content, inspect authentication headers, examine URLs, enrich indicators with threat intelligence, and correlate evidence into an explainable investigation verdict.</div>
</div>
""", unsafe_allow_html=True)

if page == "Email Investigation":
    st.markdown('<div class="section-title">New investigation</div>', unsafe_allow_html=True)
    left, right = st.columns([1.55,1])
    with left:
        raw_email = st.text_area("Paste raw email source", height=270, placeholder="From: sender@example.com\nTo: analyst@example.com\nSubject: Urgent account verification\n\nPaste the complete email headers and body here...", key="raw_email_input")
        run_clicked = st.button("🛡️  Analyze email", type="primary", use_container_width=True)
    with right:
        st.markdown("""
        <div class="panel">
         <div style="font-weight:700;font-size:15px;color:#edf4ff">Investigation workflow</div>
         <div style="color:#91a4c2;font-size:12px;margin:6px 0 14px">Analysis pipeline</div>
         <div style="padding:7px 0;color:#c8d8ee;font-size:13px">01 &nbsp; Parse email and extract IOCs</div>
         <div style="padding:7px 0;color:#c8d8ee;font-size:13px">02 &nbsp; Detect suspicious content patterns</div>
         <div style="padding:7px 0;color:#c8d8ee;font-size:13px">03 &nbsp; Inspect sender and authentication headers</div>
         <div style="padding:7px 0;color:#c8d8ee;font-size:13px">04 &nbsp; Analyze URLs and DNS indicators</div>
         <div style="padding:7px 0;color:#c8d8ee;font-size:13px">05 &nbsp; Enrich indicators with VirusTotal</div>
         <div style="padding:7px 0;color:#c8d8ee;font-size:13px">06 &nbsp; Generate local AI assessment</div>
         <div style="padding:7px 0;color:#c8d8ee;font-size:13px">07 &nbsp; Correlate evidence and assign verdict</div>
        </div>
        """, unsafe_allow_html=True)
        st.info("Privacy: VirusTotal lookups may disclose submitted indicators to a third party. Do not analyze confidential URLs unless permitted.")
    if run_clicked:
        if not raw_email.strip():
            st.warning("Paste an email before starting the investigation.")
        else:
            try:
                with st.spinner("Analyzing email and correlating security evidence..."):
                    st.session_state["result"] = run_investigation(raw_email)
                    st.session_state["current_investigation_id"] = save_investigation(
                        st.session_state["result"], raw_email
                    )
                st.success(
                    f"Investigation completed and saved to history "
                    f"(ID: {st.session_state['current_investigation_id']})."
                )
            except Exception as exc:
                st.error(f"Investigation could not be completed: {exc}")
                st.exception(exc)

    data = st.session_state.get("result")
    if data:
        corr = data.get("correlation",{}) or {}
        verdict = safe_get(corr,"verdict","Inconclusive")
        verdict_html = html.escape(str(verdict))
        risk = safe_get(corr,"risk_score",0)
        level = safe_get(corr,"risk_level","Unknown")
        level_html = html.escape(str(level))
        confidence = safe_get(corr,"confidence_score",0)
        color = verdict_color(verdict)
        st.markdown('<div class="section-title">Correlated investigation verdict</div>', unsafe_allow_html=True)
        vcol, scol, ccol = st.columns([1.35,1,1])
        with vcol:
            st.markdown(f'<div class="panel" style="height:185px;border-color:{color}55"><div class="metric-label">FINAL ASSESSMENT</div><div style="font-family:Space Grotesk;font-size:26px;font-weight:700;color:{color};margin-top:15px">{verdict_html}</div><div style="font-size:12px;color:#9eb1ce;margin-top:8px">{level_html} risk · Correlated evidence assessment</div></div>', unsafe_allow_html=True)
        with scol:
            st.markdown('<div class="metric-label" style="text-align:center;margin-top:8px">RISK SCORE</div>', unsafe_allow_html=True)
            st.plotly_chart(make_donut(risk), use_container_width=True, config={"displayModeBar":False})
        with ccol:
            st.markdown('<div class="metric-label" style="text-align:center;margin-top:8px">EVIDENCE COVERAGE</div>', unsafe_allow_html=True)
            st.plotly_chart(make_donut(confidence), use_container_width=True, config={"displayModeBar":False})
        summary_html = html.escape(str(safe_get(corr, "summary", "No summary returned.")))
        st.markdown(f'<div class="panel"><div class="metric-label">INVESTIGATION SUMMARY</div><div style="color:#dce8fa;font-size:14px;margin-top:8px">{summary_html}</div></div>', unsafe_allow_html=True)
        if safe_get(corr,"confidence_note"):
            st.caption(safe_get(corr,"confidence_note"))

        st.markdown('<div class="section-title">Correlated evidence</div>', unsafe_allow_html=True)
        evidence = as_list(safe_get(corr,"evidence",[]))
        if not evidence:
            st.info("No correlated evidence items were returned.")
        for item in evidence:
            if isinstance(item,dict):
                title = html.escape(str(item.get("title", item.get("name", "Evidence item"))))
                desc = html.escape(str(item.get("description", item.get("detail", ""))))
                source = html.escape(str(item.get("source", "Analysis engine")))
                severity = html.escape(str(item.get("severity", "Informational")))
                points = html.escape(str(item.get("points", item.get("score", 0))))
                sev = verdict_color(severity)
                st.markdown(f'<div class="evidence"><div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap"><b style="color:#edf4ff">{title}</b><span style="color:{sev};font-size:11px;font-weight:700">{severity} · +{points}</span></div><div style="color:#b2c3dc;font-size:13px;margin-top:6px">{desc}</div><div style="color:#7189ac;font-size:11px;margin-top:7px">Source: {source}</div></div>', unsafe_allow_html=True)
            else:
                st.write(item)
        limitations = as_list(safe_get(corr,"limitations",[]))
        if limitations:
            with st.expander("Important limitations and analyst notes"):
                for item in limitations: st.markdown(f"- {item}")

        st.markdown('<div class="section-title">Investigation report</div>', unsafe_allow_html=True)
        try:
            pdf_report = generate_investigation_report(data)
            st.download_button(
                label="📄 Download PDF Investigation Report",
                data=pdf_report,
                file_name="PhishIntelAI_Investigation_Report.pdf",
                mime="application/pdf",
                use_container_width=True,
                key="download_investigation_report"
            )
        except Exception as report_error:
            st.error(f"Could not generate the PDF report: {report_error}")

        st.markdown('<div class="section-title">Detailed analysis workspace</div>', unsafe_allow_html=True)
        tabs = st.tabs(["Overview","Email details","Rule findings","Headers","URL & DNS","VirusTotal","AI assessment","Performance"])
        with tabs[0]:
            parsed = data.get("parsed",{}) or {}
            a,b,c,d = st.columns(4)
            with a: metric_card("Sender",safe_get(parsed,"sender","Unknown"),"Extracted From address")
            with b: metric_card("URLs",len(as_list(safe_get(parsed,"urls",[]))),"URLs found")
            with c: metric_card("Domains",len(as_list(safe_get(parsed,"domains",[]))),"Unique domains")
            with d: metric_card("IP addresses",len(as_list(safe_get(parsed,"ip_addresses",[]))),"Extracted IP indicators")
            st.markdown("**Category score breakdown**")
            cats = safe_get(corr,"category_scores",{})
            if isinstance(cats,dict) and cats:
                labels=list(cats.keys()); values=[v if isinstance(v,(int,float)) else 0 for v in cats.values()]
                fig=go.Figure(go.Bar(x=values,y=[str(x).replace("_"," ").title() for x in labels],orientation="h",marker=dict(color="#39d5f6")))
                fig.update_layout(height=max(220,45*len(labels)),margin=dict(l=10,r=10,t=10,b=10),paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",font=dict(color="#b7c8e2"),xaxis=dict(gridcolor="rgba(150,170,210,.12)"))
                st.plotly_chart(fig,use_container_width=True)
            else: st.info("No category breakdown returned.")
        with tabs[1]:
            parsed=data.get("parsed",{}) or {}
            for field in ["sender","recipient","subject","date"]:
                st.text_input(field.replace("_"," ").title(),value=str(safe_get(parsed,field,"") or ""),disabled=True)
            for label,field in [("Extracted URLs","urls"),("Extracted domains","domains"),("Extracted IP addresses","ip_addresses")]:
                st.markdown(f"**{label}**")
                st.code("\n".join(as_list(safe_get(parsed,field,[]))) or f"No {label.lower()} found.")
            with st.expander("Raw parsed email structure"): st.code(pretty(parsed),language="json")
        with tabs[2]: render_data(data.get("rules"),"No rule findings returned.")
        with tabs[3]:
            render_data(data.get("headers"),"No header analysis returned.")
            st.warning("Authentication results in pasted headers can be forged. Treat them as reported values unless verified using trusted mail-system logs.")
        with tabs[4]:
            render_data(data.get("urls"),"No URL analysis returned.")
            st.caption("URL analysis checks indicators and DNS resolution. It does not visit URLs.")
        with tabs[5]:
            render_data(data.get("vt"),"No VirusTotal results returned.")
            st.warning("Zero detections do not prove an indicator is safe. Reputation data may be incomplete or outdated.")
        with tabs[6]:
            render_data(data.get("ai"),"No AI assessment returned.")
            st.caption("Local AI output is decision support only. Validate its statements against observable evidence.")
        with tabs[7]:
            for name, seconds in data.get("timing",{}).items():
                st.write(f"**{name}:** {seconds:.2f} seconds" if isinstance(seconds,(int,float)) else f"**{name}:** {seconds}")
            st.caption("Enrichment tasks run concurrently; their combined elapsed time is shown as one pipeline stage.")
        if st.button("Clear current investigation"):
            st.session_state.pop("result",None)
            st.rerun()

elif page == "SOC Case Management":
    st.markdown('<div class="section-title">SOC case management</div>', unsafe_allow_html=True)
    st.caption("Track investigation lifecycle, priority and analyst notes. Changes are stored in the local SQLite database.")
    cases = load_investigations()
    if not cases:
        st.info("No investigations are available yet. Analyze an email first.")
    else:
        status_filter = st.selectbox("Filter by case status", ["All", "Open", "In Progress", "Contained", "Closed"])
        priority_filter = st.selectbox("Filter by priority", ["All", "Critical", "High", "Medium", "Low"])
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = [dict(row) for row in conn.execute(
                "SELECT id, investigated_at, sender, subject, verdict, risk_level, risk_score, "
                "case_status, case_priority, analyst_notes, case_updated_at "
                "FROM investigations ORDER BY id DESC"
            ).fetchall()]
        filtered = [r for r in rows
                    if (status_filter == "All" or r["case_status"] == status_filter)
                    and (priority_filter == "All" or r["case_priority"] == priority_filter)]
        st.dataframe([{
            "Case ID": r["id"], "Date": r["investigated_at"], "Subject": r["subject"],
            "Verdict": r["verdict"], "Risk score": r["risk_score"],
            "Priority": r["case_priority"], "Status": r["case_status"]
        } for r in filtered], use_container_width=True, hide_index=True)
        if filtered:
            case_options = {f"#{r['id']} · {r['subject']} · {r['case_status']}": r["id"] for r in filtered}
            chosen = st.selectbox("Select case to update", list(case_options.keys()), key="case_select")
            case_id = case_options[chosen]
            record = next(r for r in filtered if r["id"] == case_id)
            with st.form(f"case_form_{case_id}"):
                st.write(f"**{record['subject']}**")
                status = st.selectbox("Case status", ["Open", "In Progress", "Contained", "Closed"],
                                      index=["Open", "In Progress", "Contained", "Closed"].index(record["case_status"]))
                priority = st.selectbox("Priority", ["Critical", "High", "Medium", "Low"],
                                        index=["Critical", "High", "Medium", "Low"].index(record["case_priority"]))
                notes = st.text_area("Analyst investigation notes", value=record["analyst_notes"], height=150,
                                     help="Record observations, actions taken, evidence and escalation details.")
                submitted = st.form_submit_button("Save case updates", type="primary")
            if submitted:
                update_case(case_id, status, priority, notes)
                st.success(f"Case #{case_id} updated.")
                st.rerun()
            st.caption(f"Last updated: {record['case_updated_at'] or 'Not updated yet'}")
        else:
            st.info("No cases match these filters.")

elif page == "IOC Inventory":
    import csv
    from io import StringIO

    st.markdown('<div class="section-title">Indicator of compromise inventory</div>', unsafe_allow_html=True)
    st.caption("Aggregated URLs, domains and IP addresses extracted from saved investigations. This inventory does not imply that every indicator is malicious.")
    history = load_investigations()
    ioc_rows = []
    for record in history:
        full = load_investigation(record["id"])
        result = (full or {}).get("result", {})
        parsed = result.get("parsed", {}) or {}
        for kind, field in [("URL", "urls"), ("Domain", "domains"), ("IP Address", "ip_addresses")]:
            for indicator in as_list(safe_get(parsed, field, [])):
                ioc_rows.append({
                    "Type": kind, "Indicator": str(indicator),
                    "Investigation ID": record["id"], "Subject": record["subject"],
                    "Verdict": record["verdict"], "Risk score": record["risk_score"],
                    "First recorded": record["investigated_at"]
                })
    if not ioc_rows:
        st.info("No indicators are available. Save an investigation containing URLs, domains or IP addresses first.")
    else:
        unique_count = len({(row["Type"], row["Indicator"]) for row in ioc_rows})
        a, b = st.columns(2)
        with a: metric_card("IOC observations", len(ioc_rows), "Across saved investigations")
        with b: metric_card("Unique indicators", unique_count, "Unique type and value pairs")
        kind_filter = st.selectbox("Indicator type", ["All", "URL", "Domain", "IP Address"])
        shown = ioc_rows if kind_filter == "All" else [row for row in ioc_rows if row["Type"] == kind_filter]
        st.dataframe(shown, use_container_width=True, hide_index=True)
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=list(ioc_rows[0].keys()))
        writer.writeheader()
        writer.writerows(shown)
        st.download_button("Download IOC inventory CSV", output.getvalue().encode("utf-8"),
                           file_name="PhishIntelAI_IOC_Inventory.csv", mime="text/csv")
    st.warning("Treat indicators as untrusted data. Do not open suspicious URLs. Review sharing rules before exporting or distributing IOC data.")

elif page == "Detection Lab":
    st.markdown('<div class="section-title">Safe detection validation lab</div>', unsafe_allow_html=True)
    st.caption("Run deterministic rule-engine checks against built-in synthetic email examples. No email is sent and no URL is opened.")
    scenarios = {
        "Simulated credential phishing": """From: security@example.test
To: analyst@example.test
Subject: URGENT account verification required

Your account will be suspended within 24 hours. Verify your account immediately.
Enter your password to restore access:
http://192.0.2.10/login
""",
        "Benign informational email": """From: updates@example.test
To: analyst@example.test
Subject: Monthly product newsletter

Hello, here is the monthly product newsletter. It contains product updates and release notes.
No action is required.
"""
    }
    for scenario_name, sample in scenarios.items():
        with st.expander(scenario_name):
            st.code(sample, language="text")
            if st.button(f"Run rule test: {scenario_name}", key=f"scenario_{scenario_name}"):
                try:
                    parsed_test = parse_email(sample)
                    test_result = analyze_email(parsed_test)
                    st.metric("Rule-engine risk score", f"{test_result.get('risk_score', 0)}/100")
                    st.write("Risk level:", test_result.get("risk_level", "Unknown"))
                    render_data(test_result.get("findings", []), "No rule findings.")
                except Exception as test_error:
                    st.error(f"Test failed: {test_error}")
    st.info("These scenarios validate configured rules only. They do not measure real-world detection accuracy or replace a labeled test dataset.")

elif page == "Threat Analytics":
    st.markdown('<div class="section-title">Threat analytics</div>', unsafe_allow_html=True)
    data=st.session_state.get("result")
    if not data: st.info("Run an email investigation first. Its results will appear here.")
    else:
        corr=data.get("correlation",{}) or {}
        a,b,c=st.columns(3)
        with a: metric_card("Risk score",safe_get(corr,"risk_score",0),"Correlated score out of 100")
        with b: metric_card("Risk level",safe_get(corr,"risk_level","Unknown"),"Current investigation")
        with c: metric_card("Evidence items",len(as_list(safe_get(corr,"evidence",[]))),"Correlated observations")
        st.markdown("**Threat intelligence counts**")
        render_data(safe_get(corr,"vt_counts",{}),"No threat intelligence counts available.")
        st.markdown("**Evidence categories**")
        render_data(safe_get(corr,"category_scores",{}),"No category scores available.")

elif page == "Investigation History":
    st.markdown('<div class="section-title">Investigation history</div>', unsafe_allow_html=True)
    st.caption("Previously completed investigations stored locally in your SQLite database.")

    history = load_investigations()
    if not history:
        st.info("No saved investigations yet. Analyze an email to create your first history record.")
    else:
        total = len(history)
        high_count = sum(1 for item in history if str(item.get("risk_level", "")).lower() == "high")
        suspicious_count = sum(1 for item in history if "phishing" in str(item.get("verdict", "")).lower()
                               or "suspicious" in str(item.get("verdict", "")).lower())

        m1, m2, m3 = st.columns(3)
        with m1: metric_card("Total investigations", total, "Saved records")
        with m2: metric_card("High-risk cases", high_count, "Risk level marked High")
        with m3: metric_card("Phishing / suspicious", suspicious_count, "Based on stored verdict text")

        st.markdown("**Saved investigations**")
        display_rows = [{
            "ID": item["id"],
            "Date / time": item["investigated_at"],
            "Sender": item["sender"],
            "Subject": item["subject"],
            "Verdict": item["verdict"],
            "Risk": item["risk_level"],
            "Score": item["risk_score"]
        } for item in history]
        st.dataframe(display_rows, use_container_width=True, hide_index=True)

        record_options = {
            f"#{item['id']} · {item['subject']} · {item['investigated_at']}": item["id"]
            for item in history
        }
        selected_label = st.selectbox("Select an investigation to review", list(record_options.keys()))
        selected_id = record_options[selected_label]
        selected = load_investigation(selected_id)

        if selected:
            result = selected["result"]
            corr = result.get("correlation", {}) or {}
            parsed = result.get("parsed", {}) or {}

            st.markdown('<div class="section-title">Selected investigation</div>', unsafe_allow_html=True)
            c1, c2, c3 = st.columns(3)
            with c1: metric_card("Verdict", selected["verdict"], f"Investigation #{selected_id}")
            with c2: metric_card("Risk score", selected["risk_score"], "Out of 100")
            with c3: metric_card("Risk level", selected["risk_level"], selected["investigated_at"])

            st.write(f"**Sender:** {selected['sender']}")
            st.write(f"**Subject:** {selected['subject']}")
            st.write(f"**Investigation summary:** {safe_get(corr, 'summary', 'No summary saved.')}")

            with st.expander("View correlated evidence"):
                render_data(safe_get(corr, "evidence", []), "No evidence items were saved.")
            with st.expander("View complete investigation data"):
                st.code(pretty(result), language="json")
            with st.expander("View original raw email"):
                st.code(selected.get("raw_email") or "Original email not available.")

            st.markdown("**Export this saved investigation**")
            try:
                saved_pdf = generate_investigation_report(result)
                st.download_button(
                    "📄 Download saved investigation PDF",
                    data=saved_pdf,
                    file_name=f"PhishIntelAI_Investigation_{selected_id}.pdf",
                    mime="application/pdf",
                    key=f"history_pdf_{selected_id}"
                )
            except Exception as report_error:
                st.error(f"Could not generate the saved PDF: {report_error}")

            st.divider()
            confirm_delete = st.checkbox(
                f"I understand that investigation #{selected_id} will be permanently deleted.",
                key=f"confirm_delete_{selected_id}"
            )
            if st.button("🗑️ Delete selected investigation", disabled=not confirm_delete,
                         key=f"delete_investigation_{selected_id}"):
                delete_investigation(selected_id)
                st.success(f"Investigation #{selected_id} deleted.")
                st.rerun()

    st.caption("History is stored in database/investigations.db on this machine. It is not synchronized or backed up automatically.")

else:
    st.markdown('<div class="section-title">System information</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="panel"><div style="font-size:17px;font-weight:700;color:#edf4ff">PHISHINTEL AI</div>
    <div style="color:#91a4c2;font-size:13px;margin-top:5px">Local AI-assisted phishing email investigation platform</div><hr>
    <div style="color:#d5e2f5;font-size:13px;line-height:2">
    <b>Frontend:</b> Streamlit<br><b>Analysis:</b> Python rule engine and evidence correlation<br>
    <b>Threat intelligence:</b> VirusTotal API v3<br><b>AI engine:</b> Local Ollama model<br>
    <b>Visualization:</b> Plotly<br><b>Case storage:</b> SQLite<br><b>Deployment:</b> Local development / SOC home lab</div></div>
    """,unsafe_allow_html=True)
    st.warning("This is an educational MVP, not a production email security gateway.")
    st.markdown("""**Operational safeguards**
- URLs are analyzed as indicators; the application does not open them.
- Do not submit confidential URLs to external services without authorization.
- AI conclusions must be validated against raw evidence.
- Email headers supplied as text are not independently trusted.
- Attachments are not executed by this application.""")

st.markdown('<div style="text-align:center;color:#617795;font-size:11px;padding:28px 0 10px">PHISHINTEL AI · SOC INVESTIGATION LAB · ANALYST-IN-THE-LOOP</div>',unsafe_allow_html=True)
