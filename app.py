"""
app.py  -  the SCREEN of the AI Scam Detector (Step 5: Detection Result)
------------------------------------------------------------------------
Streamlit turns simple Python lines into a web page.
Run it with:   streamlit run app.py

Features on this screen:
    - paste an email OR upload a file (.eml / .txt / .pdf)
    - classification, risk level, risk indicators, guidance
    - mail source (sender, domain, origin IP), links and attachments
    - sample emails to try, downloadable report, scan history
"""

import datetime

import streamlit as st

from detector import detect, report_as_text, train_models
from email_parser import parse_email_text, read_uploaded_file
from samples import SAMPLES

st.set_page_config(page_title="AI Scam Detector", page_icon="🛡️")


# Train the three algorithms only ONCE (Streamlit re-runs this file on every
# click, and @st.cache_resource stops it from re-training each time).
@st.cache_resource
def load_models():
    return train_models()


vectorizer, models = load_models()

# st.session_state is Streamlit's "memory". It survives button clicks, so we
# use it to remember the last result, the history, and the text box content.
if "last_result" not in st.session_state:
    st.session_state.last_result = None
if "history" not in st.session_state:
    st.session_state.history = []
if "email_box" not in st.session_state:
    st.session_state.email_box = ""


# ----------------------------------------------------------------------
# Small functions that run when the user clicks something
# ----------------------------------------------------------------------
def load_sample():
    """When a sample is picked, copy its text into the text box."""
    choice = st.session_state.sample_choice
    if choice in SAMPLES:
        st.session_state.email_box = SAMPLES[choice]


def clear_history():
    st.session_state.history = []


# ----------------------------------------------------------------------
# Functions that DRAW parts of the result
# ----------------------------------------------------------------------
def show_mail_source(source_info):
    """Where did the email come from? (sender, domain, origin IP)"""
    sender = source_info["sender"]
    st.subheader("📍 Mail source")

    if not sender["found"]:
        st.info("No sender information was found. Paste the FULL email including its "
                "headers (From:, Received: ...) or upload the .eml file to trace the source.")
        return

    st.markdown(f"- **Sender name:** {sender['name'] or '(none)'}")
    st.markdown(f"- **Email address:** `{sender['address']}`")
    st.markdown(f"- **Domain:** `{sender['domain']}` ({sender['domain_type']})")
    if sender["country_hint"]:
        st.markdown(f"- **Country hint:** {sender['country_hint']}")
    st.markdown(f"- **Likely origin IP:** `{sender['origin_ip'] or 'not found in the headers'}`")
    if sender["origin_ip"]:
        st.caption("Finding the country of an IP address needs an online lookup service, "
                   "which is not included in this offline version.")

    for warning in sender["warnings"]:
        st.warning(warning)
    for note in sender["notes"]:
        st.caption("ℹ️ " + note)


def show_links(links):
    st.subheader("🔗 Links found")
    if not links:
        st.write("No links were found in this email.")
        return
    lines = []
    for link in links:
        lines.append(f"- `{link['url']}`")
        for flag in link["flags"]:
            lines.append(f"    - ⚠️ {flag}")
        if not link["flags"]:
            lines.append("    - ✅ nothing unusual")
    st.markdown("\n".join(lines))


def show_attachments(attachments):
    st.subheader("📎 Attachments")
    if not attachments:
        st.write("No attachments were found. (Attachments can only be checked in .eml files.)")
        return
    lines = []
    for item in attachments:
        lines.append(f"- `{item['name']}`")
        for flag in item["flags"]:
            lines.append(f"    - ⚠️ {flag}")
        if not item["flags"]:
            lines.append("    - ✅ nothing unusual")
    st.markdown("\n".join(lines))


def show_detection_result(report):
    """Display the final report to the user (FR-16, FR-17, FR-18)."""
    st.divider()
    st.subheader("Detection Result")

    # Classification, shown in a green / yellow / red box
    classification = report["overall_classification"]
    if classification == "Legitimate":
        st.success(f"✅ {classification}")
    elif classification == "Suspicious":
        st.warning(f"⚠️ {classification}")
    else:
        st.error(f"🚨 {classification}")

    if report["note"]:
        st.caption(report["note"])

    st.markdown(f"**Risk level:** {report['risk_level']}")

    st.markdown("**Risk indicators:**")
    if report["risk_indicators"]:
        for indicator in report["risk_indicators"]:
            st.markdown(f"- {indicator}")
    else:
        st.markdown("- No obvious warning signs were found in the text.")

    st.markdown("**Guidance:**")
    st.info(report["guidance"])

    st.markdown("**How each algorithm voted:**")
    for name, verdict in report["algorithm_verdicts"].items():
        st.markdown(f"- {name}: {verdict}")

    # The new sections
    show_mail_source(report["source_info"])
    show_links(report["source_info"]["links"])
    show_attachments(report["source_info"]["attachments"])

    st.download_button("⬇️ Download report", data=report_as_text(report),
                       file_name="scam_report.txt", mime="text/plain")

    # SSR-03: never claim the result is a guarantee
    st.caption("This is an automated assessment to support your judgement. "
               "It can be wrong, so it is not a guarantee that an email is safe or fraudulent.")


# ----------------------------------------------------------------------
# The page itself
# ----------------------------------------------------------------------
st.title("🛡️ AI Scam Detector")
st.write("Paste an email or upload a file, then click the **Analyse** button.")

tab_paste, tab_upload = st.tabs(["📋 Paste email", "📎 Upload file"])

with tab_paste:
    st.selectbox("Try a sample", ["(choose a sample)"] + list(SAMPLES), key="sample_choice", on_change=load_sample)
    st.text_area("Email content (include the headers if you have them)", height=250,
                 placeholder="Paste the email here...", key="email_box")
    analyse_pasted = st.button("Analyse Email")

with tab_upload:
    uploaded_file = st.file_uploader("Upload an email file", type=["eml", "txt", "pdf"])
    st.caption("Tip: .eml files give the best results because they contain the full headers and attachments.")
    analyse_file = st.button("Analyse File")

# ----------------------------------------------------------------------
# What happens when a button is clicked
# ----------------------------------------------------------------------
parsed, error = None, None

if analyse_pasted:
    parsed = parse_email_text(st.session_state.email_box)
elif analyse_file:
    if uploaded_file is None:
        error = "Please choose a file first."
    else:
        parsed, error = read_uploaded_file(uploaded_file.name, uploaded_file.getvalue())

if error:
    st.session_state.last_result = {"status": "invalid", "message": error}
elif parsed is not None:
    result = detect(parsed, vectorizer, models)
    st.session_state.last_result = result

    if result["status"] == "ok":    # remember it in the history
        report = result["report"]
        label = parsed["subject"] or parsed["model_text"][:30]
        time_now = datetime.datetime.now().strftime("%H:%M")
        st.session_state.history.append(
            f"{time_now} | {label} -> {report['overall_classification']} ({report['risk_level']})")

# Show the last result (kept in memory, so it stays on screen after clicking Download)
last = st.session_state.last_result
if last is not None:
    if last["status"] == "ok":
        show_detection_result(last["report"])
    else:
        st.error(last["message"])

# ----------------------------------------------------------------------
# Sidebar: scan history (SSR-04: only kept in memory, never saved to disk)
# ----------------------------------------------------------------------
st.sidebar.header("🕘 Scan history")
st.sidebar.caption("Kept only while this page is open. Nothing is saved to disk.")
if st.session_state.history:
    for entry in reversed(st.session_state.history):
        st.sidebar.text(entry)
    st.sidebar.button("Clear history", on_click=clear_history)
else:
    st.sidebar.write("No scans yet.")
