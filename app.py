"""
app.py  -  the SCREEN of the AI Scam Detector (Step 5: Detection Result)
------------------------------------------------------------------------
Streamlit turns simple Python lines into a web page.
Run it with:   streamlit run app.py
"""

import streamlit as st

from detector import detect, train_models

st.set_page_config(page_title="AI Scam Detector", page_icon="🛡️")


# Train the three algorithms only ONCE (Streamlit re-runs this file on every
# click, and @st.cache_resource stops it from re-training each time).
@st.cache_resource
def load_models():
    return train_models()


vectorizer, models = load_models()


def show_detection_result(report):
    """Display the final report to the user (FR-16, FR-17, FR-18)."""
    st.subheader("Detection Result")

    # Classification, shown in a green / yellow / red box
    classification = report["overall_classification"]
    if classification == "Legitimate":
        st.success(f"✅ {classification}")
    elif classification == "Suspicious":
        st.warning(f"⚠️ {classification}")
    else:
        st.error(f"🚨 {classification}")

    # Risk level
    st.markdown(f"**Risk level:** {report['risk_level']}")

    # Risk indicators (a bullet list)
    st.markdown("**Risk indicators:**")
    if report["risk_indicators"]:
        for indicator in report["risk_indicators"]:
            st.markdown(f"- {indicator}")
    else:
        st.markdown("- No obvious warning signs were found.")

    # Guidance
    st.markdown("**Guidance:**")
    st.info(report["guidance"])

    # What each algorithm said
    st.markdown("**How each algorithm voted:**")
    for name, verdict in report["algorithm_verdicts"].items():
        st.markdown(f"- {name}: {verdict}")

    # SSR-03: never claim the result is a guarantee
    st.caption(
        "This is an automated assessment to support your judgement. "
        "It can be wrong, so it is not a guarantee that an email is safe or fraudulent."
    )


# ----------------------------------------------------------------------
# The page itself (FR-01: user enters or pastes email content)
# ----------------------------------------------------------------------
st.title("🛡️ AI Scam Detector")
st.write("Paste an email below (subject and body) and click **Analyse Email**.")

email_text = st.text_area(
    "Email content",
    height=250,
    placeholder="Paste the email here...",
)

if st.button("Analyse Email"):
    result = detect(email_text, vectorizer, models)

    if result["status"] == "ok":
        show_detection_result(result["report"])
    else:
        # Empty / invalid / unprocessable input (FR-03): show a friendly message
        st.error(result["message"])
