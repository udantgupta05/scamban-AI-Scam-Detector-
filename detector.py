"""
detector.py  -  the "brain" of the AI Scam Detector
---------------------------------------------------
Follows the flow from the SRS:

    Source Input -> Filtering -> Analysis -> Report Generation -> Detection Result

Steps 1-4 live in this file, one function each.
Step 5 (Detection Result = showing the report to the user) lives in app.py.

New in this version: the sender, links and attachments are also checked
(see source_checker.py) and added to the report.

You can test this file WITHOUT the screen by running:   python detector.py
"""

import re

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB

from source_checker import check_source
from training_data import EMAILS, LABELS

MAX_LENGTH = 5000   # PR-04: maximum email size we accept (characters)
MIN_WORDS = 3       # anything shorter than this is too small to analyse


# ======================================================================
# STEP 0 - TRAINING (done once, when the app starts)
# ======================================================================
def train_models():
    """Teach the three algorithms using the example emails in training_data.py."""

    # Computers can't read words, only numbers. The vectorizer turns each
    # email into a list of numbers (how important each word is in that email).
    vectorizer = TfidfVectorizer(stop_words="english")
    numbers = vectorizer.fit_transform(EMAILS)

    # The three algorithms named in the SRS, kept separate (SQA-08)
    models = {
        "Naive Bayes": MultinomialNB(),
        "Logistic Regression": LogisticRegression(),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
    }

    # "fit" = learn from the examples (EMAILS) and their answers (LABELS)
    for model in models.values():
        model.fit(numbers, LABELS)

    return vectorizer, models


# ======================================================================
# STEP 1 - SOURCE INPUT   (FR-02, FR-03, FR-04)
# ======================================================================
def source_input(text):
    """Check the email text. Returns (is_valid, message)."""
    if text is None or text.strip() == "":
        return False, "There is no email content to analyse. Please paste an email or upload a file."

    if len(text) > MAX_LENGTH:
        return False, f"The email is too long. Please keep it under {MAX_LENGTH} characters."

    if len(text.split()) < MIN_WORDS:
        return False, "The email is too short to analyse. Please paste the full email."

    return True, text.strip()   # valid: hand back the cleaned-up text


# ======================================================================
# STEP 2 - FILTERING   (FR-05 to FR-09)
# ======================================================================
def filtering(text, vectorizer, models):
    """Ask each of the three algorithms for its own result."""
    numbers = vectorizer.transform([text])

    # If none of the words are known to the model, we can't judge fairly
    # (SQA-15: never treat a missing result as a valid result).
    if numbers.nnz == 0:
        raise ValueError("The text has no words the detector recognises.")

    individual_results = {}
    for name, model in models.items():
        # predict_proba gives [chance_legit, chance_scam]; we want chance_scam
        chance_scam = model.predict_proba(numbers)[0][1]
        individual_results[name] = {
            "verdict": "Scam" if chance_scam > 0.5 else "Not scam",
            "chance_scam": chance_scam,   # kept internal, not shown to the user
        }
    return individual_results


# ======================================================================
# STEP 3 - ANALYSIS   (FR-10 to FR-13)
# ======================================================================
def analysis(individual_results, source_warnings=0):
    """Compare the three results -> overall classification + risk level.

    NOTE: the SRS does not say HOW to combine the results, so this is my
    simple choice for the demo (easy to change later - SQA-09):
        0 algorithms say scam  -> Legitimate
        1 or 2 say scam        -> Suspicious        (they disagree)
        all 3 say scam         -> Potentially Fraudulent
    The risk level uses the average 'chance of scam' of the three algorithms.

    NEW extra rule: scammers can write a normal-looking message from a fake
    address. So if the text looks fine but 2 or more warnings were found in the
    sender / links / attachments, 'Legitimate' is raised to 'Suspicious'.
    """
    votes_for_scam = sum(1 for r in individual_results.values() if r["verdict"] == "Scam")
    average_chance = sum(r["chance_scam"] for r in individual_results.values()) / len(individual_results)

    # Overall classification (FR-12)
    if votes_for_scam == 0:
        overall_classification = "Legitimate"
    elif votes_for_scam == len(individual_results):
        overall_classification = "Potentially Fraudulent"
    else:
        overall_classification = "Suspicious"

    # Risk level (FR-13)
    if average_chance < 0.35:
        risk_level = "Low"
    elif average_chance < 0.65:
        risk_level = "Medium"
    else:
        risk_level = "High"

    # The extra rule described above
    note = ""
    if overall_classification == "Legitimate" and source_warnings >= 2:
        overall_classification = "Suspicious"
        if risk_level == "Low":
            risk_level = "Medium"
        note = ("The message text looks normal, but the sender, links or attachments "
                "raised warnings, so the result was raised to Suspicious.")

    return {"overall_classification": overall_classification, "risk_level": risk_level, "note": note}


# ======================================================================
# STEP 4 - REPORT GENERATION   (FR-14, FR-15)
# ======================================================================

# Each warning sign has a name and a list of words/phrases that reveal it
WARNING_SIGNS = {
    "Creates urgency or pressure": [
        "urgent", "immediately", "act now", "final warning", "last chance",
        "expires", "within 24 hours", "right now", "today",
    ],
    "Promises prizes or easy money": [
        "lottery", "you have won", "winner", "prize", "get rich", "guaranteed",
        "double your money", "free gift", "inheritance",
    ],
    "Asks for private information": [
        "password", "otp", "pin", "credit card", "card number", "bank account",
        "bank details", "social security", "aadhaar", "passport number",
    ],
    "Asks for a payment or fee": [
        "processing fee", "registration fee", "customs fee", "wire transfer",
        "gift cards", "bitcoin", "deposit",
    ],
    "Threatens account suspension or legal trouble": [
        "suspended", "blocked", "locked", "disabled", "arrest", "legal action",
    ],
}


def find_risk_indicators(text):
    """Look for warning signs inside the email. Returns a list of sentences."""
    lower_text = text.lower()
    found = []

    # Check the word lists above. \b means "whole word only",
    # so 'pin' will not match inside 'shipping'.
    for sign_name, words in WARNING_SIGNS.items():
        for word in words:
            if re.search(r"\b" + re.escape(word) + r"\b", lower_text):
                found.append(sign_name)
                break   # one match is enough for this warning sign

    # Two simple checks that don't need word lists
    if "http" in lower_text or "www." in lower_text or "click here" in lower_text:
        found.append("Contains a link or asks you to click something")

    shouting_words = [w for w in re.findall(r"[A-Za-z]+", text) if w.isupper() and len(w) >= 4]
    if len(shouting_words) >= 2 or text.count("!") >= 3:
        found.append("Uses ALL-CAPS words or many exclamation marks")

    return found


GUIDANCE = {
    "Legitimate": "This email looks normal. Still, stay alert: never share passwords or OTPs "
                  "by email, and double-check the sender if anything feels off.",
    "Suspicious": "The detectors disagreed, so be careful. Do not click links or open attachments. "
                  "Contact the sender through an official website or phone number to confirm it is real.",
    "Potentially Fraudulent": "Do NOT click any links, open attachments, reply, or share personal or "
                              "bank details. Delete the email or report it as phishing.",
}


def generate_report(text, individual_results, analysis_result, source_info):
    """Pack everything into one neat report (a dictionary)."""
    classification = analysis_result["overall_classification"]
    return {
        "overall_classification": classification,
        "risk_level": analysis_result["risk_level"],
        "risk_indicators": find_risk_indicators(text),
        "guidance": GUIDANCE[classification],
        "note": analysis_result["note"],
        # For transparency we show each algorithm's verdict (but not its score)
        "algorithm_verdicts": {name: r["verdict"] for name, r in individual_results.items()},
        # NEW: the sender / links / attachments findings from source_checker.py
        "source_info": source_info,
    }


def report_as_text(report):
    """Turn the report into plain text, for the 'Download report' button."""
    lines = ["AI SCAM DETECTOR - REPORT", "=" * 40,
             f"Classification : {report['overall_classification']}",
             f"Risk level     : {report['risk_level']}"]
    if report["note"]:
        lines.append(f"Note           : {report['note']}")

    lines += ["", "Risk indicators:"]
    lines += [f"  - {item}" for item in report["risk_indicators"]] or ["  - none found"]

    sender = report["source_info"]["sender"]
    lines += ["", "Mail source:"]
    if sender["found"]:
        lines += [f"  Sender : {sender['name']} <{sender['address']}>",
                  f"  Domain : {sender['domain']} ({sender['domain_type']})",
                  f"  Origin IP : {sender['origin_ip'] or 'not available'}"]
        lines += [f"  WARNING: {w}" for w in sender["warnings"]]
    else:
        lines.append("  No sender information was found.")

    lines += ["", "Links:"]
    for link in report["source_info"]["links"]:
        lines.append(f"  - {link['url']}")
        lines += [f"      WARNING: {flag}" for flag in link["flags"]]
    if not report["source_info"]["links"]:
        lines.append("  none found")

    lines += ["", "Attachments:"]
    for item in report["source_info"]["attachments"]:
        lines.append(f"  - {item['name']}")
        lines += [f"      WARNING: {flag}" for flag in item["flags"]]
    if not report["source_info"]["attachments"]:
        lines.append("  none")

    lines += ["", "Algorithm verdicts:"]
    lines += [f"  - {name}: {verdict}" for name, verdict in report["algorithm_verdicts"].items()]
    lines += ["", "Guidance:", f"  {report['guidance']}", "",
              "This is an automated assessment, not a guarantee that an email is safe or fraudulent."]
    return "\n".join(lines)


# ======================================================================
# RUN THE WHOLE PIPELINE (this is what app.py calls)
# ======================================================================
def detect(parsed, vectorizer, models):
    """Runs Steps 1 to 4 in order and returns a dictionary with a 'status'.
    'parsed' comes from email_parser.py (pasted text OR uploaded file)."""

    # Step 1: Source Input
    is_valid, result = source_input(parsed["model_text"])
    if not is_valid:
        return {"status": "invalid", "message": result}

    # Step 2: Filtering (wrapped so that an error never crashes the program - SSR-01)
    try:
        individual_results = filtering(result, vectorizer, models)
    except ValueError as error:
        return {"status": "error", "message": str(error)}

    # NEW: check where the email came from (sender, links, attachments)
    source_info = check_source(parsed)

    # Step 3: Analysis
    analysis_result = analysis(individual_results, source_info["warning_count"])

    # Step 4: Report Generation
    report = generate_report(result, individual_results, analysis_result, source_info)
    return {"status": "ok", "report": report}


# ======================================================================
# QUICK TEST: run `python detector.py` in the terminal
# ======================================================================
if __name__ == "__main__":
    from email_parser import parse_email_text

    vectorizer, models = train_models()

    samples = [
        "URGENT! Your bank account is suspended. Verify your password and OTP immediately at www.secure-bank.xyz or lose access.",
        "Hi Anita, the project meeting is moved to Thursday at 2 pm. Please bring the updated report.",
    ]
    for sample in samples:
        report = detect(parse_email_text(sample), vectorizer, models)["report"]
        print("EMAIL         :", sample)
        print("CLASSIFICATION:", report["overall_classification"], "| RISK:", report["risk_level"])
        print("-" * 60)
