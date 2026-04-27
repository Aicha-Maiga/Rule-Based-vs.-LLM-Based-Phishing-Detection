"""
Aicha Maiga
CIS 602-01
Spring 2026
"""


import streamlit as st
import pandas as pd
import re
import requests
import json

# 1. CONFIG
st.set_page_config(page_title="Phishing Email Detection", layout="wide")

# API Key
API_KEY = st.secrets["GEMINI_KEY"]

# 2. Getting data from dataset
@st.cache_data
def load_my_data():
    try:
        return pd.read_csv("Phishing_Email_Cleaned.csv")
    except:
        st.error("The dataset is missing")
        return None

df = load_my_data()

# 3. Rules for the rule-based system(Heuristic Analysis)
def run_rule_analysis(text):
    text = str(text).lower()
    score = 0
    flags = []

    if re.search(r"http[s]?://|www\.", text):
        score += 25
        flags.append("Suspicious link detected")

    if re.search(r"\b(urgent|immediately|asap|verify|action required|act now|within 24 hours)\b", text):
        score += 20
        flags.append("Urgency or pressure language detected")

    if re.search(r"\b(password|login|bank|ssn|social security|credentials|account locked|credit card|confirm your details)\b", text):
        score += 30
        flags.append("Request for sensitive information")

    if re.search(r"\b(suspended|terminated|locked|penalty|legal action|unauthorized access|failure to respond)\b", text):
        score += 15
        flags.append("Threatening or consequence language")

    if re.search(r"!{2,}", text):
        score += 10
        flags.append("Excessive punctuation")

    if re.search(r"\b[a-z]{4,}\b.*[A-Z]{4,}\b", text):
        score += 10
        flags.append("Suspicious capitalization patterns")

    if re.search(r"\b(free|winner|prize|lottery|claim|reward|bonus|cash|million|inheritance)\b", text):
        score += 15
        flags.append("Financial lure or reward keywords")

    if re.search(r"\b(paypal|amazon|apple|microsoft|irs|fbi|bank of america|chase|wells fargo|google)\b", text):
        score += 20
        flags.append("Brand impersonation detected")

    score = min(score, 100)

    if score >= 50:
        verdict = "Phishing"
        risk = "🚨 High Risk"
    elif score >= 25:
        verdict = "Suspicious"
        risk = "⚠️ Medium Risk"
    else:
        verdict = "Safe"
        risk = "✅ Low Risk"

    return score, verdict, risk, flags

# 4. Gemini system
def run_ai_analysis(email_text):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={API_KEY}"    
    my_prompt = f"""
    You are a cybersecurity expert, helping a non-technical user.
    Analyze this email content for phishing risks: "{email_text[:1200]}"
    
    Please provide:
    1. A clear summary: Is it safe or a scam?
    2. The 'Why': Explain the psychological tricks or red flags.
    3. Action Plan: Provide ONE clear, non-technical instruction on exactly what the user should do right now.
    
    Use friendly, human language.
    """
    
    headers = {'Content-Type': 'application/json'}
    payload = {"contents": [{"parts": [{"text": my_prompt}]}]}
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        data = response.json()
        if "error" in data:
            return f"⚠️ Gemini API Error: {data['error']['message']}"

        if "candidates" not in data:
            return f"⚠️ No AI answer returned. Full response: {data}"

        return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        return f"⚠️ Real error: {type(e).__name__} - {e}"

# 5. SESSION STATE
if 'email' not in st.session_state:
    st.session_state.email = ""
if 'rb_ledger' not in st.session_state:
    st.session_state.rb_ledger = []
if 'llm_ledger' not in st.session_state:
    st.session_state.llm_ledger = []
if 'rb_quality' not in st.session_state:
    st.session_state.rb_quality = []
if 'llm_quality' not in st.session_state:
    st.session_state.llm_quality = []
if 'email_count' not in st.session_state:
    st.session_state.email_count = 0

# 6. UI
st.title("🛡️ Phishing Email Detector")
st.divider()

if df is not None:
    st.subheader("Step 1: Select an Email Sample")
    col_select, col_btn = st.columns([2, 1])
    with col_select:
        category = st.selectbox("Select Email Category:", ["Phishing Email", "Safe Email"])
    with col_btn:
        if st.button("Get Random Example"):
            sample = df[df["Email Type"] == category].sample(1)
            st.session_state.email = str(sample["Email Text"].values[0])[:2000]
            st.rerun()

user_input = st.text_area("Analyze Email Text:", value=st.session_state.email, height=200)

if st.button("Run Email Analysis", type="primary"):
    if user_input:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("🔍 Rule-Based Analysis")
            score, verdict, risk, flags = run_rule_analysis(user_input)
            st.metric("Risk Score", f"{score}/100")
            st.metric("Verdict", verdict)
            st.metric("Risk Level", risk)
            st.progress(score / 100)
            st.markdown("**Detected Indicators:**")
            if flags:
                for f in flags:
                    st.write(f"- {f}")
            else:
                st.write("- No phishing indicators detected")

        with col2:
            st.subheader("🧠 LLM Analysis (Gemini)")
            with st.spinner("Generating explanation..."):
                ai_result = run_ai_analysis(user_input)
                st.write(ai_result)
    else:
        st.warning("Please select a sample first.")

# 7. RESULTS TRACKER
st.divider()
st.header("📊 Results Tracker")
st.markdown(f"**Emails analyzed: {st.session_state.email_count} / 30**")
st.caption("""
TP = True Positive-Phishing correctly identified as Phishing
TN = True Negative- Safe correctly identified as Safe
FP = False Positive-Safe incorrectly flagged as Phishing
FN = False Negative-Phishing missed, classified as Safe or Suspicious
""")

col3, col4 = st.columns(2)

with col3:
    st.markdown("### 🔍 Rule-Based Accuracy")
    st.caption("Was the rule-based verdict correct for this email?")
    rb1, rb2, rb3, rb4 = st.columns(4)
    with rb1:
        if st.button("✅ TP", key="rb_tp"):
            st.session_state.rb_ledger.append("TP")
            st.session_state.email_count += 1
            st.rerun()
    with rb2:
        if st.button("✅ TN", key="rb_tn"):
            st.session_state.rb_ledger.append("TN")
            st.session_state.email_count += 1
            st.rerun()
    with rb3:
        if st.button("❌ FP", key="rb_fp"):
            st.session_state.rb_ledger.append("FP")
            st.session_state.email_count += 1
            st.rerun()
    with rb4:
        if st.button("❌ FN", key="rb_fn"):
            st.session_state.rb_ledger.append("FN")
            st.session_state.email_count += 1
            st.rerun()

with col4:
    st.markdown("### 🧠 LLM Accuracy")
    st.caption("Was the LLM verdict correct for this email?")
    llm1, llm2, llm3, llm4 = st.columns(4)
    with llm1:
        if st.button("✅ TP", key="llm_tp"):
            st.session_state.llm_ledger.append("TP")
            st.rerun()
    with llm2:
        if st.button("✅ TN", key="llm_tn"):
            st.session_state.llm_ledger.append("TN")
            st.rerun()
    with llm3:
        if st.button("❌ FP", key="llm_fp"):
            st.session_state.llm_ledger.append("FP")
            st.rerun()
    with llm4:
        if st.button("❌ FN", key="llm_fn"):
            st.session_state.llm_ledger.append("FN")
            st.rerun()

# OUTPUT QUALITY
st.divider()
st.markdown("### Rate Output Quality")
st.caption("Rate how useful each system output is for a non-technical user deciding what to do with this email")

q1, q2 = st.columns(2)
with q1:
    rb_q = st.radio(
        "Rule-Based Output Quality",
        [1, 2, 3],
        format_func=lambda x: {
            1: "1 — No useful explanation",
            2: "2 — Partial explanation",
            3: "3 — Clear and actionable"
        }[x],
        horizontal=True,
        key="rb_q"
    )
with q2:
    llm_q = st.radio(
        "LLM Output Quality",
        [1, 2, 3],
        format_func=lambda x: {
            1: "1 — No useful explanation",
            2: "2 — Partial explanation",
            3: "3 — Clear and actionable"
        }[x],
        horizontal=True,
        key="llm_q"
    )

if st.button("Save Quality Scores", use_container_width=True):
    st.session_state.rb_quality.append(rb_q)
    st.session_state.llm_quality.append(llm_q)
    st.success(f"Saved. Total quality ratings: {len(st.session_state.rb_quality)} / 30")

# LIVE DASHBOARD
st.divider()
st.header("📈 Live Results Dashboard")

if st.session_state.rb_ledger or st.session_state.llm_ledger:
    d1, d2 = st.columns(2)

    with d1:
        st.markdown("**🔍 Rule-Based System**")
        if st.session_state.rb_ledger:
            rb_tp = st.session_state.rb_ledger.count("TP")
            rb_tn = st.session_state.rb_ledger.count("TN")
            rb_fp = st.session_state.rb_ledger.count("FP")
            rb_fn = st.session_state.rb_ledger.count("FN")
            rb_total = len(st.session_state.rb_ledger)
            rb_acc = (rb_tp + rb_tn) / rb_total if rb_total > 0 else 0
            rb_prec = rb_tp / (rb_tp + rb_fp) if (rb_tp + rb_fp) > 0 else 0
            rb_rec = rb_tp / (rb_tp + rb_fn) if (rb_tp + rb_fn) > 0 else 0

            m1, m2, m3 = st.columns(3)
            with m1:
                st.metric("Accuracy", f"{rb_acc:.1%}")
            with m2:
                st.metric("Precision", f"{rb_prec:.1%}")
            with m3:
                st.metric("Recall", f"{rb_rec:.1%}")

            st.table(pd.DataFrame({
                "Predicted Phishing": [rb_tp, rb_fp],
                "Predicted Safe": [rb_fn, rb_tn]
            }, index=["Actual Phishing", "Actual Safe"]))

        if st.session_state.rb_quality:
            avg_rb = sum(st.session_state.rb_quality) / len(st.session_state.rb_quality)
            st.metric("Avg Output Quality", f"{avg_rb:.1f} / 3")

    with d2:
        st.markdown("**🧠 LLM-Based System**")
        if st.session_state.llm_ledger:
            llm_tp = st.session_state.llm_ledger.count("TP")
            llm_tn = st.session_state.llm_ledger.count("TN")
            llm_fp = st.session_state.llm_ledger.count("FP")
            llm_fn = st.session_state.llm_ledger.count("FN")
            llm_total = len(st.session_state.llm_ledger)
            llm_acc = (llm_tp + llm_tn) / llm_total if llm_total > 0 else 0
            llm_prec = llm_tp / (llm_tp + llm_fp) if (llm_tp + llm_fp) > 0 else 0
            llm_rec = llm_tp / (llm_tp + llm_fn) if (llm_tp + llm_fn) > 0 else 0

            m4, m5, m6 = st.columns(3)
            with m4:
                st.metric("Accuracy", f"{llm_acc:.1%}")
            with m5:
                st.metric("Precision", f"{llm_prec:.1%}")
            with m6:
                st.metric("Recall", f"{llm_rec:.1%}")

            st.table(pd.DataFrame({
                "Predicted Phishing": [llm_tp, llm_fp],
                "Predicted Safe": [llm_fn, llm_tn]
            }, index=["Actual Phishing", "Actual Safe"]))

        if st.session_state.llm_quality:
            avg_llm = sum(st.session_state.llm_quality) / len(st.session_state.llm_quality)
            st.metric("Avg Output Quality", f"{avg_llm:.1f} / 3")

    if st.button("Reset All Data"):
        st.session_state.rb_ledger = []
        st.session_state.llm_ledger = []
        st.session_state.rb_quality = []
        st.session_state.llm_quality = []
        st.session_state.email_count = 0
        st.rerun()

else:
    st.info("No results recorded yet. Analyze emails and record results above.")

# 8. HOW IT WORKS
with st.expander("How the Rule-Based Detection Works"):
    st.markdown("""
This engine uses **Heuristic Analysis** via Regular Expressions.
It is deterministic — it looks for fixed signatures of phishing like specific brand names or urgency keywords.

| Rule | Indicator | Weight |
|------|-----------|--------|
| 1 | Suspicious URLs | +25 |
| 2 | Urgency / Pressure language | +20 |
| 3 | Sensitive information requests | +30 |
| 4 | Threatening language | +15 |
| 5 | Excessive punctuation | +10 |
| 6 | Suspicious capitalization | +10 |
| 7 | Financial lure keywords | +15 |
| 8 | Brand impersonation | +20 |

**Thresholds:** Score ≥ 50 → Phishing | Score 25–49 → Suspicious | Score < 25 → Safe
""")

st.caption("Research Prototype — Rule-Based vs LLM Phishing Email Detection | Graduate Research Project")