# 🛡️ TrustLens

**Track:** Catch the Impersonation (phishing / social engineering / identity trust)
**Problem Statement 03**

TrustLens is a privacy-conscious defensive assistant. You paste a suspicious SMS or email, and it tells you **how risky it is, exactly why, and how to verify it safely**. It never opens links, sends replies, or takes any action on your behalf.

## The problem

Phishing now mixes convincing wording, impersonation, shortened or confusing links, and multiple channels. Static keyword filters misclassify genuine messages and never explain their warnings. Indian users also face multilingual, code-mixed messages (for example Hinglish).

## What TrustLens does

- Analyzes **SMS and email** messages
- Handles **English, Hinglish, Hindi and Kannada** wording
- Detects these signals, each shown with the exact text that triggered it:
  - **Suspicious links:** shortened links, raw IP addresses, look-alike brand domains, high-abuse domain endings
  - **Sender / domain inconsistency:** for example a bank message from a personal phone number or a Gmail address
  - **Credential or money requests:** asking you to share an OTP, PIN, password or KYC, or to pay a fee or buy gift cards
  - **Suspicious urgency:** "block ho jayega", "within 2 hours", "immediately"
  - **Too-good-to-be-true lures:** unexpected prizes and rewards
  - **Missing provenance:** generic greetings, or a job title on a free email address
- Gives a **risk tier** (LOW / MEDIUM / HIGH) with **highlighted evidence**
- Recommends **safe verification steps** (use the official app, the number on your card, or type the website yourself)
- Lets the user **challenge a result** ("I think this is legit"). The tier drops by one step only if the user confirms they verified through a trusted channel, and stays cautious if credentials or money are requested
- Avoids false alarms: a genuine "Do not share your OTP" message is not treated as a request for an OTP

## Safety and privacy by design

- **No automatic actions.** Links are never opened, fetched or made clickable. Messages are only analyzed as text.
- **Fully offline.** No network calls and no third-party APIs. Messages are not stored or sent anywhere.
- **Synthetic data only.** The dataset contains invented messages. No real people, numbers or accounts.

## How to run

Requires Python 3.9 or newer.

```
pip install -r requirements.txt
python detector.py      # runs the built-in test on the dataset
streamlit run app.py    # starts the web app
```

## Project files

| File | Purpose |
|---|---|
| `detector.py` | Rule-based signal extraction, scoring and risk tiers |
| `app.py` | Streamlit web interface |
| `dataset.json` | Synthetic benign and phishing messages (SMS and email, four languages) |
| `requirements.txt` | Python dependency (Streamlit) |
| `trustlens-popup/` | Chrome extension and demo inbox that show the warning popup |

## How scoring works

Each signal has a weight (link 3, sender mismatch 3, credential/money request 3, urgency 2, lure 2, unrecognised link 1, missing provenance 1). The total gives the tier: **0-2 LOW, 3-5 MEDIUM, 6+ HIGH**. Because the rules are simple, every verdict can be explained.

## Popup warning for Gmail (browser extension)

The `trustlens-popup` folder is a Chrome extension. When you open an email in Gmail, it checks the sender and text **on your computer** and shows a popup with the reasons and safe steps if the email looks risky. It never clicks, replies, or changes anything.

- **Demo inbox (no install):** double-click `trustlens-popup/inbox.html` and open any invented SMS or email.
- **Gmail:** open `chrome://extensions`, turn on Developer mode, click **Load unpacked**, and choose the `trustlens-popup` folder. Full steps are in `trustlens-popup/HOW_TO.txt`.
- SMS on a real phone would need a mobile app. The demo inbox shows the same warning for SMS.

## Limitations (honest notes)

- The detector is **rule-based**, so scams that use wording or domains it doesn't know can be missed. Accuracy on the small included dataset was tuned alongside the rules, so it is a sanity check, not a measure of real-world performance.
- The brand allowlist is a small demo list and should be verified and expanded before real use.
- Language coverage is limited to a set of common words and phrases.

## Future work

- Optional LLM layer to explain findings in plain language (rule-based verdict stays the source of truth)
- Suspicious QR code content checks
- Synthetic voice / deepfake flagging
- More Indian languages and a larger tested dataset
- Reporting dashboard and one-tap links to the 1930 helpline and cybercrime.gov.in

## Team
Team name: SKILL ISSUES

Sanika Somani

Sharanya Sindgi

Satyam Gusain

Sharan Desai
