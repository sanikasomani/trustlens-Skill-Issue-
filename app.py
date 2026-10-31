import html
import json
import re

import streamlit as st

from detector import DATASET_PATH, VERIFY_HINTS, WEIGHTS, analyze, reconsider

st.set_page_config(page_title="TrustLens", page_icon="🔍", layout="wide")

# ---------- Look and feel (system fonts only, so the app stays fully offline) ----------
CSS = """<style>
:root{--ink:#14213d;--muted:#5b6678;--paper:#ffffff;--line:#d5dbe4;--safe:#1b7f5c;--warn:#b86e00;--danger:#c4332d;--mark:#ffe45e}
html,body,[class*="css"],.stApp{font-family:"Segoe UI",system-ui,-apple-system,Roboto,sans-serif}
.block-container{padding-top:2rem;max-width:1180px}
#MainMenu,footer{visibility:hidden}
.tl-title{font-family:Georgia,"Times New Roman",serif;font-size:2.6rem;font-weight:700;color:var(--ink);letter-spacing:-.02em;line-height:1.1;margin:0}
.tl-title span{display:inline-block;width:.62em;height:.62em;border:.13em solid var(--ink);border-radius:50%;margin-right:.3em;position:relative;top:-.04em}
.tl-lede{font-size:1.08rem;color:var(--muted);margin:.5rem 0 .9rem;max-width:44rem}
.tl-facts{display:flex;flex-wrap:wrap;gap:6px 22px;margin-bottom:1.2rem;color:var(--ink);font-size:.92rem}
.tl-facts b{color:var(--safe);margin-right:6px}
.tl-h{font-family:Georgia,"Times New Roman",serif;font-size:1.25rem;font-weight:700;color:var(--ink);margin:0 0 .5rem}
.tl-verdict{background:var(--paper);border:1px solid var(--line);border-left:10px solid var(--c);border-radius:10px;padding:18px 22px;margin-bottom:16px;color:var(--ink)}
.tl-verdict.LOW{--c:var(--safe)}.tl-verdict.MEDIUM{--c:var(--warn)}.tl-verdict.HIGH{--c:var(--danger)}
.tl-vt{font-family:Georgia,"Times New Roman",serif;font-size:2.1rem;font-weight:700;color:var(--c);line-height:1.1}
.tl-vs{margin:6px 0 14px;font-size:1.02rem}
.tl-seg{display:flex;gap:6px;max-width:320px}
.tl-seg i{flex:1;height:9px;border-radius:5px;background:#e3e8ef}
.tl-seg i.on.LOW{background:var(--safe)}.tl-seg i.on.MEDIUM{background:var(--warn)}.tl-seg i.on.HIGH{background:var(--danger)}
.tl-score{margin-top:8px;font-size:.86rem;color:var(--muted)}
.tl-msg{background:var(--paper);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:16px;color:var(--ink);font-family:Consolas,"Courier New",monospace;font-size:.95rem;line-height:1.75;word-break:break-word}
.tl-msg mark{background:var(--mark);color:var(--ink);padding:1px 3px;border-radius:3px}
.tl-msg sup{color:var(--danger);font-weight:700;font-family:"Segoe UI",system-ui,sans-serif;font-size:.7rem;margin-left:2px}
.tl-ledger{background:var(--paper);border:1px solid var(--line);border-radius:10px;margin-bottom:16px;color:var(--ink)}
.tl-row{display:flex;gap:14px;padding:14px 18px;border-top:1px solid var(--line)}
.tl-row:first-child{border-top:none}
.tl-n{flex:0 0 26px;height:26px;border-radius:50%;background:var(--danger);color:#fff;text-align:center;line-height:26px;font-weight:700;font-size:.85rem}
.tl-name{font-weight:700}
.tl-w{font-weight:400;font-size:.82rem;color:var(--muted);margin-left:8px}
.tl-found{font-family:Consolas,"Courier New",monospace;font-size:.84rem;background:#fff6c2;border-radius:4px;padding:1px 6px;margin:2px 4px 0 0;display:inline-block;word-break:break-all}
.tl-chk{color:var(--muted);font-size:.9rem;margin-top:6px}
.tl-steps{background:var(--paper);border:1px solid var(--line);border-radius:10px;padding:6px 18px;margin-bottom:16px;color:var(--ink)}
.tl-step{display:flex;gap:14px;padding:10px 0;border-top:1px solid var(--line)}
.tl-step:first-child{border-top:none}
.tl-sn{flex:0 0 26px;height:26px;border-radius:50%;border:2px solid var(--ink);text-align:center;line-height:22px;font-weight:700;font-size:.85rem}
.tl-empty{background:var(--paper);border:1px dashed #aab4c3;border-radius:10px;padding:22px;color:var(--ink)}
.tl-empty p{margin:.3rem 0}
.tl-key{display:flex;gap:10px;align-items:baseline;margin:.35rem 0}
.tl-key b{min-width:96px}
.tl-report{font-size:.92rem;color:var(--muted);margin-top:4px}
.tl-bar{display:flex;align-items:center;gap:12px;margin:8px 0;color:var(--ink)}
.tl-bar span.l{width:90px;font-weight:600}
.tl-bar span.t{flex:1;background:#e3e8ef;border-radius:5px;height:14px;overflow:hidden}
.tl-bar span.t i{display:block;height:100%}
</style>"""
st.markdown(CSS, unsafe_allow_html=True)

TIER_TITLE = {"LOW": "Low risk", "MEDIUM": "Medium risk", "HIGH": "High risk"}
TIER_TEXT = {
    "LOW": "No strong warning signs found. Stay careful if it asks you to act on money or accounts.",
    "MEDIUM": "This looks suspicious. Check it through a trusted channel before you act.",
    "HIGH": "This is very likely a scam. Do not click, reply, or pay.",
}
TIER_COLOR = {"LOW": "#1b7f5c", "MEDIUM": "#b86e00", "HIGH": "#c4332d"}

DATA = {d["id"]: d for d in json.loads(DATASET_PATH.read_text(encoding="utf-8"))}
EXAMPLES = [("Hinglish scam", 1), ("Email scam", 6), ("Prize scam", 5),
            ("Kannada scam", 7), ("Real bank OTP", 11), ("Real email", 15)]


def esc(x):
    return html.escape(str(x))


# ---------- State ----------
for key, default in {"channel": "SMS", "sender": "", "text": "", "result": None,
                     "analyzed_text": "", "empty": False, "history": []}.items():
    st.session_state.setdefault(key, default)


def set_example(i):
    d = DATA[i]
    st.session_state.channel = "SMS" if d["channel"] == "sms" else "Email"
    st.session_state.sender = d["sender"]
    st.session_state.text = d["text"]
    st.session_state.result = None
    st.session_state.empty = False


def clear_all():
    st.session_state.sender = ""
    st.session_state.text = ""
    st.session_state.result = None
    st.session_state.empty = False


def run_analysis():
    text = st.session_state.text
    if not text.strip():
        st.session_state.result = None
        st.session_state.empty = True
        return
    r = analyze(text, st.session_state.sender, st.session_state.channel.lower())
    st.session_state.result = r
    st.session_state.analyzed_text = text
    st.session_state.empty = False
    st.session_state.verified = False
    st.session_state.history.append({"tier": r["tier"], "channel": st.session_state.channel, "score": r["score"]})


# ---------- HTML builders (text is always escaped; links are never clickable) ----------
def highlight(text, signals):
    owner = {}
    for n, s in enumerate(signals, 1):
        for e in s["evidence"]:
            k = (e or "").lower()
            if k and k in text.lower() and k not in owner:
                owner[k] = n
    if not owner:
        return esc(text).replace("\n", "<br>")
    pat = re.compile("|".join(re.escape(k) for k in sorted(owner, key=len, reverse=True)), re.I)
    out, last = [], 0
    for m in pat.finditer(text):
        out.append(esc(text[last:m.start()]))
        out.append(f"<mark>{esc(m.group(0))}<sup>{owner[m.group(0).lower()]}</sup></mark>")
        last = m.end()
    out.append(esc(text[last:]))
    return "".join(out).replace("\n", "<br>")


def verdict_html(tier, score, n):
    levels = ["LOW", "MEDIUM", "HIGH"]
    segs = "".join(f'<i class="{lv}{" on" if levels.index(lv) <= levels.index(tier) else ""}"></i>' for lv in levels)
    plural = "" if n == 1 else "s"
    return (f'<div class="tl-verdict {tier}"><div class="tl-vt">{TIER_TITLE[tier]}</div>'
            f'<div class="tl-vs">{TIER_TEXT[tier]}</div><div class="tl-seg">{segs}</div>'
            f'<div class="tl-score">Score {score} from {n} warning sign{plural}</div></div>')


def ledger_html(signals):
    rows = []
    for n, s in enumerate(signals, 1):
        found = "".join(f'<span class="tl-found">{esc(e)}</span>' for e in dict.fromkeys(s["evidence"]) if e)
        rows.append(
            f'<div class="tl-row"><div class="tl-n">{n}</div><div>'
            f'<div class="tl-name">{esc(s["name"])}<span class="tl-w">adds {WEIGHTS[s["name"]]} to the score</span></div>'
            f'<div>{esc(s["why"])}</div><div>{found}</div>'
            f'<div class="tl-chk">How to check: {esc(VERIFY_HINTS[s["name"]])}</div></div></div>')
    return f'<div class="tl-ledger">{"".join(rows)}</div>'


def steps_html(steps):
    rows = "".join(f'<div class="tl-step"><div class="tl-sn">{i}</div><div>{esc(s)}</div></div>'
                   for i, s in enumerate(steps, 1))
    return f'<div class="tl-steps">{rows}</div>'


# ---------- Header ----------
st.markdown(
    '<div class="tl-title"><span></span>TrustLens</div>'
    '<div class="tl-lede">Paste a suspicious SMS or email. TrustLens shows what looks wrong, '
    'quotes the exact words, and tells you how to check it safely.</div>'
    '<div class="tl-facts"><div><b>✓</b>Links are never opened</div>'
    '<div><b>✓</b>Runs on your computer, nothing is sent out</div>'
    '<div><b>✓</b>Nothing is saved after you close the app</div></div>',
    unsafe_allow_html=True,
)

tab_check, tab_session, tab_test, tab_how = st.tabs(
    ["Check a message", "This session", "Test on dataset", "How it works"])

# ---------- Tab 1: check ----------
with tab_check:
    left, right = st.columns([5, 6], gap="large")

    with left:
        st.markdown('<div class="tl-h">Message to check</div>', unsafe_allow_html=True)
        st.radio("Where did it arrive?", ["SMS", "Email"], horizontal=True, key="channel")
        st.text_input("Sender", key="sender",
                      placeholder="9876543210, VM-HDFCBK, or Name <mail@site.com>")
        st.text_area("Message", key="text", height=190, placeholder="Paste the message here")
        b1, b2, _ = st.columns([3, 2, 4])
        b1.button("Check this message", type="primary", on_click=run_analysis, key="go")
        b2.button("Clear", on_click=clear_all, key="clear")
        st.markdown('<div class="tl-h" style="margin-top:24px">Try an example</div>', unsafe_allow_html=True)
        grid = st.columns(3) + st.columns(3)
        for col, (label, i) in zip(grid, EXAMPLES):
            col.button(label, key=f"ex{i}", on_click=set_example, args=(i,))
        st.caption("Examples are invented. No real people, numbers or accounts.")

    with right:
        r = st.session_state.result
        if st.session_state.empty:
            st.warning("Paste a message first, then press Check this message.")
        if r is None:
            st.markdown(
                '<div class="tl-empty"><div class="tl-h">What you will see here</div>'
                '<p>The verdict, your message with the suspicious words marked, '
                'the reason for each mark, and what to do next.</p>'
                '<div class="tl-key"><b style="color:#1b7f5c">Low risk</b>No strong warning signs.</div>'
                '<div class="tl-key"><b style="color:#b86e00">Medium risk</b>Check before you act.</div>'
                '<div class="tl-key"><b style="color:#c4332d">High risk</b>Do not click, reply, or pay.</div></div>',
                unsafe_allow_html=True)
        else:
            sigs = r["signals"]
            st.markdown(verdict_html(r["tier"], r["score"], len(sigs)), unsafe_allow_html=True)

            st.markdown('<div class="tl-h">Your message, marked</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="tl-msg">{highlight(st.session_state.analyzed_text, sigs)}</div>',
                        unsafe_allow_html=True)

            if sigs:
                st.markdown('<div class="tl-h">Why it was flagged</div>', unsafe_allow_html=True)
                st.markdown(ledger_html(sigs), unsafe_allow_html=True)
            else:
                st.markdown('<div class="tl-h">Why it was flagged</div>', unsafe_allow_html=True)
                st.markdown('<div class="tl-ledger"><div class="tl-row">No warning signs were found in this message.</div></div>',
                            unsafe_allow_html=True)

            st.markdown('<div class="tl-h">What to do next</div>', unsafe_allow_html=True)
            st.markdown(steps_html(r["advice"]), unsafe_allow_html=True)

            with st.expander("I think this message is genuine"):
                st.write("Fair challenge. Each numbered reason above shows what raised the score. "
                         "If you can explain each one, confirm below that you checked the sender yourself.")
                verified = st.checkbox("I checked through the official app, the number on my card, or in person",
                                       key="verified")
                new_tier, note = reconsider(r, verified)
                st.markdown(verdict_html(new_tier, r["score"], len(sigs)), unsafe_allow_html=True)
                st.write(note)

            st.markdown('<div class="tl-report">Already clicked or paid? Call 1930 and report at cybercrime.gov.in.</div>',
                        unsafe_allow_html=True)

# ---------- Tab 2: session dashboard ----------
with tab_session:
    hist = st.session_state.history
    st.markdown('<div class="tl-h">Messages checked in this session</div>', unsafe_allow_html=True)
    if not hist:
        st.write("Nothing yet. Check a message and the totals will appear here.")
    else:
        total = len(hist)
        bars = ""
        for tier in ["HIGH", "MEDIUM", "LOW"]:
            n = sum(1 for h in hist if h["tier"] == tier)
            bars += (f'<div class="tl-bar"><span class="l">{TIER_TITLE[tier]}</span>'
                     f'<span class="t"><i style="width:{n / total * 100:.0f}%;background:{TIER_COLOR[tier]}"></i></span>'
                     f'<span>{n}</span></div>')
        st.markdown(f'<div class="tl-ledger" style="padding:14px 18px">{bars}</div>', unsafe_allow_html=True)
        c1, c2, c3 = st.columns(3)
        c1.metric("Checked", total)
        c2.metric("SMS", sum(1 for h in hist if h["channel"] == "SMS"))
        c3.metric("Email", sum(1 for h in hist if h["channel"] == "Email"))
        st.caption("Only counts are kept, never the message text. They disappear when you close the app.")

# ---------- Tab 3: dataset test ----------
with tab_test:
    st.markdown('<div class="tl-h">TrustLens against the invented dataset</div>', unsafe_allow_html=True)
    rows, correct, scams, caught, false_alarms = [], 0, 0, 0, 0
    for d in DATA.values():
        res = analyze(d["text"], d.get("sender", ""), d["channel"])
        flagged = res["tier"] != "LOW"
        is_scam = d["label"] == "phishing"
        ok = flagged == is_scam
        correct += ok
        scams += is_scam
        caught += flagged and is_scam
        false_alarms += flagged and not is_scam
        rows.append({"#": d["id"], "Channel": d["channel"], "Language": d["language"],
                     "Truth": d["label"], "TrustLens": res["tier"], "Right?": "yes" if ok else "no"})
    m1, m2, m3 = st.columns(3)
    m1.metric("Correct", f"{correct} of {len(DATA)}")
    m2.metric("Scams caught", f"{caught} of {scams}")
    m3.metric("False alarms", false_alarms)
    st.dataframe(rows, hide_index=True)
    st.caption("These messages were used to tune the rules, so treat this as a sanity check, not a promise of real-world accuracy.")

# ---------- Tab 4: how it works ----------
with tab_how:
    st.markdown('<div class="tl-h">How TrustLens decides</div>', unsafe_allow_html=True)
    st.markdown(
        "TrustLens reads only the **text** of a message. It looks for six kinds of warning sign, "
        "and each one adds points. The total gives the risk level.\n\n"
        "| Warning sign | Points | Example |\n|---|---|---|\n"
        "| Suspicious link | 3 | `bit.ly/...`, `sbi-kyc-update.xyz` |\n"
        "| Sender does not match the brand | 3 | A bank message from a personal number |\n"
        "| Asks for OTP, password, KYC or money | 3 | \"Share OTP to verify\" |\n"
        "| Pressure and urgency | 2 | \"block ho jayega\", \"within 2 hours\" |\n"
        "| Too-good-to-be-true prize | 2 | \"You won Rs 25,00,000\" |\n"
        "| Link to an unknown site | 1 | A link that is not an official domain |\n"
        "| Missing provenance | 1 | \"Dear customer\", or a CEO on a Gmail address |\n\n"
        "**0 to 2 points is low risk, 3 to 5 is medium, 6 or more is high.**\n\n"
        "A genuine line like \"Do not share your OTP with anyone\" is **not** counted as a request for an OTP."
    )
    st.markdown('<div class="tl-h" style="margin-top:18px">Safety and privacy</div>', unsafe_allow_html=True)
    st.markdown(
        "- Links are never opened, fetched or made clickable.\n"
        "- TrustLens never replies, sends, or acts for you.\n"
        "- No internet connection is used. Messages are not stored.\n"
        "- All example data is invented."
    )
    st.markdown('<div class="tl-h" style="margin-top:18px">Limits</div>', unsafe_allow_html=True)
    st.markdown(
        "TrustLens uses rules, so a scam written in words it does not know can be missed. "
        "Use the verdict as a second opinion, and always confirm through the official app or number."
    )
