/* TrustLens detector (JavaScript port). Reads text only. Never opens links or sends anything. */
(function (g) {
  const B = {
    "HDFC Bank": { a: ["hdfc"], d: ["hdfcbank.com"], s: ["HDFC"] },
    "SBI": { a: ["sbi", "yono"], d: ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"], s: ["SBI"] },
    "ICICI Bank": { a: ["icici"], d: ["icicibank.com"], s: ["ICICI"] },
    "Amazon": { a: ["amazon"], d: ["amazon.in", "amazon.com"], s: ["AMZN", "AMAZON"] },
    "Flipkart": { a: ["flipkart"], d: ["flipkart.com"], s: ["FLIPKT", "FLPKRT"] },
    "Paytm": { a: ["paytm", "पेटीएम"], d: ["paytm.com"], s: ["PAYTM"] },
    "India Post": { a: ["india post", "indiapost"], d: ["indiapost.gov.in"], s: ["INDPST", "INDPOST"] },
    "Income Tax Dept": { a: ["income tax", "incometax"], d: ["incometax.gov.in"], s: ["INCTAX", "ITDEPT"] }
  };
  const FREE = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com"];
  const SHORT = ["bit.ly", "tinyurl.com", "cutt.ly", "t.co", "goo.gl", "rb.gy", "is.gd"];
  const BADTLD = ["xyz", "top", "click", "icu", "buzz", "live", "rest", "cfd", "sbs", "support"];
  const W = { "Suspicious link": 3, "Sender / domain inconsistency": 3, "Asks for credentials or money": 3,
    "Suspicious urgency": 2, "Too-good-to-be-true lure": 2, "Unrecognised link": 1, "Missing provenance": 1 };
  const URL_RE = /(?:https?:\/\/|www\.)[^\s<>"']+|\b(?:bit\.ly|tinyurl\.com|cutt\.ly|t\.co|goo\.gl|rb\.gy|is\.gd)\/[^\s<>"']+/gi;
  const URG = new RegExp("\\b(?:urgent(?:ly)?|immediately|right away|act now|last warning|final notice|within \\d+ ?(?:hours?|hrs?|minutes?|mins?)|expires? (?:today|tonight)|turant|abhi|jaldi|\\d+ ghante(?: me| mein)?|block ho jayega|band ho jayega|account (?:will be |is |has been )?(?:blocked|suspended|closed|disconnected)|(?:blocked|suspended|disconnected) (?:tonight|today))\\b|तुरंत|ब्लॉक|ತಕ್ಷಣ|ಬ್ಲಾಕ್", "gi");
  const CRED = /\b(?:otp|password|passcode|pin|cvv|aadhaar|aadhar|pan|kyc|card number|net ?banking|upi pin)\b|ओटीपी|ಒಟಿಪಿ|पासवर्ड/gi;
  const VB = "\\b(?:share|send|submit|provide|give|reply|verify|confirm|update|click|karein|kariye|kijiye|bhejo|bhejein|bheje|bhejiye|batao|batayein|bataiye|dijiye|dalein|daalein)\\b|भेजें|बताएं|कीजिए|ಕಳುಹಿಸಿ|ಕ್ಲಿಕ್";
  const WARN = /do not share|don'?t share|never share|never ask|will never ask|not share|share na|kisi ko na|कभी नहीं|do not disclose/i;
  const MONEY = /\b(?:processing|registration|customs|clearance|redelivery|delivery|release) (?:fee|charges?)\b|\bgift ?cards?\b|\bsend (?:me )?(?:money|rs\.? ?\d[\d,]*|₹ ?\d[\d,]*)|\btransfer (?:rs\.? ?\d[\d,]*|₹ ?\d[\d,]*|the amount|money)|\bpay (?:rs\.? ?\d[\d,]*|₹ ?\d[\d,]*)/gi;
  const LURE = /\b(?:you(?:'ve| have)? won|congratulations|lucky draw|lottery|claim your (?:prize|reward|gift)|claim (?:now|prize))\b/gi;
  const GREET = /\bdear (?:customer|user|valued customer|account holder|sir\/madam|taxpayer|beneficiary)\b|प्रिय ग्राहक|ಪ್ರಿಯ ಗ್ರಾಹಕ/i;
  const rx = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const off = (h, d) => h === d || h.endsWith("." + d);
  const all = (re, t) => [...t.matchAll(re)].map(m => m[0]);
  const host = u => { try { return new URL(u.includes("://") ? u : "http://" + u).hostname.toLowerCase(); } catch (e) { return ""; } };

  function analyze(text, sender) {
    text = text || ""; sender = (sender || "").trim();
    const urls = (text.match(URL_RE) || []).map(u => u.replace(/[.,;:!?)»]+$/, ""));
    let dom = "", disp = sender;
    const am = sender.match(/<([^>]+)>/) || sender.match(/([^\s<>]+@[^\s<>]+)/);
    if (am) { dom = am[1].split("@").pop().toLowerCase(); disp = sender.replace(am[0], "").trim(); }
    const hay = (text + " " + sender).toLowerCase();
    const brands = Object.keys(B).filter(n => B[n].a.some(a => new RegExp("(^|[^a-z0-9])" + rx(a) + "($|[^a-z0-9])").test(hay)));
    const sig = [];
    const add = (name, why, ev) => sig.push({ name, why, evidence: [...new Set(ev.filter(Boolean))] });

    // 1. suspicious links (text analysis only)
    const lev = [], lw = [];
    urls.forEach(u => {
      const h = host(u), i = [];
      if (SHORT.includes(h)) i.push("shortened link hides the real destination");
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) i.push("raw IP address instead of a domain");
      if (h.includes("xn--")) i.push("look-alike characters in domain");
      if (BADTLD.includes(h.split(".").pop())) i.push("high-abuse domain ending");
      if ((h.match(/-/g) || []).length >= 2) i.push("several hyphens in domain");
      const leet = h.replace(/0/g, "o").replace(/3/g, "e").replace(/5/g, "s");
      for (const n in B) {
        if (B[n].d.some(d => off(h, d))) continue;
        if (B[n].a.some(a => /^[\x00-\x7f]+$/.test(a) && leet.includes(a.replace(/ /g, "")))) { i.push("imitates " + n + " but is not its real domain"); break; }
      }
      if (i.length && /^http:\/\//i.test(u)) i.push("not even HTTPS");
      if (i.length) { lev.push(u); lw.push(u + ": " + i.join("; ")); }
    });
    if (lev.length) add("Suspicious link", lw.join(" | "), lev);
    const unk = urls.filter(u => !lev.includes(u) && !Object.values(B).some(b => b.d.some(d => off(host(u), d))));
    if (unk.length) add("Unrecognised link", "link goes to a site that is not a known official domain", unk);

    // 2. credential / money requests
    const cev = [], cw = [], VERB = new RegExp(VB + (urls.length ? "|\\benter\\b" : ""), "i");
    text.split(/(?<=[.!?।])\s+|\n+/).forEach(s => {
      const t = all(CRED, s);
      if (!t.length || WARN.test(s)) return;
      const v = s.match(VERB);
      if (v) { cev.push(...t); cw.push('asks you to "' + v[0] + '" ' + t.join(", ")); }
    });
    const mev = all(MONEY, text);
    if (cev.length || mev.length) add("Asks for credentials or money", cw.concat(mev.length ? ["mentions a payment demand: " + mev.join(", ")] : []).join("; "), cev.concat(mev));

    // 3. sender / domain inconsistency
    if (brands.length) {
      const ask = urls.length || cev.length || mev.length;
      let bad = "";
      if (dom) {
        if (!brands.some(n => B[n].d.some(d => off(dom, d)))) bad = "sender domain '" + dom + "' is not an official " + brands.join(" / ") + " domain";
      } else {
        const h = sender.match(/^[A-Za-z]{2}-([A-Za-z0-9]{3,8})$/);
        if (h) { if (!brands.some(n => B[n].s.some(i => h[1].toUpperCase().includes(i)))) bad = "SMS sender ID '" + sender + "' does not match " + brands.join(" / "); }
        else if (/^\+?[\d\s-]{8,15}$/.test(sender)) bad = "claims to be " + brands.join(" / ") + " but came from a personal phone number";
      }
      const bd = brands.some(n => B[n].a.some(a => disp.toLowerCase().includes(a)));
      const ev = [], w = [];
      if (bad && (ask || bd)) { ev.push(sender); w.push(bad); }
      urls.forEach(u => {
        const h = host(u);
        if (!brands.some(n => B[n].d.some(d => off(h, d)))) { ev.push(u); w.push("link goes to '" + h + "', not an official " + brands.join(" / ") + " site"); }
      });
      if (ev.length) add("Sender / domain inconsistency", w.join(" | "), ev);
    }

    // 4. urgency, 5. lure, 6. provenance
    const urg = all(URG, text); if (urg.length) add("Suspicious urgency", "pressure language pushes you to act before verifying", urg);
    const lure = all(LURE, text); if (lure.length) add("Too-good-to-be-true lure", "unexpected prize or reward language", lure);
    const pe = [], pw = [], gm = text.match(GREET);
    if (gm) { pe.push(gm[0]); pw.push("generic greeting instead of your real name"); }
    if (FREE.includes(dom) && /\b(?:ceo|md|director|manager|hr|finance|accounts|boss)\b/i.test(disp)) { pe.push(disp); pw.push("job title shown on a free email address"); }
    if (!sender) pw.push("no sender information, so the origin can't be verified");
    if (pw.length) add("Missing provenance", pw.join("; "), pe);

    const score = sig.reduce((n, s) => n + W[s.name], 0);
    const tier = score >= 6 ? "HIGH" : score >= 3 ? "MEDIUM" : "LOW";
    const advice = [];
    if (tier !== "LOW") {
      advice.push("Do not click links, call numbers in the message, or reply.");
      advice.push(brands.length ? "Contact " + brands.join(" / ") + " through the official app, the number on your card, or by typing the website yourself." : "Verify with the sender using a number or app you already have, not details from this message.");
      if (cev.length || mev.length) advice.push("Never share OTP, PIN, CVV or passwords through a message or link.");
      if (tier === "HIGH") advice.push("Already clicked or paid? Call 1930 and report at cybercrime.gov.in.");
    }
    return { tier, score, signals: sig, advice };
  }
  g.TrustLens = { analyze };
})(typeof window !== "undefined" ? window : globalThis);
