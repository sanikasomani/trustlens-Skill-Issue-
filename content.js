/* Runs inside Gmail. Reads the opened email on this computer only, then shows a warning if it looks risky. */
(function () {
  let last = "";

  function read() {
    const body = document.querySelector("div.a3s.aiL") || document.querySelector("div.a3s");
    if (!body) return null;
    const s = document.querySelector("span.gD[email]");
    const sender = s ? (s.getAttribute("name") || "") + " <" + s.getAttribute("email") + ">" : "";
    const subject = (document.querySelector("h2.hP") || {}).innerText || "";
    const links = [...body.querySelectorAll("a[href]")].map(a => {
      try {
        const u = new URL(a.href);
        return u.hostname.endsWith("google.com") && u.pathname === "/url" ? (u.searchParams.get("q") || a.href) : a.href;
      } catch (e) { return ""; }
    }).filter(l => /^https?:/.test(l));
    return { sender, text: subject + "\n" + body.innerText + "\n" + links.join(" ") };
  }

  function check() {
    const m = read();
    if (!m) { TLPopup.hide(); last = ""; return; }
    const key = m.sender + "|" + m.text.length;
    if (key === last) return;
    last = key;
    const r = TrustLens.analyze(m.text, m.sender);
    if (r.tier === "LOW") TLPopup.hide(); else TLPopup.show(r);
  }

  let t;
  new MutationObserver(() => { clearTimeout(t); t = setTimeout(check, 700); })
    .observe(document.body, { childList: true, subtree: true });
})();
