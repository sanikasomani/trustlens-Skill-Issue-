/* TrustLens popup. Only shows a warning. It never clicks, replies, or changes anything. */
(function (g) {
  const C = { LOW: "#1b7f5c", MEDIUM: "#b86e00", HIGH: "#c4332d" };
  const T = { LOW: "Low risk", MEDIUM: "Medium risk", HIGH: "High risk" };
  const S = {
    LOW: "No strong warning signs found. Stay careful if it asks you to act on money or accounts.",
    MEDIUM: "This looks suspicious. Check it through a trusted channel before you act.",
    HIGH: "This is very likely a scam. Do not click, reply, or pay."
  };
  const e = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function hide() { const h = document.getElementById("trustlens-host"); if (h) h.remove(); }

  function show(r) {
    hide();
    const host = document.createElement("div");
    host.id = "trustlens-host";
    const root = host.attachShadow({ mode: "open" });
    const reasons = r.signals.map((s, i) =>
      `<li><b>${i + 1}. ${e(s.name)}</b><div>${e(s.why)}</div>` +
      `<div>${s.evidence.map(x => `<code>${e(x)}</code>`).join("")}</div></li>`).join("");
    const steps = r.advice.map(a => `<li>${e(a)}</li>`).join("");
    root.innerHTML = `<style>
      .card{position:fixed;top:16px;right:16px;width:380px;max-width:calc(100vw - 32px);max-height:calc(100vh - 32px);overflow:auto;
        z-index:2147483647;background:#fff;color:#14213d;border:1px solid #d5dbe4;border-left:10px solid ${C[r.tier]};
        border-radius:10px;padding:16px 18px;font:14px/1.5 "Segoe UI",system-ui,sans-serif;box-shadow:0 6px 24px rgba(20,33,61,.22)}
      .top{display:flex;justify-content:space-between;align-items:center;font-size:12px;color:#5b6678}
      h2{font:700 24px Georgia,serif;margin:4px 0;color:${C[r.tier]}}
      p{margin:4px 0 10px} ul,ol{margin:6px 0 10px;padding-left:20px} li{margin:8px 0}
      code{display:inline-block;font:12px Consolas,monospace;background:#fff6c2;border-radius:4px;padding:1px 6px;margin:3px 4px 0 0;word-break:break-all}
      h3{font:700 15px Georgia,serif;margin:12px 0 2px}
      button{font:600 13px inherit;background:#14213d;color:#fff;border:0;border-radius:6px;padding:7px 14px;cursor:pointer}
      button:focus-visible{outline:3px solid #ffe45e}
    </style>
    <div class="card" role="alertdialog" aria-label="TrustLens warning">
      <div class="top"><span>TrustLens checked this message on your device</span><button id="x">Close</button></div>
      <h2>${T[r.tier]}</h2><p>${S[r.tier]}</p>
      ${reasons ? `<h3>Why it was flagged</h3><ul>${reasons}</ul>` : ""}
      ${steps ? `<h3>What to do next</h3><ol>${steps}</ol>` : ""}
    </div>`;
    document.documentElement.appendChild(host);
    root.getElementById("x").onclick = hide;
    root.getElementById("x").focus();
  }
  document.addEventListener("keydown", ev => { if (ev.key === "Escape") hide(); });
  g.TLPopup = { show, hide };
})(window);
