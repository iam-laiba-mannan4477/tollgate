// Tollgate web app script. The only script on any page (strict CSP: no inline scripts,
// no network calls). Display helpers only: the server decides every approval and release.
(function () {
  "use strict";
  var STEP = 30;
  var loaded = Date.now();
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };
  var pad = function (n) { return (n < 10 ? "0" : "") + n; };
  var secondsGone = function () { return (Date.now() - loaded) / 1000; };

  // ---- countdowns: data-countdown="<seconds>", optional data-format="mmss" -------------
  var timers = $$("[data-countdown]").map(function (el) {
    return { el: el, start: parseInt(el.getAttribute("data-countdown"), 10) || 0,
             mmss: el.getAttribute("data-format") === "mmss" };
  });
  function showTimers() {
    var gone = Math.floor(secondsGone());
    timers.forEach(function (t) {
      var left = Math.max(0, t.start - gone);
      t.el.textContent = t.mmss ? pad(Math.floor(left / 60)) + ":" + pad(left % 60) : String(left);
    });
  }

  // ---- approve panels: <details> opens without JavaScript; Cancel closes it ----------------
  $$("[data-approve-panel]").forEach(function (panel) {
    var cancel = panel.querySelector("[data-panel-cancel]");
    if (cancel) {
      cancel.addEventListener("click", function (ev) { ev.preventDefault(); panel.open = false; });
    }
  });

  // ---- demo mode only: the code inside each approve panel -------------------------------
  // Each demo form carries this step's code and the next step's code (fake public demo
  // secret). If this step's code was already used, Confirm waits for the next fresh code
  // and then sends it. The server checks it exactly like a typed code.
  var forms = $$("form[data-demo-approve]").map(function (form) {
    return { form: form, field: form.querySelector("[data-demo-code-field]"), auto: true,
             seconds: parseInt(form.getAttribute("data-seconds"), 10) || STEP,
             code: form.getAttribute("data-code"), next: form.getAttribute("data-next"),
             used: form.getAttribute("data-used") === "true" };
  });
  var waiting = false;

  // 0 = still the step the page was made in, 1 = the next step, 2+ = page is stale.
  function stepOffset(d) {
    var gone = secondsGone();
    return gone < d.seconds ? 0 : 1 + Math.floor((gone - d.seconds) / STEP);
  }
  // A code not used yet, null if we must wait, undefined if the page is stale.
  function freshCode(d) {
    var k = stepOffset(d);
    if (k === 0) { return d.used ? null : d.code; }
    if (k === 1) { return d.next; }
    return undefined;
  }
  function closeAll() { $$("[data-approve-panel]").forEach(function (p) { p.open = false; }); }
  function send(d, code) {
    if (d.field) { d.field.value = code; }
    d.form.submit();             // a normal form post: the server checks the code as usual
    closeAll();
  }
  function showDemo() {
    forms.forEach(function (d) {
      if (!d.auto || !d.field || waiting) { return; }
      d.field.value = freshCode(d) || "";
      var used = d.form.querySelector("[data-demoused]");
      if (used && stepOffset(d) >= 1) { used.hidden = true; }
    });
  }
  forms.forEach(function (d) {
    if (d.field) { d.field.addEventListener("input", function () { d.auto = false; }); }
    d.form.addEventListener("submit", function (ev) {
      if (!d.auto) { closeAll(); return; }          // typed by hand: send as typed
      ev.preventDefault();
      if (waiting) { return; }
      var code = freshCode(d);
      if (code === undefined) { location.reload(); return; }
      var button = d.form.querySelector("[data-demo-button]");
      if (button) { button.disabled = true; }
      if (code) { send(d, code); return; }
      // This step's code was already used: wait for the next one instead of sending it.
      waiting = true;
      var status = d.form.querySelector("[data-demo-status]");
      var wait = setInterval(function () {
        var left = Math.max(0, Math.ceil(d.seconds - secondsGone()));
        if (status) { status.textContent = "Code already used. Waiting " + left + " s for a fresh one..."; }
        if (stepOffset(d) >= 1) { clearInterval(wait); send(d, d.next); }
      }, 250);
    });
  });

  function tick() { showTimers(); showDemo(); }
  tick();
  setInterval(tick, 1000);
})();

// ---- intro animation: once per tab session, skippable, never blocks the page ------------
// Skipped when: already seen in this tab (sessionStorage), prefers-reduced-motion, or the
// URL has ?nointro=1 (for tests and screen recordings). Any error -> it stays hidden.
(function () {
  "use strict";
  var KEY = "tollgate.introSeen";
  var PLAY_MS = 6300;
  var intro = document.getElementById("intro");
  if (!intro) { return; }
  function seen() { try { return window.sessionStorage.getItem(KEY) === "1"; } catch (e) { return true; } }
  function remember() { try { window.sessionStorage.setItem(KEY, "1"); } catch (e) { /* ignore */ } }
  function reducedMotion() {
    return !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  }
  function optedOut() { return /(?:^|[?&])nointro=1(?:&|$)/.test(window.location.search); }
  try {
    if (seen() || reducedMotion() || optedOut()) { remember(); return; }
    remember();
    var timer = null;
    var done = false;
    var end = function () {
      if (done) { return; }
      done = true;
      clearTimeout(timer);
      document.removeEventListener("keydown", onKey);
      intro.classList.add("out");
      setTimeout(function () { intro.hidden = true; intro.classList.remove("play", "out"); }, 850);
    };
    var onKey = function () { end(); };
    intro.hidden = false;
    void intro.offsetWidth;            // restart the CSS animation
    intro.classList.add("play");
    var skip = document.getElementById("skip");
    if (skip) { skip.addEventListener("click", end); skip.focus(); }
    document.addEventListener("keydown", onKey);
    timer = setTimeout(end, PLAY_MS);
  } catch (e) {
    intro.hidden = true;               // fail open: the page is always usable
  }
})();
