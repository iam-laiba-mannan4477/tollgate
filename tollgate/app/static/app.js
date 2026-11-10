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

  // ---- demo mode only: the code box and "Approve with demo code" ------------------------
  var box = document.getElementById("democode");
  var demo = box ? {
    seconds: parseInt(box.getAttribute("data-seconds"), 10) || STEP,
    code: box.getAttribute("data-code"),
    next: box.getAttribute("data-next"),
    used: box.getAttribute("data-used") === "true"
  } : null;
  var waiting = false;

  // 0 = still the step the page was made in, 1 = the next step, 2+ = page is stale.
  function stepOffset() {
    var gone = secondsGone();
    return gone < demo.seconds ? 0 : 1 + Math.floor((gone - demo.seconds) / STEP);
  }
  // A code that has not been used yet, null if we must wait, undefined if the page is stale.
  function freshCode() {
    var k = stepOffset();
    if (k === 0) { return demo.used ? null : demo.code; }
    if (k === 1) { return demo.next; }
    return undefined;
  }
  function showDemo() {
    var k = stepOffset();
    if (k >= 2) { if (!waiting) { location.reload(); } return; }
    var left = Math.max(0, Math.ceil(demo.seconds + STEP * k - secondsGone()));
    var codeEl = box.querySelector("[data-democode]");
    var leftEl = box.querySelector("[data-demo-left]");
    var bar = box.querySelector("[data-demobar]");
    var usedEl = box.querySelector("[data-demoused]");
    if (codeEl) { codeEl.textContent = k === 0 ? demo.code : demo.next; }
    if (leftEl) { leftEl.textContent = String(left); }
    if (bar) { bar.style.width = Math.round(left / STEP * 100) + "%"; }
    if (usedEl && k >= 1) { usedEl.hidden = true; }
  }
  function submitWith(form, code) {
    var field = form.querySelector("[data-demo-code-field]");
    if (field) { field.value = code; }
    form.submit();               // a normal form post: the server checks the code as usual
  }
  $$("form[data-demo-approve]").forEach(function (form) {
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      if (!demo || waiting) { return; }
      var button = form.querySelector("[data-demo-button]");
      var status = form.querySelector("[data-demo-status]");
      var code = freshCode();
      if (code === undefined) { location.reload(); return; }
      if (button) { button.disabled = true; }
      if (code) { submitWith(form, code); return; }
      // This step's code was already used: wait for the next one instead of sending it.
      waiting = true;
      var wait = setInterval(function () {
        var left = Math.max(0, Math.ceil(demo.seconds - secondsGone()));
        if (status) { status.textContent = "Code already used. Waiting " + left + " s for a fresh one..."; }
        if (stepOffset() >= 1) { clearInterval(wait); submitWith(form, demo.next); }
      }, 250);
    });
  });

  function tick() { showTimers(); if (demo) { showDemo(); } }
  tick();
  setInterval(tick, 1000);
})();
