// "How to use this page" guide. Presentation only; never changes anything on the server.
// The Guide button is a native <details> (#guide): with no script it still opens the full
// guide (what is this app, tips, glossary, tasks). This script adds:
//  - the page tour: one note card at a time next to the real part of the page, with
//    "Step N of M", Back, Next, Close and Skip (Escape closes); the last card says what to do
//    next, with a link;
//  - a "What is this app?" card before the tour on the first visit in this tab session;
//  - opening the tour once by itself on the first visit to each page in this tab session;
//  - remembering ticked "Try it yourself" tasks in this tab session.
// Storage is sessionStorage in try/catch. Any error: the page and the plain guide still work.
// Card position: fully inside the window and never over the thing it describes (below,
// above, right or left of it), else a strip along the bottom with the target scrolled above.
(function () {
  "use strict";

  // Pure placement rule (also used by tests/guide_harness.js).
  function choose(r, w, h, vw, vh, pad) {
    pad = pad || 12;
    if (w > vw - 2 * pad || h > vh - 2 * pad) { return null; }
    var clampX = function (x) { return Math.min(Math.max(pad, x), vw - w - pad); };
    var clampY = function (y) { return Math.min(Math.max(pad, y), vh - h - pad); };
    var spots = [
      { top: r.bottom + pad, left: clampX(r.left) },          // below
      { top: r.top - h - pad, left: clampX(r.left) },         // above
      { top: clampY(r.top), left: r.right + pad },            // right
      { top: clampY(r.top), left: r.left - w - pad }          // left
    ];
    for (var i = 0; i < spots.length; i++) {
      var s = spots[i];
      var inside = s.left >= pad && s.top >= pad && s.left + w <= vw - pad && s.top + h <= vh - pad;
      var covers = !(s.left >= r.right || s.left + w <= r.left || s.top >= r.bottom || s.top + h <= r.top);
      if (inside && !covers) { return { top: Math.round(s.top), left: Math.round(s.left) }; }
    }
    return null;
  }
  try { window.TollgateGuidePlace = choose; } catch (e) { /* ignore */ }

  try {
    var guide = document.getElementById("guide");
    var card = document.getElementById("guide-card");
    if (!guide || !card) { return; }
    var summary = guide.querySelector("summary");
    var tips = Array.prototype.slice.call(guide.querySelectorAll("li[data-guide-target]"));
    if (!summary || !tips.length) { return; }
    var countEl = card.querySelector("#guide-count");
    var textEl = card.querySelector("#guide-text");
    var go = card.querySelector("#guide-go");
    var back = card.querySelector("[data-guide-back]");
    var next = card.querySelector("[data-guide-next]");
    var tourBtn = guide.querySelector("[data-guide-tour]");
    var whatEl = guide.querySelector("[data-guide-what]");
    var page = guide.getAttribute("data-guide-page") || "page";
    var mode = guide.getAttribute("data-guide-mode") || "demo";
    var PAGE_KEY = "tollgate.guideSeen." + page;
    var WHAT_KEY = "tollgate.whatSeen";
    var TASK_KEY = "tollgate.tasks." + mode;
    var reduced = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
    var steps = [];
    var index = 0;
    var lit = null;

    function get(k) { try { return window.sessionStorage.getItem(k); } catch (e) { return "1"; } }
    function put(k, v) { try { window.sessionStorage.setItem(k, v); } catch (e) { /* ignore */ } }

    function pageSteps() {
      return tips.map(function (li) {
        var link = li.getAttribute("data-guide-link");
        var label = li.getAttribute("data-guide-link-text");
        var text = li.firstChild && li.firstChild.nodeType === 3 && link ? li.firstChild.nodeValue : li.textContent;
        return { sel: li.getAttribute("data-guide-target"), text: String(text).trim(),
                 link: link, label: label };
      });
    }
    function target(sel) {
      if (!sel) { return null; }
      try { return document.querySelector(sel); } catch (e) { return null; }
    }
    function unlight() { if (lit) { lit.classList.remove("guide-lit"); lit = null; } }

    function place(el) {
      card.classList.remove("guide-floating", "guide-strip");
      card.style.top = ""; card.style.left = "";
      var vw = window.innerWidth, vh = window.innerHeight;
      if (el) {
        try { el.scrollIntoView({ block: "center", behavior: "auto" }); } catch (e) { /* ignore */ }
        var spot = choose(el.getBoundingClientRect(), card.offsetWidth, card.offsetHeight, vw, vh, 12);
        if (spot) {
          card.classList.add("guide-floating");
          card.style.top = spot.top + "px";                 // CSSOM, not a style attribute in markup
          card.style.left = spot.left + "px";
          return;
        }
      }
      card.classList.add("guide-strip");                     // bottom strip (CSS)
      if (el) {
        var r = el.getBoundingClientRect();
        var room = vh - card.offsetHeight - 12;
        if (r.bottom > room) {
          try { window.scrollBy(0, Math.min(r.top - 12, r.bottom - room)); } catch (e) { /* ignore */ }
        }
      }
    }
    function show(i) {
      index = Math.max(0, Math.min(i, steps.length - 1));
      var s = steps[index];
      unlight();
      var el = target(s.sel);
      if (el) { el.classList.add("guide-lit"); lit = el; }
      var off = steps[0].welcome ? 1 : 0;                    // the welcome card is not a step
      countEl.textContent = s.welcome ? "Welcome" : "Step " + (index + 1 - off) + " of " + (steps.length - off);
      textEl.textContent = s.text;
      if (s.link) { go.href = s.link; go.textContent = s.label || "Go"; go.hidden = false; }
      else { go.hidden = true; }
      back.disabled = index === 0;
      next.textContent = index === steps.length - 1 ? "Done" : "Next";
      card.hidden = false;
      place(el);
      if (!reduced) { card.classList.remove("guide-in"); void card.offsetWidth; card.classList.add("guide-in"); }
    }
    function startTour(withWelcome, focus) {
      guide.open = false;
      steps = pageSteps();
      if (withWelcome && whatEl) {
        steps.unshift({ sel: "", text: whatEl.textContent.trim(), welcome: true });
        put(WHAT_KEY, "1");
      }
      put(PAGE_KEY, "1");
      show(0);
      if (focus) { next.focus(); }
    }
    function close() {
      card.hidden = true;
      unlight();
      put(PAGE_KEY, "1");
    }
    function closeAndReturn() { close(); summary.focus(); }

    if (tourBtn) {
      tourBtn.hidden = false;
      tourBtn.addEventListener("click", function () { startTour(false, true); });
    }
    back.addEventListener("click", function () { show(index - 1); });
    next.addEventListener("click", function () {
      if (index >= steps.length - 1) { closeAndReturn(); } else { show(index + 1); }
    });
    card.querySelector("[data-guide-close]").addEventListener("click", closeAndReturn);
    card.querySelector("[data-guide-skip]").addEventListener("click", closeAndReturn);
    document.addEventListener("keydown", function (ev) {
      if (ev.key !== "Escape" && ev.key !== "Esc") { return; }
      if (!card.hidden) { closeAndReturn(); } else if (guide.open) { guide.open = false; summary.focus(); }
    });
    window.addEventListener("resize", function () { if (!card.hidden) { place(lit); } });

    // "Try it yourself": remember ticked tasks in this tab session, show progress.
    var boxes = Array.prototype.slice.call(guide.querySelectorAll("[data-task-box]"));
    var progress = guide.querySelector("[data-guide-progress]");
    var done = [];
    try { done = JSON.parse(get(TASK_KEY) || "[]"); } catch (e) { done = []; }
    if (!Array.isArray(done)) { done = []; }
    function showProgress() {
      var n = boxes.filter(function (b) { return b.checked; }).length;
      if (progress) { progress.textContent = "(" + n + " of " + boxes.length + " done)"; }
    }
    boxes.forEach(function (b, i) {
      b.checked = done.indexOf(i + 1) !== -1;
      b.addEventListener("change", function () {
        var list = [];
        boxes.forEach(function (x, j) { if (x.checked) { list.push(j + 1); } });
        put(TASK_KEY, JSON.stringify(list));
        showProgress();
      });
    });
    showProgress();

    // First visit to this page in this tab: open the tour gently, after the intro has gone.
    if (get(PAGE_KEY) !== "1") {
      var tries = 0;
      var timer = setInterval(function () {
        tries += 1;
        var intro = document.getElementById("intro");
        if (intro && !intro.hidden && tries < 40) { return; }
        clearInterval(timer);
        if (get(PAGE_KEY) !== "1") { startTour(get(WHAT_KEY) !== "1", false); }
      }, 400);
    }
  } catch (e) {
    // Fail quietly: the plain <details> guide still works.
  }
})();
