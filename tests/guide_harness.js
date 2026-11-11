// Runs tollgate/app/static/guide.js against a tiny fake page and prints what the tour did.
// Usage: node guide_harness.js <guide.js> <scenario>
// Scenarios: first (welcome + full tour), seen (no auto open), tight (small window),
//            nostorage (storage throws), place (placement rule only).
"use strict";
const fs = require("fs");
const vm = require("vm");
const [, , guidePath, scenario] = process.argv;

const VW = scenario === "tight" ? 360 : 1280;
const VH = scenario === "tight" ? 300 : 800;

function node(attrs, rect) {
  const classes = new Set();
  const listeners = {};
  return {
    attrs: attrs || {}, hidden: !!(attrs && attrs.hidden), disabled: false, checked: false,
    textContent: (attrs && attrs.text) || "", href: "", focused: false, open: false,
    style: {}, offsetWidth: 340, offsetHeight: 170, firstChild: null,
    classList: { add: (...c) => c.forEach((x) => classes.add(x)), remove: (...c) => c.forEach((x) => classes.delete(x)),
                 contains: (c) => classes.has(c) },
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
    addEventListener(t, f) { listeners[t] = f; }, fire(t) { if (listeners[t]) { listeners[t]({ key: "Escape" }); } },
    focus() { this.focused = true; }, scrollIntoView() {},
    getBoundingClientRect() { return rect || { top: 0, left: 0, right: 0, bottom: 0 }; },
  };
}
// The Approvals page in demo mode: 5 tips plus the "what next" card.
const targets = {
  ".sub": node({}, { top: 120, left: 240, right: 1000, bottom: 160 }),
  "[data-approve-panel] > summary": node({}, { top: 300, left: 1050, right: 1250, bottom: 340 }),
  ".apr form[action$='/reject']": node({}, { top: 300, left: 900, right: 1000, bottom: 340 }),
  "[data-guide=waiting]": node({}, { top: 640, left: 240, right: 1250, bottom: 680 }),
  ".demo-banner": node({}, { top: 0, left: 0, right: 1280, bottom: 40 }),
};
if (scenario === "tight") {
  Object.values(targets).forEach((t) => { t.getBoundingClientRect = () => ({ top: 20, left: 10, right: 350, bottom: 120 }); });
}
const tipLis = Object.keys(targets).map((sel, i) => node({ "data-guide-target": sel, text: `tip ${i + 1}` }));
const nextLi = node({ "data-guide-target": "", "data-guide-link": "/audit", "data-guide-link-text": "Open Activity",
                      text: "Next: open Activity. Open Activity" });
nextLi.firstChild = { nodeType: 3, nodeValue: "Next: open Activity. " };
tipLis.push(nextLi);
tipLis.forEach((li) => { li.textContent = li.attrs.text; });

const summary = node();
const tourBtn = node({ hidden: true });
tourBtn.hidden = true;
const what = node({ text: "Tollgate is a payment firewall for AI agents." });
const progress = node();
const boxes = [node(), node(), node()];
const guide = node({ "data-guide-page": "approvals", "data-guide-mode": "demo" });
guide.querySelector = (s) => ({ summary, "[data-guide-tour]": tourBtn, "[data-guide-what]": what,
                                "[data-guide-progress]": progress }[s] || null);
guide.querySelectorAll = (s) => (s === "li[data-guide-target]" ? tipLis : s === "[data-task-box]" ? boxes : []);
const parts = {};
["#guide-count", "#guide-text", "#guide-go", "[data-guide-back]", "[data-guide-next]",
 "[data-guide-close]", "[data-guide-skip]"].forEach((k) => { parts[k] = node(); });
parts["#guide-go"].hidden = true;
const card = node({ hidden: true });
card.hidden = true;
card.querySelector = (s) => parts[s] || null;

const store = scenario === "seen" ? { "tollgate.guideSeen.approvals": "1", "tollgate.whatSeen": "1" } : {};
const docListeners = {};
const intervals = [];
const document = {
  getElementById: (id) => ({ guide, "guide-card": card }[id] || null),
  querySelector: (s) => targets[s] || null,
  addEventListener: (t, f) => { docListeners[t] = f; },
};
const window = {
  innerWidth: VW, innerHeight: VH, scrollBy() {},
  matchMedia: () => ({ matches: true }),               // reduced motion: no animation
  addEventListener() {},
};
Object.defineProperty(window, "sessionStorage", {
  get() {
    if (scenario === "nostorage") { throw new Error("storage blocked"); }
    return { getItem: (k) => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } };
  },
});
const sandbox = { window, document, JSON, Math, Array, String,
                  setInterval: (f) => { intervals.push(f); return intervals.length; }, clearInterval: () => {} };
vm.runInNewContext(fs.readFileSync(guidePath, "utf8"), sandbox);

const out = { tourButtonShown: !tourBtn.hidden };
if (scenario === "place") {
  const place = window.TollgateGuidePlace;
  const r = { top: 300, left: 1050, right: 1250, bottom: 340 };
  out.besideButton = place(r, 340, 170, 1280, 800, 12);
  out.tooSmall = place(r, 340, 170, 300, 800, 12);
  console.log(JSON.stringify(out));
  process.exit(0);
}
intervals.forEach((f) => f());                         // the first-visit timer fires
out.autoOpened = !card.hidden;
if (card.hidden && scenario === "seen") {
  console.log(JSON.stringify({ ...out, store }));
  process.exit(0);
}
const seenCards = [];
for (let i = 0; i < 20 && !card.hidden; i++) {
  const lit = Object.values(targets).find((t) => t.classList.contains("guide-lit"));
  const rect = lit ? lit.getBoundingClientRect() : null;
  const top = parseInt(card.style.top, 10), left = parseInt(card.style.left, 10);
  const floating = card.classList.contains("guide-floating");
  const inside = floating ? left >= 12 && top >= 12 && left + 340 <= VW - 12 && top + 170 <= VH - 12 : true;
  const covers = floating && rect ? !(left >= rect.right || left + 340 <= rect.left || top >= rect.bottom || top + 170 <= rect.top) : false;
  seenCards.push({ count: parts["#guide-count"].textContent, text: parts["#guide-text"].textContent,
                   floating, strip: card.classList.contains("guide-strip"), inside, covers,
                   link: parts["#guide-go"].hidden ? null : parts["#guide-go"].href,
                   next: parts["[data-guide-next]"].textContent });
  parts["[data-guide-next]"].fire("click");
}
out.cards = seenCards;
out.closedAtEnd = card.hidden;
out.remembered = store["tollgate.guideSeen.approvals"] === "1";
console.log(JSON.stringify(out));
