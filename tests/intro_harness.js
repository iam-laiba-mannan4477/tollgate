// Runs tollgate/app/static/app.js against a tiny fake DOM and prints what the intro did.
// Usage: node intro_harness.js <app.js> <scenario>
// Scenarios: first, seen, nointro, reduced, key, skip, nostorage, broken
"use strict";
const fs = require("fs");
const vm = require("vm");
const [, , appPath, scenario] = process.argv;

function el(id) {
  const classes = new Set();
  const listeners = {};
  return {
    id, hidden: true, offsetWidth: 1, focused: false,
    classList: { add: (...c) => c.forEach((x) => classes.add(x)), remove: (...c) => c.forEach((x) => classes.delete(x)),
                 contains: (c) => classes.has(c) },
    addEventListener: (t, f) => { listeners[t] = f; }, fire: (t) => listeners[t] && listeners[t](),
    focus() { this.focused = true; }, querySelector: () => null, getAttribute: () => null,
  };
}
const intro = el("intro");
const skip = el("skip");
const docListeners = {};
const timers = [];
const store = scenario === "seen" ? { "tollgate.introSeen": "1" } : {};
const sessionStorage = scenario === "nostorage" ? undefined : {
  getItem: (k) => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); },
};
const document = {
  getElementById: (id) => {
    if (scenario === "broken" && id === "skip") { throw new Error("broken DOM"); }
    return id === "intro" ? intro : id === "skip" ? skip : null;
  },
  querySelectorAll: () => [],
  addEventListener: (t, f) => { docListeners[t] = f; },
  removeEventListener: (t) => { delete docListeners[t]; },
};
const window = {
  location: { search: scenario === "nointro" ? "?nointro=1" : "", reload() {} },
  matchMedia: () => ({ matches: scenario === "reduced" }),
};
Object.defineProperty(window, "sessionStorage", {
  get() { if (sessionStorage === undefined) { throw new Error("storage blocked"); } return sessionStorage; },
});
const sandbox = {
  window, document, location: window.location, Date,
  setTimeout: (f, ms) => { timers.push({ f, ms }); return timers.length; },
  clearTimeout: () => {}, setInterval: () => 0, clearInterval: () => {},
};
vm.runInNewContext(fs.readFileSync(appPath, "utf8"), sandbox);
const shownAtStart = !intro.hidden && intro.classList.contains("play");
if (scenario === "key" && docListeners.keydown) { docListeners.keydown(); }
if (scenario === "skip") { skip.fire("click"); }
const endedEarly = intro.classList.contains("out");
timers.filter((t) => t.ms <= 900).forEach((t) => t.f());     // let the fade-out finish
console.log(JSON.stringify({
  shownAtStart, endedEarly, hiddenAfter: intro.hidden, skipFocused: skip.focused,
  remembered: store["tollgate.introSeen"] === "1", autoEndMs: (timers.find((t) => t.ms > 900) || {}).ms || null,
}));
