// Counts down every element with data-countdown="<seconds>". Display only: the server
// decides when anything is released. No inline scripts are used anywhere (strict CSP).
(function () {
  "use strict";
  var items = Array.prototype.slice.call(document.querySelectorAll("[data-countdown]"));
  var started = Date.now();
  var starts = items.map(function (el) { return parseInt(el.getAttribute("data-countdown"), 10) || 0; });
  function tick() {
    var gone = Math.floor((Date.now() - started) / 1000);
    items.forEach(function (el, i) { el.textContent = String(Math.max(0, starts[i] - gone)); });
  }
  if (items.length) { setInterval(tick, 1000); }
})();
