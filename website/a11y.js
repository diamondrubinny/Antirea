/*!
 * Antirea / NoREA — accessibility toolbar.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 *
 * A convenience layer ONLY — the site is built to be accessible without it.
 * Disclosure pattern: a button (aria-expanded) shows a non-modal panel of
 * toggle buttons (aria-pressed). Escape closes it and returns focus.
 * Settings live in localStorage ("norea_a11y"), never leave the browser, and
 * are listed in the privacy policy as a user-requested preference.
 *
 * Must load BEFORE i18n.js: its labels carry data-i18n keys that i18n.js fills
 * in (and refills on every language change).
 */
(function () {
  "use strict";

  var KEY = "norea_a11y";
  var OPTIONS = [
    { id: "text", label: "tb.text", fallback: "Larger text" },
    { id: "contrast", label: "tb.contrast", fallback: "High contrast" },
    { id: "links", label: "tb.links", fallback: "Underline links" },
    { id: "font", label: "tb.font", fallback: "Readable font" },
    { id: "motion", label: "tb.motion", fallback: "Stop animations" },
  ];
  var root = document.documentElement;

  function load() {
    try {
      var v = JSON.parse(localStorage.getItem(KEY) || "{}");
      return v && typeof v === "object" ? v : {};
    } catch (e) {
      return {};
    }
  }
  function save(state) {
    try {
      var any = false;
      for (var k in state) if (state[k]) any = true;
      if (any) localStorage.setItem(KEY, JSON.stringify(state));
      else localStorage.removeItem(KEY);
    } catch (e) {
      /* storage blocked — settings still apply for this page view */
    }
  }
  function applyState(state) {
    for (var i = 0; i < OPTIONS.length; i++) {
      root.classList.toggle("a11y-" + OPTIONS[i].id, state[OPTIONS[i].id] === true);
    }
  }

  // Apply saved settings as early as possible to limit a flash of default styles.
  var state = load();
  applyState(state);

  function el(tag, attrs, i18nKey, text) {
    var e = document.createElement(tag);
    for (var a in attrs) e.setAttribute(a, attrs[a]);
    if (i18nKey) e.setAttribute("data-i18n", i18nKey);
    if (text) e.textContent = text;
    return e;
  }

  function build() {
    if (document.getElementById("a11y-panel")) return;

    var fab = el("button", {
      type: "button",
      class: "a11y-fab",
      "aria-expanded": "false",
      "aria-controls": "a11y-panel",
    });
    var icon = el("span", { "aria-hidden": "true" }, null, "♿");
    var fabLabel = el("span", { class: "sr-only", id: "a11y-fab-label" }, "tb.open", "Accessibility options");
    fab.appendChild(icon);
    fab.appendChild(fabLabel);

    var panel = el("div", { id: "a11y-panel", class: "a11y-panel", hidden: "" });
    panel.appendChild(el("h2", { id: "a11y-title" }, "tb.title", "Accessibility options"));

    var list = el("ul", { class: "a11y-opts" });
    var buttons = [];
    for (var i = 0; i < OPTIONS.length; i++) {
      var o = OPTIONS[i];
      var li = document.createElement("li");
      var b = el(
        "button",
        { type: "button", class: "a11y-opt", "data-opt": o.id, "aria-pressed": String(state[o.id] === true) },
        o.label,
        o.fallback,
      );
      li.appendChild(b);
      list.appendChild(li);
      buttons.push(b);
    }
    panel.appendChild(list);

    var row = el("div", { class: "a11y-row" });
    var reset = el("button", { type: "button", class: "a11y-act" }, "tb.reset", "Reset");
    var close = el("button", { type: "button", class: "a11y-act" }, "tb.close", "Close");
    row.appendChild(reset);
    row.appendChild(close);
    panel.appendChild(row);
    panel.appendChild(
      el("a", { class: "a11y-link", href: "/accessibility.html" }, "tb.statement", "Accessibility statement"),
    );

    function setOpen(open) {
      fab.setAttribute("aria-expanded", String(open));
      if (open) panel.removeAttribute("hidden");
      else panel.setAttribute("hidden", "");
    }

    fab.addEventListener("click", function () {
      var open = fab.getAttribute("aria-expanded") !== "true";
      setOpen(open);
      if (open) buttons[0].focus();
    });
    close.addEventListener("click", function () {
      setOpen(false);
      fab.focus();
    });
    reset.addEventListener("click", function () {
      state = {};
      applyState(state);
      save(state);
      for (var j = 0; j < buttons.length; j++) buttons[j].setAttribute("aria-pressed", "false");
    });
    list.addEventListener("click", function (ev) {
      var t = ev.target;
      while (t && t !== list && !(t.getAttribute && t.getAttribute("data-opt"))) t = t.parentNode;
      if (!t || t === list) return;
      var id = t.getAttribute("data-opt");
      state[id] = !(state[id] === true);
      t.setAttribute("aria-pressed", String(state[id]));
      applyState(state);
      save(state);
    });
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape" && fab.getAttribute("aria-expanded") === "true") {
        setOpen(false);
        fab.focus();
      }
    });

    // A labelled landmark after the footer: last in tab order, outside <main>,
    // and every piece of content still sits inside a landmark.
    var aside = el("aside", { class: "a11y-tools", "aria-labelledby": "a11y-fab-label" });
    aside.appendChild(fab);
    aside.appendChild(panel);
    document.body.appendChild(aside);

    // Keep the toolbar reachable while the cookie banner is showing: lift it
    // above the banner instead of being covered by it (WCAG 2.4.11). CSSOM
    // property writes are allowed under the site's strict style-src CSP.
    var lifted = -1;
    function lift() {
      var bn = document.querySelector(".cc-banner");
      var h = bn && !bn.classList.contains("cc-hidden") ? Math.ceil(bn.getBoundingClientRect().height) : 0;
      if (h !== lifted) {
        lifted = h;
        aside.style.setProperty("--a11y-lift", h + "px");
      }
    }
    lift();
    if (window.MutationObserver) {
      new MutationObserver(lift).observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["class"],
      });
    }
    window.addEventListener("resize", lift);
  }

  if (document.readyState !== "loading") build();
  else document.addEventListener("DOMContentLoaded", build);
})();
