/*!
 * NoREA cookie-consent (GDPR / Israeli Privacy Law oriented). No dependencies.
 * Author: Diamond Rubinny. Apache-2.0.
 *
 * Categories: essential (always on) + functional, analytics, marketing (opt-in,
 * default OFF, never pre-checked). Reject is as easy and prominent as Accept.
 * Consent is recorded (version + timestamp + categories) in localStorage.
 *
 * This site currently sets NO analytics/marketing cookies. The framework gates
 * any such scripts you add later: call window.noreaConsent.get("analytics")
 * before loading them, or subscribe with window.noreaConsent.onChange(...).
 *
 * NOTE: this is a technical control, not legal advice. Have the cookie/privacy
 * texts reviewed by a lawyer before relying on them.
 */
(function () {
  "use strict";
  var KEY = "norea_consent";
  var VERSION = "2026-11-05";
  var CATS = [
    {
      id: "functional",
      name: "Functional",
      desc: "Remembers preferences (e.g. your chosen options) to improve the experience.",
    },
    {
      id: "analytics",
      name: "Analytics",
      desc: "Helps us understand aggregate, anonymous usage. Loaded only if you allow it.",
    },
    {
      id: "marketing",
      name: "Marketing",
      desc: "Used for advertising/remarketing. Loaded only if you allow it.",
    },
  ];
  var listeners = [];

  function read() {
    try {
      var raw = localStorage.getItem(KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }
  function save(categories) {
    var record = { v: VERSION, date: new Date().toISOString(), categories: categories };
    try {
      localStorage.setItem(KEY, JSON.stringify(record));
    } catch (e) {
      /* storage unavailable — consent simply won't persist */
    }
    listeners.forEach(function (cb) {
      try {
        cb(categories);
      } catch (e) {
        /* ignore */
      }
    });
    return record;
  }
  function allOff() {
    return { functional: false, analytics: false, marketing: false };
  }
  function allOn() {
    return { functional: true, analytics: true, marketing: true };
  }

  var el = {};
  function qs(id) {
    return document.getElementById(id);
  }

  function showBanner(show) {
    if (el.banner) el.banner.classList.toggle("cc-hidden", !show);
  }
  function openModal() {
    var current = (read() && read().categories) || allOff();
    CATS.forEach(function (c) {
      var input = qs("cc-sw-" + c.id);
      if (input) input.checked = !!current[c.id];
    });
    el.overlay.classList.remove("cc-hidden");
    var first = el.modal.querySelector("input,button");
    if (first) first.focus();
  }
  function closeModal() {
    el.overlay.classList.add("cc-hidden");
  }

  function applyAndClose(categories) {
    save(categories);
    showBanner(false);
    closeModal();
  }

  function build() {
    // Banner
    var banner = document.createElement("div");
    banner.className = "cc-banner cc-hidden";
    banner.setAttribute("role", "region");
    banner.setAttribute("aria-label", "Cookie consent");
    banner.innerHTML =
      '<div class="cc-banner-in">' +
      '<p class="cc-text">We use only essential storage to run this site and remember your choice. ' +
      "With your consent we may later use functional, analytics or marketing cookies. " +
      'See our <a href="privacy.html">Privacy &amp; Cookie Policy</a>.</p>' +
      '<div class="cc-actions">' +
      '<button class="cc-btn" id="cc-reject" type="button">Reject all</button>' +
      '<button class="cc-btn" id="cc-manage" type="button">Manage preferences</button>' +
      '<button class="cc-btn cc-btn-primary" id="cc-accept" type="button">Accept all</button>' +
      "</div></div>";

    // Modal
    var overlay = document.createElement("div");
    overlay.className = "cc-overlay cc-hidden";
    var cats = CATS.map(function (c) {
      return (
        '<div class="cc-cat"><div class="cc-cat-head"><strong>' +
        c.name +
        "</strong>" +
        '<input class="cc-switch" type="checkbox" id="cc-sw-' +
        c.id +
        '" aria-label="' +
        c.name +
        ' cookies"></div><p>' +
        c.desc +
        "</p></div>"
      );
    }).join("");
    overlay.innerHTML =
      '<div class="cc-modal" role="dialog" aria-modal="true" aria-labelledby="cc-title">' +
      '<h2 id="cc-title">Privacy preferences</h2>' +
      "<p>Choose which cookies to allow. Essential storage is always on because the site cannot work without it. " +
      "You can change this anytime via “Cookie settings” in the footer.</p>" +
      '<div class="cc-cat"><div class="cc-cat-head"><strong>Essential</strong><span class="cc-locked">Always on</span></div>' +
      "<p>Required for the site to function and to store your consent choice. No tracking.</p></div>" +
      cats +
      '<div class="cc-modal-actions">' +
      '<button class="cc-btn" id="cc-m-reject" type="button">Reject all</button>' +
      '<button class="cc-btn" id="cc-m-save" type="button">Save preferences</button>' +
      '<button class="cc-btn cc-btn-primary" id="cc-m-accept" type="button">Accept all</button>' +
      "</div></div>";

    document.body.appendChild(banner);
    document.body.appendChild(overlay);
    el.banner = banner;
    el.overlay = overlay;
    el.modal = overlay.querySelector(".cc-modal");

    qs("cc-accept").addEventListener("click", function () {
      applyAndClose(allOn());
    });
    qs("cc-reject").addEventListener("click", function () {
      applyAndClose(allOff());
    });
    qs("cc-manage").addEventListener("click", openModal);
    qs("cc-m-accept").addEventListener("click", function () {
      applyAndClose(allOn());
    });
    qs("cc-m-reject").addEventListener("click", function () {
      applyAndClose(allOff());
    });
    qs("cc-m-save").addEventListener("click", function () {
      var cats = {};
      CATS.forEach(function (c) {
        cats[c.id] = !!qs("cc-sw-" + c.id).checked;
      });
      applyAndClose(cats);
    });
    overlay.addEventListener("click", function (e) {
      if (e.target === overlay) closeModal();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !overlay.classList.contains("cc-hidden")) closeModal();
    });
  }

  function init() {
    build();
    var stored = read();
    if (!stored || stored.v !== VERSION) {
      // No valid consent for the current policy version → ask.
      showBanner(true);
    } else {
      listeners.forEach(function (cb) {
        try {
          cb(stored.categories);
        } catch (e) {
          /* ignore */
        }
      });
    }
    // Footer "Cookie settings" link(s).
    Array.prototype.forEach.call(document.querySelectorAll("[data-cc-open]"), function (a) {
      a.addEventListener("click", function (e) {
        e.preventDefault();
        openModal();
      });
    });
  }

  // Public API for gating non-essential scripts.
  window.noreaConsent = {
    get: function (id) {
      var r = read();
      return !!(r && r.categories && r.categories[id]);
    },
    onChange: function (cb) {
      listeners.push(cb);
      var r = read();
      if (r) cb(r.categories);
    },
    openSettings: openModal,
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
