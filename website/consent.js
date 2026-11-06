/*!
 * NoREA cookie-consent (GDPR / Israeli Privacy Law oriented). No dependencies.
 * Author: Diamond Rubinny. Apache-2.0.
 *
 * Categories: essential (always on) + functional, analytics, marketing (opt-in,
 * default OFF, never pre-checked). Reject is as easy and prominent as Accept.
 * Consent is recorded (version + timestamp + categories) in localStorage.
 *
 * Localized (en, he, es, fr, de, ar). It follows the site language set by
 * i18n.js (window.noreaLang / <html lang>) and re-localizes on the
 * "norea:langchange" event. Translations are machine-generated and
 * community-extendable (not professionally reviewed).
 *
 * This site currently sets NO analytics/marketing cookies. The framework gates
 * any such scripts you add later: call window.noreaConsent.get("analytics")
 * before loading them, or subscribe with window.noreaConsent.onChange(...).
 *
 * NOTE: this is a technical control, not legal advice. The cookie/privacy
 * wording shown is the site owner's approved text; keep it in sync with your
 * actual data practices.
 */
(function () {
  "use strict";
  var KEY = "norea_consent";
  var VERSION = "2026-11-05";
  var CATS = [{ id: "functional" }, { id: "analytics" }, { id: "marketing" }];

  var I18N = {
    en: {
      bannerAria: "Cookie consent",
      bannerText:
        'We use only essential storage to run this site and remember your choice. With your consent we may later use functional, analytics or marketing cookies. See our <a href="privacy.html">Privacy &amp; Cookie Policy</a>.',
      reject: "Reject all",
      manage: "Manage preferences",
      accept: "Accept all",
      modalTitle: "Privacy preferences",
      modalIntro:
        "Choose which cookies to allow. Essential storage is always on because the site cannot work without it. You can change this anytime via “Cookie settings” in the footer.",
      essentialName: "Essential",
      essentialLocked: "Always on",
      essentialDesc: "Required for the site to function and to store your consent choice. No tracking.",
      functional_name: "Functional",
      functional_desc: "Remembers preferences (e.g. your chosen options) to improve the experience.",
      analytics_name: "Analytics",
      analytics_desc: "Helps us understand aggregate, anonymous usage. Loaded only if you allow it.",
      marketing_name: "Marketing",
      marketing_desc: "Used for advertising/remarketing. Loaded only if you allow it.",
      mReject: "Reject all",
      mSave: "Save preferences",
      mAccept: "Accept all",
    },
    he: {
      bannerAria: "הסכמה לעוגיות",
      bannerText:
        'אנחנו משתמשים רק באחסון חיוני כדי להפעיל את האתר ולזכור את בחירתך. בהסכמתך נוכל בעתיד להשתמש בעוגיות פונקציונליות, אנליטיקה או שיווק. ראה את <a href="privacy.html">מדיניות הפרטיות והעוגיות</a> שלנו.',
      reject: "דחה הכל",
      manage: "ניהול העדפות",
      accept: "אשר הכל",
      modalTitle: "העדפות פרטיות",
      modalIntro:
        'בחר אילו עוגיות לאפשר. אחסון חיוני תמיד פעיל כי האתר אינו יכול לפעול בלעדיו. אפשר לשנות זאת בכל עת דרך "הגדרות עוגיות" בכותרת התחתונה.',
      essentialName: "חיוני",
      essentialLocked: "תמיד פעיל",
      essentialDesc: "נדרש לתפקוד האתר ולשמירת בחירת ההסכמה שלך. ללא מעקב.",
      functional_name: "פונקציונלי",
      functional_desc: "זוכר העדפות (למשל האפשרויות שבחרת) כדי לשפר את החוויה.",
      analytics_name: "אנליטיקה",
      analytics_desc: "עוזר לנו להבין שימוש מצטבר ואנונימי. נטען רק אם תאשר.",
      marketing_name: "שיווק",
      marketing_desc: "משמש לפרסום/רימרקטינג. נטען רק אם תאשר.",
      mReject: "דחה הכל",
      mSave: "שמור העדפות",
      mAccept: "אשר הכל",
    },
    es: {
      bannerAria: "Consentimiento de cookies",
      bannerText:
        'Usamos solo almacenamiento esencial para que el sitio funcione y recordar tu elección. Con tu consentimiento podríamos usar más adelante cookies funcionales, de analítica o de marketing. Consulta nuestra <a href="privacy.html">Política de privacidad y cookies</a>.',
      reject: "Rechazar todo",
      manage: "Gestionar preferencias",
      accept: "Aceptar todo",
      modalTitle: "Preferencias de privacidad",
      modalIntro:
        "Elige qué cookies permitir. El almacenamiento esencial siempre está activado porque el sitio no puede funcionar sin él. Puedes cambiarlo cuando quieras mediante “Ajustes de cookies” en el pie de página.",
      essentialName: "Esencial",
      essentialLocked: "Siempre activo",
      essentialDesc:
        "Necesario para que el sitio funcione y para almacenar tu elección de consentimiento. Sin seguimiento.",
      functional_name: "Funcional",
      functional_desc: "Recuerda preferencias (p. ej., las opciones que elijas) para mejorar la experiencia.",
      analytics_name: "Analítica",
      analytics_desc: "Nos ayuda a entender el uso agregado y anónimo. Se carga solo si lo permites.",
      marketing_name: "Marketing",
      marketing_desc: "Se usa para publicidad/remarketing. Se carga solo si lo permites.",
      mReject: "Rechazar todo",
      mSave: "Guardar preferencias",
      mAccept: "Aceptar todo",
    },
    fr: {
      bannerAria: "Consentement aux cookies",
      bannerText:
        'Nous utilisons uniquement un stockage essentiel pour faire fonctionner le site et mémoriser votre choix. Avec votre consentement, nous pourrons utiliser plus tard des cookies fonctionnels, d’analyse ou de marketing. Consultez notre <a href="privacy.html">Politique de confidentialité et de cookies</a>.',
      reject: "Tout refuser",
      manage: "Gérer les préférences",
      accept: "Tout accepter",
      modalTitle: "Préférences de confidentialité",
      modalIntro:
        "Choisissez les cookies à autoriser. Le stockage essentiel est toujours actif car le site ne peut pas fonctionner sans lui. Vous pouvez le modifier à tout moment via « Paramètres des cookies » dans le pied de page.",
      essentialName: "Essentiel",
      essentialLocked: "Toujours actif",
      essentialDesc:
        "Nécessaire au fonctionnement du site et à l’enregistrement de votre choix de consentement. Aucun suivi.",
      functional_name: "Fonctionnel",
      functional_desc: "Mémorise les préférences (p. ex. les options choisies) pour améliorer l’expérience.",
      analytics_name: "Analyse",
      analytics_desc:
        "Nous aide à comprendre l’usage agrégé et anonyme. Chargé uniquement si vous l’autorisez.",
      marketing_name: "Marketing",
      marketing_desc: "Utilisé pour la publicité/le remarketing. Chargé uniquement si vous l’autorisez.",
      mReject: "Tout refuser",
      mSave: "Enregistrer les préférences",
      mAccept: "Tout accepter",
    },
    de: {
      bannerAria: "Cookie-Einwilligung",
      bannerText:
        'Wir verwenden nur essenziellen Speicher, um die Website zu betreiben und Ihre Wahl zu merken. Mit Ihrer Einwilligung können wir später funktionale, Analyse- oder Marketing-Cookies verwenden. Siehe unsere <a href="privacy.html">Datenschutz- &amp; Cookie-Richtlinie</a>.',
      reject: "Alle ablehnen",
      manage: "Einstellungen verwalten",
      accept: "Alle akzeptieren",
      modalTitle: "Datenschutzeinstellungen",
      modalIntro:
        "Wählen Sie, welche Cookies erlaubt sind. Essenzieller Speicher ist immer aktiv, da die Website ohne ihn nicht funktioniert. Sie können dies jederzeit über „Cookie-Einstellungen“ in der Fußzeile ändern.",
      essentialName: "Essenziell",
      essentialLocked: "Immer aktiv",
      essentialDesc:
        "Erforderlich, damit die Website funktioniert und Ihre Einwilligung gespeichert wird. Kein Tracking.",
      functional_name: "Funktional",
      functional_desc:
        "Merkt sich Präferenzen (z. B. Ihre gewählten Optionen), um das Erlebnis zu verbessern.",
      analytics_name: "Analyse",
      analytics_desc:
        "Hilft uns, die aggregierte, anonyme Nutzung zu verstehen. Wird nur geladen, wenn Sie zustimmen.",
      marketing_name: "Marketing",
      marketing_desc: "Wird für Werbung/Remarketing verwendet. Wird nur geladen, wenn Sie zustimmen.",
      mReject: "Alle ablehnen",
      mSave: "Einstellungen speichern",
      mAccept: "Alle akzeptieren",
    },
    ar: {
      bannerAria: "الموافقة على ملفات تعريف الارتباط",
      bannerText:
        'نستخدم تخزينًا أساسيًا فقط لتشغيل الموقع وتذكّر اختيارك. وبموافقتك قد نستخدم لاحقًا ملفات تعريف ارتباط وظيفية أو تحليلية أو تسويقية. راجع <a href="privacy.html">سياسة الخصوصية وملفات تعريف الارتباط</a> لدينا.',
      reject: "رفض الكل",
      manage: "إدارة التفضيلات",
      accept: "قبول الكل",
      modalTitle: "تفضيلات الخصوصية",
      modalIntro:
        'اختر ملفات تعريف الارتباط المسموح بها. التخزين الأساسي مُفعَّل دائمًا لأن الموقع لا يعمل بدونه. يمكنك تغيير ذلك في أي وقت عبر "إعدادات ملفات تعريف الارتباط" في التذييل.',
      essentialName: "أساسي",
      essentialLocked: "مُفعَّل دائمًا",
      essentialDesc: "ضروري لعمل الموقع ولتخزين اختيار موافقتك. بلا تتبّع.",
      functional_name: "وظيفي",
      functional_desc: "يتذكّر التفضيلات (مثل الخيارات التي تحددها) لتحسين التجربة.",
      analytics_name: "تحليلات",
      analytics_desc: "يساعدنا على فهم الاستخدام الإجمالي والمجهول. يُحمَّل فقط إذا سمحت به.",
      marketing_name: "تسويق",
      marketing_desc: "يُستخدم للإعلان/إعادة الاستهداف. يُحمَّل فقط إذا سمحت به.",
      mReject: "رفض الكل",
      mSave: "حفظ التفضيلات",
      mAccept: "قبول الكل",
    },
  };

  function activeLang() {
    var l = window.noreaLang || document.documentElement.lang || "en";
    l = ("" + l).slice(0, 2).toLowerCase();
    return I18N[l] ? l : "en";
  }

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
    banner.innerHTML =
      '<div class="cc-banner-in">' +
      '<p class="cc-text" id="cc-text"></p>' +
      '<div class="cc-actions">' +
      '<button class="cc-btn" id="cc-reject" type="button"></button>' +
      '<button class="cc-btn" id="cc-manage" type="button"></button>' +
      '<button class="cc-btn cc-btn-primary" id="cc-accept" type="button"></button>' +
      "</div></div>";

    // Modal
    var overlay = document.createElement("div");
    overlay.className = "cc-overlay cc-hidden";
    var cats = CATS.map(function (c) {
      return (
        '<div class="cc-cat"><div class="cc-cat-head"><strong id="cc-cat-name-' +
        c.id +
        '"></strong>' +
        '<input class="cc-switch" type="checkbox" id="cc-sw-' +
        c.id +
        '"></div><p id="cc-cat-desc-' +
        c.id +
        '"></p></div>'
      );
    }).join("");
    overlay.innerHTML =
      '<div class="cc-modal" role="dialog" aria-modal="true" aria-labelledby="cc-title">' +
      '<h2 id="cc-title"></h2>' +
      '<p id="cc-intro"></p>' +
      '<div class="cc-cat"><div class="cc-cat-head"><strong id="cc-ess-name"></strong><span class="cc-locked" id="cc-ess-locked"></span></div>' +
      '<p id="cc-ess-desc"></p></div>' +
      cats +
      '<div class="cc-modal-actions">' +
      '<button class="cc-btn" id="cc-m-reject" type="button"></button>' +
      '<button class="cc-btn" id="cc-m-save" type="button"></button>' +
      '<button class="cc-btn cc-btn-primary" id="cc-m-accept" type="button"></button>' +
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
      var picked = {};
      CATS.forEach(function (c) {
        picked[c.id] = !!qs("cc-sw-" + c.id).checked;
      });
      applyAndClose(picked);
    });
    overlay.addEventListener("click", function (e) {
      if (e.target === overlay) closeModal();
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && !overlay.classList.contains("cc-hidden")) closeModal();
    });
  }

  function setHTML(id, html) {
    var n = qs(id);
    if (n && html != null) n.innerHTML = html;
  }

  function localize() {
    var t = I18N[activeLang()] || I18N.en;
    if (el.banner) el.banner.setAttribute("aria-label", t.bannerAria);
    setHTML("cc-text", t.bannerText);
    setHTML("cc-reject", t.reject);
    setHTML("cc-manage", t.manage);
    setHTML("cc-accept", t.accept);
    setHTML("cc-title", t.modalTitle);
    setHTML("cc-intro", t.modalIntro);
    setHTML("cc-ess-name", t.essentialName);
    setHTML("cc-ess-locked", t.essentialLocked);
    setHTML("cc-ess-desc", t.essentialDesc);
    setHTML("cc-m-reject", t.mReject);
    setHTML("cc-m-save", t.mSave);
    setHTML("cc-m-accept", t.mAccept);
    CATS.forEach(function (c) {
      setHTML("cc-cat-name-" + c.id, t[c.id + "_name"]);
      setHTML("cc-cat-desc-" + c.id, t[c.id + "_desc"]);
      var sw = qs("cc-sw-" + c.id);
      if (sw) sw.setAttribute("aria-label", t[c.id + "_name"]);
    });
  }

  function init() {
    build();
    localize();
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
    // Footer "Cookie settings" link(s) — delegated so it survives i18n
    // re-rendering the surrounding markup on language change.
    document.addEventListener("click", function (e) {
      var opener = e.target.closest ? e.target.closest("[data-cc-open]") : null;
      if (opener) {
        e.preventDefault();
        openModal();
      }
    });
    // Re-localize when the site language changes.
    window.addEventListener("norea:langchange", localize);
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
