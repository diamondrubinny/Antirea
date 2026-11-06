/*!
 * Antirea / NoREA — marketing site i18n.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 *
 * English is authoritative; other languages are machine-translated and
 * community-extendable (not professionally reviewed). Missing keys fall back to
 * English. Values may contain inline HTML (first-party, trusted content only).
 */
(function () {
  "use strict";

  var LANGS = ["en", "he", "es", "fr", "de", "ar"];
  var NAMES = { en: "English", he: "עברית", es: "Español", fr: "Français", de: "Deutsch", ar: "العربية" };
  var RTL = { he: true, ar: true };

  var DICT = {
    en: {
      "meta.title": "NoREA — Stop reverse-engineering of your code | anti-REA protection (Antirea)",
      "meta.desc":
        "NoREA (Antirea) is an open-source toolkit to detect, deceive and block reverse-engineering tools like REA. Protect your website, SaaS and app source code with honeypots, CDP/DevTools detection, WASM, and hermetic server-side execution.",
      skip: "Skip to main content",
      "nav.how": "How it works",
      "nav.quickstart": "Quickstart",
      "nav.ai": "AI agents",
      "nav.github": "GitHub ★",
      "hero.eyebrow": "Open source · Apache-2.0 · self-hosted",
      "hero.h1": 'Stop <span class="accent">reverse-engineering</span> of your code.',
      "hero.lead":
        "<strong>NoREA</strong> (“no REA”) is a drop-in toolkit that <strong>detects, deceives and blocks</strong> reverse-engineering tools — including CDP/DevTools-based ones like <strong>REA</strong> — and keeps the logic that matters off the client entirely. For websites, SaaS and apps.",
      "hero.cta1": "Get started",
      "hero.cta2": "View on GitHub",
      "hero.honest":
        "Honest by design: only server-side execution is hermetic; client-side layers deter, deceive and report.",
      "hero.imgAlt":
        "NoREA control panel showing reverse-engineering attempts by country, signal and REA fingerprints",
      "problem.h2": "The problem",
      "problem.lead":
        "Reverse-engineering tools like <strong>REA</strong> attach to a browser (via the Chrome DevTools Protocol), read your bundles and source maps, and drive scripted sessions — turning your shipped JavaScript into a blueprint for cloning. Every business that ships a web app exposes its front-end code.",
      "how.h2": "How NoREA protects — three layers",
      "how.c1.h3": "1 · Detect",
      "how.c1.p":
        "A browser guard flags DevTools/CDP attach, automation (Playwright/Puppeteer), integrity tampering, and a <strong>verified REA fingerprint</strong>. Every attempt is reported to your dashboard.",
      "how.c2.h3": "2 · Deceive",
      "how.c2.p":
        "A server-side honeypot serves <strong>inert decoy</strong> code (with canary tokens) to requests scored as analysis — behavioural detection that doesn’t trust the User-Agent, so forging headers raises the score.",
      "how.c3.h3": "3 · Protect",
      "how.c3.p":
        "The logic that matters runs <strong>server-side</strong> (hermetic — REA never sees the algorithm); code that must ship to the browser can be compiled to <strong>WASM</strong> (an opaque binary).",
      "more.h2": "More ways it protects",
      "more.c1.h3": "Proof of work",
      "more.c1.p":
        "Make mass scraping pay CPU: suspicious clients must solve a small challenge before they can reach protected routes.",
      "more.c2.h3": "Tarpit &amp; TLS fingerprint",
      "more.c2.p":
        "Slow down detected bots, and flag <code>curl</code>/<code>python</code>/<code>scrapy</code> by their TLS (JA3) handshake — not just the User-Agent.",
      "more.c3.h3": "WebAssembly",
      "more.c3.p":
        "Ship client-side logic as an opaque WASM binary instead of readable JavaScript — much harder to reverse.",
      "more.c4.h3": "Traitor tracing",
      "more.c4.p":
        "Watermark each viewer invisibly, scan public code for leaks, and get a webhook alert when attacks spike.",
      "more.c5.h3": "Domain lock",
      "more.c5.p":
        "Flag — and optionally shut down — your front-end when it's rehosted on a domain you didn't authorize (a cloned site).",
      "more.c6.h3": "Hardening",
      "more.c6.p":
        "Obfuscate shipped JavaScript, pin assets with SRI, set a strict CSP, and deliver the real bundle encrypted — the key reaches verified clients only.",
      "rea.h2": "We know REA",
      "rea.lead":
        "NoREA ships fingerprints <strong>verified against REA’s public source</strong>, each documented with its evadability:",
      "rea.li1":
        "<strong>Server signal</strong> — REA’s source-map fetcher sends a distinctive <code>Accept: application/source-map+json</code> with no cookie or referer. No browser does this → near-certain, hard to evade.",
      "rea.li2":
        "<strong>Client signal</strong> — REA’s default Playwright profile (headless + <code>navigator.webdriver</code> + 1280×720 + UTC + reduced-motion…) is a distinctive combination.",
      "rea.li3":
        "<strong>Adaptive</strong> — an optional AI advisor learns attack patterns and proposes <em>bounded</em> defense changes (you approve them).",
      "qs.h2": "Quickstart",
      "qs.s1.h3": "Add the guard to your pages",
      "qs.s2.h3": "Add the honeypot to your server",
      "qs.s3.h3": "Keep the crown jewels off the client",
      "qs.foot":
        'Full docs, Docker deploy and the control panel are in the <a href="https://github.com/diamondrubinny/Antirea" rel="noopener">GitHub repository</a>.',
      "ai.h2": "Install it with an AI agent",
      "ai.lead":
        "Using <strong>Claude Code</strong>, <strong>Cursor</strong>, <strong>GitHub Copilot</strong> or any coding agent? Paste this prompt and let it wire NoREA into your project:",
      "ai.tip":
        "Tip: point the agent at the repo’s <code>README.md</code>, <code>docs/REA-SIGNATURES.md</code> and <code>docs/WASM.md</code> for exact APIs.",
      "who.h2": "Who it’s for",
      "who.lead":
        "SaaS and software owners, agencies, and product teams who ship proprietary web apps and want to make cloning and reverse-engineering expensive — and <em>visible</em>. Self-hosted, privacy-respecting (no raw IPs stored), and free under Apache-2.0.",
      "who.cta": "Protect your code →",
      "support.h2": "Support this project",
      "support.lead":
        "NoREA is free and open source (Apache-2.0). If it helps you or your team, a small donation keeps it maintained and independent. Thank you.",
      "support.donate": "Donate with PayPal",
      "support.scan": "Scan to donate",
      "footer.tagline": "anti-REA code protection",
      "footer.created":
        'Created by <strong>Diamond Rubinny</strong> · Apache-2.0 · <a href="https://github.com/diamondrubinny/Antirea" rel="noopener">GitHub</a>',
      "footer.disclaimer":
        "NoREA is independent software; “REA” is referenced only to describe the reverse-engineering tooling NoREA helps defend against.",
      "footer.donate": "Donate",
      "footer.privacy": "Privacy &amp; Cookie Policy",
      "footer.cookies": "Cookie settings",
      "lang.label": "Language",
      "p.meta.title": "Privacy & Cookie Policy — NoREA",
      "p.meta.desc": "Privacy and cookie policy for the NoREA (Antirea) website.",
      "p.nav.home": "Home",
      "p.h1": "Privacy & Cookie Policy",
      "p.updated": "Last updated: 2026-11-06",
      "p.lead":
        "This is the policy for the <strong>norea.rubinny.net</strong> marketing website only. The NoREA / Antirea software you self-host is governed by your own policies.",
      "p.who.h2": "Who we are",
      "p.who.p":
        "This site is operated by Diamond Rubinny. For privacy questions, use the contact details you publish on your main site.",
      "p.collect.h2": "What this website collects",
      "p.collect.p1":
        "This is a static website. It sets <strong>no analytics or marketing cookies</strong> by default. It uses a small amount of <strong>local storage</strong> on your device for one strictly-necessary purpose: to remember your cookie-consent choice. That data stays in your browser and is not sent to us or any third party.",
      "p.collect.p2":
        "Standard web-server logs (e.g. IP address, user-agent, timestamp) may be processed by the hosting provider for security and reliability. If you enable analytics or marketing tools in the future, document them here and gate them behind consent (the site is already built to do this).",
      "p.cookies.h2": "Cookies & similar technologies",
      "p.th.name": "Name",
      "p.th.cat": "Category",
      "p.th.purpose": "Purpose",
      "p.th.ret": "Retention",
      "p.row.cat": "Essential",
      "p.row.purpose": "Stores your cookie-consent choice (local storage).",
      "p.row.ret": "Until you clear it / change the policy version.",
      "p.cookies.note":
        'Non-essential categories (functional, analytics, marketing) are <strong>off by default</strong> and load only with your consent. You can change or withdraw consent anytime: <a href="#" data-cc-open>open cookie settings</a>.',
      "p.legal.h2": "Legal bases (GDPR) & Israeli law",
      "p.legal.p":
        "Where the EU GDPR applies, non-essential cookies rely on your <strong>consent</strong>; essential storage relies on legitimate interest / necessity to provide the service. Where the Israeli Protection of Privacy Law applies, we aim to collect the minimum necessary and to be transparent about it.",
      "p.rights.h2": "Your rights",
      "p.rights.p":
        'Subject to applicable law, you may request access, correction, deletion, or restriction of your personal data, and withdraw consent. Because this site stores consent only in your browser, you can exercise withdrawal directly via <a href="#" data-cc-open>cookie settings</a> or by clearing your browser storage.',
      "p.third.h2": "Third parties",
      "p.third.p":
        "The site is hosted by a hosting provider and its source lives on GitHub. No third-party analytics, advertising, chat or social pixels are embedded by default. Add any you introduce to this policy and to the consent categories.",
      "p.back": "← Back to home",
    },

    he: {
      "meta.title": "NoREA — עצירת הנדסה לאחור של הקוד שלך | הגנת anti-REA (Antirea)",
      "meta.desc":
        "NoREA (Antirea) היא ערכת כלים בקוד פתוח לזיהוי, הטעיה וחסימה של כלי הנדסה לאחור כמו REA. הגן על קוד המקור של האתר, ה-SaaS והאפליקציה שלך באמצעות honeypots, זיהוי CDP/DevTools, WASM והרצה הרמטית בצד השרת.",
      skip: "דלג לתוכן הראשי",
      "nav.how": "איך זה עובד",
      "nav.quickstart": "התחלה מהירה",
      "nav.ai": "סוכני AI",
      "nav.github": "GitHub ★",
      "hero.eyebrow": "קוד פתוח · Apache-2.0 · אירוח עצמי",
      "hero.h1": 'עצור <span class="accent">הנדסה לאחור</span> של הקוד שלך.',
      "hero.lead":
        "<strong>NoREA</strong> (“no REA”) היא ערכת כלים מוכנה-לשילוב ש<strong>מזהה, מטעה וחוסמת</strong> כלי הנדסה לאחור — כולל כאלה מבוססי CDP/DevTools כמו <strong>REA</strong> — ומשאירה את הלוגיקה החשובה הרחק מהלקוח לחלוטין. לאתרים, ל-SaaS ולאפליקציות.",
      "hero.cta1": "בואו נתחיל",
      "hero.cta2": "צפייה ב-GitHub",
      "hero.honest": "ישר מיסודו: רק הרצה בצד השרת היא הרמטית; שכבות צד-הלקוח מרתיעות, מטעות ומדווחות.",
      "hero.imgAlt": "לוח הניהול של NoREA מציג ניסיונות הנדסה לאחור לפי מדינה, סימן וטביעות אצבע של REA",
      "problem.h2": "הבעיה",
      "problem.lead":
        "כלי הנדסה לאחור כמו <strong>REA</strong> מתחברים לדפדפן (דרך Chrome DevTools Protocol), קוראים את ה-bundles ומפות המקור שלך, ומריצים סשנים מתוסרטים — והופכים את ה-JavaScript שאתה מגיש לשרטוט לשכפול. כל עסק שמגיש אפליקציית web חושף את קוד צד-הלקוח שלו.",
      "how.h2": "איך NoREA מגנה — שלוש שכבות",
      "how.c1.h3": "1 · זיהוי",
      "how.c1.p":
        "שומר דפדפן מסמן חיבור DevTools/CDP, אוטומציה (Playwright/Puppeteer), פגיעה בשלמות, ו<strong>טביעת אצבע מאומתת של REA</strong>. כל ניסיון מדווח ללוח שלך.",
      "how.c2.h3": "2 · הטעיה",
      "how.c2.p":
        "honeypot בצד השרת מגיש קוד <strong>דמה מנוטרל</strong> (עם canary tokens) לבקשות שמדורגות כניתוח — זיהוי התנהגותי שאינו בוטח ב-User-Agent, כך שזיוף כותרות רק מעלה את הציון.",
      "how.c3.h3": "3 · הגנה",
      "how.c3.p":
        "הלוגיקה החשובה רצה <strong>בצד השרת</strong> (הרמטית — REA לעולם לא רואה את האלגוריתם); קוד שחייב להישלח לדפדפן ניתן להדר ל-<strong>WASM</strong> (בינארי אטום).",
      "more.h2": "עוד דרכים שבהן היא מגנה",
      "more.c1.h3": "הוכחת עבודה",
      "more.c1.p":
        "גרום לגרידה המונית לשלם ב-CPU: לקוחות חשודים חייבים לפתור אתגר קטן לפני שיגיעו לנתיבים מוגנים.",
      "more.c2.h3": "Tarpit &amp; טביעת אצבע TLS",
      "more.c2.p":
        "האט בוטים שזוהו, וסַמֵּן <code>curl</code>/<code>python</code>/<code>scrapy</code> לפי לחיצת היד של ה-TLS (JA3) שלהם — לא רק לפי ה-User-Agent.",
      "more.c3.h3": "WebAssembly",
      "more.c3.p": "שלח לוגיקת צד-לקוח כבינארי WASM אטום במקום JavaScript קריא — הרבה יותר קשה להנדס לאחור.",
      "more.c4.h3": "מעקב אחר מדליפים",
      "more.c4.p":
        "הטבע סימן מים בלתי-נראה לכל צופה, סרוק קוד ציבורי לאיתור דליפות, וקבל התראת webhook כשמתקפות מזנקות.",
      "more.c5.h3": "נעילת דומיין",
      "more.c5.p":
        "סַמֵּן — ואפשר גם להשבית — את צד-הלקוח שלך כשהוא מאורח מחדש בדומיין שלא אישרת (אתר משוכפל).",
      "more.c6.h3": "הקשחה",
      "more.c6.p":
        "ערפל JavaScript שנשלח, קבע נעילת נכסים עם SRI, הגדר CSP מחמיר, והגש את ה-bundle האמיתי מוצפן — המפתח מגיע ללקוחות מאומתים בלבד.",
      "rea.h2": "אנחנו מכירים את REA",
      "rea.lead":
        "NoREA כוללת טביעות אצבע <strong>מאומתות מול הקוד הציבורי של REA</strong>, כל אחת מתועדת עם מידת ההתחמקות שלה:",
      "rea.li1":
        "<strong>אות שרת</strong> — מאחזר מפות-המקור של REA שולח <code>Accept: application/source-map+json</code> ייחודי, ללא cookie או referer. אף דפדפן אינו עושה זאת → כמעט-ודאי, קשה להתחמקות.",
      "rea.li2":
        "<strong>אות לקוח</strong> — פרופיל ה-Playwright שבברירת המחדל של REA (headless + <code>navigator.webdriver</code> + 1280×720 + UTC + reduced-motion…) הוא צירוף ייחודי.",
      "rea.li3":
        "<strong>אדפטיבי</strong> — יועץ AI אופציונלי לומד דפוסי תקיפה ומציע שינויי הגנה <em>תחומים</em> (אתה מאשר אותם).",
      "qs.h2": "התחלה מהירה",
      "qs.s1.h3": "הוסף את השומר לדפים שלך",
      "qs.s2.h3": "הוסף את ה-honeypot לשרת שלך",
      "qs.s3.h3": "שמור את תכשיטי הכתר הרחק מהלקוח",
      "qs.foot":
        'תיעוד מלא, פריסת Docker ולוח הניהול נמצאים ב<a href="https://github.com/diamondrubinny/Antirea" rel="noopener">מאגר שב-GitHub</a>.',
      "ai.h2": "התקן אותה עם סוכן AI",
      "ai.lead":
        "משתמש ב-<strong>Claude Code</strong>, <strong>Cursor</strong>, <strong>GitHub Copilot</strong> או כל סוכן קוד אחר? הדבק את ההנחיה הזו ותן לו לחבר את NoREA לפרויקט שלך:",
      "ai.tip":
        "טיפ: הפנה את הסוכן אל <code>README.md</code>, <code>docs/REA-SIGNATURES.md</code> ו-<code>docs/WASM.md</code> שבמאגר, ל-API המדויק.",
      "who.h2": "למי זה מיועד",
      "who.lead":
        "בעלי SaaS ותוכנה, סוכנויות וצוותי מוצר שמגישים אפליקציות web קנייניות ורוצים להפוך שכפול והנדסה לאחור ליקרים — ו<em>גלויים</em>. אירוח עצמי, מכבד פרטיות (לא נשמרים IP גולמיים), וחינמי תחת Apache-2.0.",
      "who.cta": "הגן על הקוד שלך →",
      "support.h2": "תמכו בפרויקט",
      "support.lead":
        "NoREA חינמית וקוד פתוח (Apache-2.0). אם היא עוזרת לך או לצוות שלך, תרומה קטנה שומרת אותה מתוחזקת ועצמאית. תודה.",
      "support.donate": "לתרומה עם PayPal",
      "support.scan": "סרקו לתרומה",
      "footer.tagline": "הגנת anti-REA לקוד",
      "footer.created":
        'נוצר על ידי <strong>Diamond Rubinny</strong> · Apache-2.0 · <a href="https://github.com/diamondrubinny/Antirea" rel="noopener">GitHub</a>',
      "footer.disclaimer":
        "NoREA היא תוכנה עצמאית; השם “REA” מוזכר רק כדי לתאר את כלי ההנדסה-לאחור ש-NoREA מסייעת להתגונן מפניהם.",
      "footer.donate": "תרומה",
      "footer.privacy": "פרטיות ומדיניות עוגיות",
      "footer.cookies": "הגדרות עוגיות",
      "lang.label": "שפה",
      "p.meta.title": "מדיניות פרטיות ועוגיות — NoREA",
      "p.meta.desc": "מדיניות פרטיות ועוגיות עבור אתר NoREA (Antirea).",
      "p.nav.home": "בית",
      "p.h1": "מדיניות פרטיות ועוגיות",
      "p.updated": "עודכן לאחרונה: 2026-11-06",
      "p.lead":
        "זוהי המדיניות עבור אתר השיווק <strong>norea.rubinny.net</strong> בלבד. תוכנת NoREA / Antirea שאתה מארח בעצמך כפופה למדיניות שלך.",
      "p.who.h2": "מי אנחנו",
      "p.who.p":
        "האתר מופעל על ידי Diamond Rubinny. לשאלות פרטיות, השתמש בפרטי הקשר שאתה מפרסם באתר הראשי שלך.",
      "p.collect.h2": "מה האתר אוסף",
      "p.collect.p1":
        "זהו אתר סטטי. הוא אינו מגדיר <strong>עוגיות אנליטיקה או שיווק</strong> כברירת מחדל. הוא משתמש בכמות קטנה של <strong>אחסון מקומי</strong> במכשירך למטרה הכרחית אחת בלבד: לזכור את בחירת ההסכמה שלך לעוגיות. המידע נשאר בדפדפן שלך ואינו נשלח אלינו או לצד שלישי.",
      "p.collect.p2":
        "יומני שרת סטנדרטיים (למשל כתובת IP, user-agent, חותמת זמן) עשויים להתעבד על ידי ספק האירוח לצורכי אבטחה ואמינות. אם תפעיל כלי אנליטיקה או שיווק בעתיד, תעד אותם כאן והתנה אותם בהסכמה (האתר כבר בנוי לכך).",
      "p.cookies.h2": "עוגיות וטכנולוגיות דומות",
      "p.th.name": "שם",
      "p.th.cat": "קטגוריה",
      "p.th.purpose": "מטרה",
      "p.th.ret": "זמן שמירה",
      "p.row.cat": "חיונית",
      "p.row.purpose": "שומר את בחירת ההסכמה שלך לעוגיות (אחסון מקומי).",
      "p.row.ret": "עד שתנקה אותו / תשתנה גרסת המדיניות.",
      "p.cookies.note":
        'קטגוריות לא-חיוניות (פונקציונלית, אנליטיקה, שיווק) <strong>כבויות כברירת מחדל</strong> ונטענות רק בהסכמתך. אפשר לשנות או למשוך הסכמה בכל עת: <a href="#" data-cc-open>פתיחת הגדרות עוגיות</a>.',
      "p.legal.h2": "בסיסים חוקיים (GDPR) והדין הישראלי",
      "p.legal.p":
        "כאשר חל ה-GDPR האירופי, עוגיות לא-חיוניות מסתמכות על <strong>הסכמתך</strong>; אחסון חיוני מסתמך על אינטרס לגיטימי / נחיצות לאספקת השירות. כאשר חל חוק הגנת הפרטיות הישראלי, אנו שואפים לאסוף את המינימום הנדרש ולהיות שקופים לגביו.",
      "p.rights.h2": "הזכויות שלך",
      "p.rights.p":
        'בכפוף לדין החל, אתה רשאי לבקש גישה, תיקון, מחיקה או הגבלה של המידע האישי שלך, ולמשוך הסכמה. מאחר שהאתר שומר הסכמה רק בדפדפן שלך, תוכל לממש משיכה ישירות דרך <a href="#" data-cc-open>הגדרות עוגיות</a> או על ידי ניקוי אחסון הדפדפן.',
      "p.third.h2": "צדדים שלישיים",
      "p.third.p":
        "האתר מתארח אצל ספק אירוח וקוד המקור שלו נמצא ב-GitHub. לא מוטמעים כברירת מחדל כלי אנליטיקה, פרסום, צ'אט או פיקסלים חברתיים של צד שלישי. הוסף כל כזה שתכניס למדיניות זו ולקטגוריות ההסכמה.",
      "p.back": "← חזרה לדף הבית",
    },

    es: {
      "meta.title": "NoREA — Detén la ingeniería inversa de tu código | protección anti-REA (Antirea)",
      "meta.desc":
        "NoREA (Antirea) es un conjunto de herramientas de código abierto para detectar, engañar y bloquear herramientas de ingeniería inversa como REA. Protege el código de tu sitio web, SaaS y app con honeypots, detección de CDP/DevTools, WASM y ejecución hermética del lado del servidor.",
      skip: "Saltar al contenido principal",
      "nav.how": "Cómo funciona",
      "nav.quickstart": "Inicio rápido",
      "nav.ai": "Agentes de IA",
      "nav.github": "GitHub ★",
      "hero.eyebrow": "Código abierto · Apache-2.0 · autoalojado",
      "hero.h1": 'Detén la <span class="accent">ingeniería inversa</span> de tu código.',
      "hero.lead":
        "<strong>NoREA</strong> (“no REA”) es un conjunto de herramientas listo para integrar que <strong>detecta, engaña y bloquea</strong> herramientas de ingeniería inversa — incluidas las basadas en CDP/DevTools como <strong>REA</strong> — y mantiene la lógica importante completamente fuera del cliente. Para sitios web, SaaS y apps.",
      "hero.cta1": "Empezar",
      "hero.cta2": "Ver en GitHub",
      "hero.honest":
        "Honesto por diseño: solo la ejecución del lado del servidor es hermética; las capas del lado del cliente disuaden, engañan e informan.",
      "hero.imgAlt":
        "Panel de control de NoREA que muestra intentos de ingeniería inversa por país, señal y huellas de REA",
      "problem.h2": "El problema",
      "problem.lead":
        "Las herramientas de ingeniería inversa como <strong>REA</strong> se conectan a un navegador (mediante el Chrome DevTools Protocol), leen tus bundles y source maps, y ejecutan sesiones con scripts — convirtiendo el JavaScript que entregas en un plano para clonar. Toda empresa que publica una app web expone su código de front-end.",
      "how.h2": "Cómo protege NoREA — tres capas",
      "how.c1.h3": "1 · Detectar",
      "how.c1.p":
        "Un guardián del navegador detecta la conexión de DevTools/CDP, la automatización (Playwright/Puppeteer), la manipulación de integridad y una <strong>huella de REA verificada</strong>. Cada intento se informa a tu panel.",
      "how.c2.h3": "2 · Engañar",
      "how.c2.p":
        "Un honeypot del lado del servidor entrega código <strong>señuelo inerte</strong> (con canary tokens) a las solicitudes puntuadas como análisis — detección por comportamiento que no confía en el User-Agent, así que falsificar cabeceras aumenta la puntuación.",
      "how.c3.h3": "3 · Proteger",
      "how.c3.p":
        "La lógica que importa se ejecuta <strong>en el servidor</strong> (hermética — REA nunca ve el algoritmo); el código que debe llegar al navegador puede compilarse a <strong>WASM</strong> (un binario opaco).",
      "more.h2": "Más formas de proteger",
      "more.c1.h3": "Prueba de trabajo",
      "more.c1.p":
        "Haz que el scraping masivo pague CPU: los clientes sospechosos deben resolver un pequeño desafío antes de alcanzar las rutas protegidas.",
      "more.c2.h3": "Tarpit y huella TLS",
      "more.c2.p":
        "Ralentiza los bots detectados y marca <code>curl</code>/<code>python</code>/<code>scrapy</code> por su handshake TLS (JA3) — no solo por el User-Agent.",
      "more.c3.h3": "WebAssembly",
      "more.c3.p":
        "Entrega la lógica del lado del cliente como un binario WASM opaco en lugar de JavaScript legible — mucho más difícil de revertir.",
      "more.c4.h3": "Rastreo de filtradores",
      "more.c4.p":
        "Marca de agua invisible para cada visitante, escaneo de código público en busca de filtraciones y alerta por webhook cuando los ataques se disparan.",
      "more.c5.h3": "Bloqueo de dominio",
      "more.c5.p":
        "Marca — y opcionalmente desactiva — tu front-end cuando se rehospeda en un dominio que no autorizaste (un sitio clonado).",
      "more.c6.h3": "Endurecimiento",
      "more.c6.p":
        "Ofusca el JavaScript entregado, fija los recursos con SRI, establece una CSP estricta y entrega el bundle real cifrado — la clave llega solo a clientes verificados.",
      "rea.h2": "Conocemos REA",
      "rea.lead":
        "NoREA incluye huellas <strong>verificadas contra el código público de REA</strong>, cada una documentada con su evasibilidad:",
      "rea.li1":
        "<strong>Señal de servidor</strong> — el descargador de source maps de REA envía un <code>Accept: application/source-map+json</code> distintivo, sin cookie ni referer. Ningún navegador hace esto → casi seguro, difícil de evadir.",
      "rea.li2":
        "<strong>Señal de cliente</strong> — el perfil de Playwright por defecto de REA (headless + <code>navigator.webdriver</code> + 1280×720 + UTC + reduced-motion…) es una combinación distintiva.",
      "rea.li3":
        "<strong>Adaptativo</strong> — un asesor de IA opcional aprende patrones de ataque y propone cambios de defensa <em>acotados</em> (tú los apruebas).",
      "qs.h2": "Inicio rápido",
      "qs.s1.h3": "Añade el guardián a tus páginas",
      "qs.s2.h3": "Añade el honeypot a tu servidor",
      "qs.s3.h3": "Mantén las joyas de la corona fuera del cliente",
      "qs.foot":
        'La documentación completa, el despliegue con Docker y el panel de control están en el <a href="https://github.com/diamondrubinny/Antirea" rel="noopener">repositorio de GitHub</a>.',
      "ai.h2": "Instálalo con un agente de IA",
      "ai.lead":
        "¿Usas <strong>Claude Code</strong>, <strong>Cursor</strong>, <strong>GitHub Copilot</strong> o cualquier agente de programación? Pega este prompt y deja que integre NoREA en tu proyecto:",
      "ai.tip":
        "Consejo: dirige al agente al <code>README.md</code>, <code>docs/REA-SIGNATURES.md</code> y <code>docs/WASM.md</code> del repo para las APIs exactas.",
      "who.h2": "Para quién es",
      "who.lead":
        "Dueños de SaaS y software, agencias y equipos de producto que publican apps web propietarias y quieren encarecer la clonación y la ingeniería inversa — y hacerlas <em>visibles</em>. Autoalojado, respetuoso con la privacidad (no se almacenan IP en bruto) y gratis bajo Apache-2.0.",
      "who.cta": "Protege tu código →",
      "support.h2": "Apoya este proyecto",
      "support.lead":
        "NoREA es gratis y de código abierto (Apache-2.0). Si te ayuda a ti o a tu equipo, una pequeña donación lo mantiene mantenido e independiente. Gracias.",
      "support.donate": "Donar con PayPal",
      "support.scan": "Escanea para donar",
      "footer.tagline": "protección de código anti-REA",
      "footer.created":
        'Creado por <strong>Diamond Rubinny</strong> · Apache-2.0 · <a href="https://github.com/diamondrubinny/Antirea" rel="noopener">GitHub</a>',
      "footer.disclaimer":
        "NoREA es software independiente; “REA” se menciona solo para describir las herramientas de ingeniería inversa contra las que NoREA ayuda a defenderse.",
      "footer.donate": "Donar",
      "footer.privacy": "Privacidad y cookies",
      "footer.cookies": "Ajustes de cookies",
      "lang.label": "Idioma",
      "p.meta.title": "Política de privacidad y cookies — NoREA",
      "p.meta.desc": "Política de privacidad y cookies del sitio web NoREA (Antirea).",
      "p.nav.home": "Inicio",
      "p.h1": "Política de privacidad y cookies",
      "p.updated": "Última actualización: 2026-11-06",
      "p.lead":
        "Esta es la política solo para el sitio web de marketing <strong>norea.rubinny.net</strong>. El software NoREA / Antirea que autoalojas se rige por tus propias políticas.",
      "p.who.h2": "Quiénes somos",
      "p.who.p":
        "Este sitio está operado por Diamond Rubinny. Para consultas de privacidad, usa los datos de contacto que publicas en tu sitio principal.",
      "p.collect.h2": "Qué recopila este sitio",
      "p.collect.p1":
        "Este es un sitio estático. No establece <strong>cookies de analítica ni de marketing</strong> de forma predeterminada. Usa una pequeña cantidad de <strong>almacenamiento local</strong> en tu dispositivo con un único fin estrictamente necesario: recordar tu elección de consentimiento de cookies. Esos datos permanecen en tu navegador y no se nos envían a nosotros ni a terceros.",
      "p.collect.p2":
        "Los registros estándar del servidor web (p. ej., dirección IP, user-agent, marca de tiempo) pueden ser procesados por el proveedor de alojamiento por seguridad y fiabilidad. Si habilitas herramientas de analítica o marketing en el futuro, documéntalas aquí y condiciónalas al consentimiento (el sitio ya está preparado para ello).",
      "p.cookies.h2": "Cookies y tecnologías similares",
      "p.th.name": "Nombre",
      "p.th.cat": "Categoría",
      "p.th.purpose": "Finalidad",
      "p.th.ret": "Conservación",
      "p.row.cat": "Esencial",
      "p.row.purpose": "Almacena tu elección de consentimiento de cookies (almacenamiento local).",
      "p.row.ret": "Hasta que la borres / cambie la versión de la política.",
      "p.cookies.note":
        'Las categorías no esenciales (funcional, analítica, marketing) están <strong>desactivadas de forma predeterminada</strong> y se cargan solo con tu consentimiento. Puedes cambiar o retirar el consentimiento en cualquier momento: <a href="#" data-cc-open>abrir ajustes de cookies</a>.',
      "p.legal.h2": "Bases legales (RGPD) y ley israelí",
      "p.legal.p":
        "Cuando se aplica el RGPD de la UE, las cookies no esenciales se basan en tu <strong>consentimiento</strong>; el almacenamiento esencial se basa en el interés legítimo / la necesidad de prestar el servicio. Cuando se aplica la Ley de Protección de la Privacidad de Israel, procuramos recopilar lo mínimo necesario y ser transparentes al respecto.",
      "p.rights.h2": "Tus derechos",
      "p.rights.p":
        'Con sujeción a la ley aplicable, puedes solicitar acceso, rectificación, supresión o limitación de tus datos personales, y retirar el consentimiento. Como este sitio almacena el consentimiento solo en tu navegador, puedes ejercer la retirada directamente mediante <a href="#" data-cc-open>ajustes de cookies</a> o borrando el almacenamiento de tu navegador.',
      "p.third.h2": "Terceros",
      "p.third.p":
        "El sitio está alojado por un proveedor de alojamiento y su código fuente está en GitHub. No se incrustan de forma predeterminada analíticas, publicidad, chat ni píxeles sociales de terceros. Añade a esta política y a las categorías de consentimiento cualquiera que introduzcas.",
      "p.back": "← Volver al inicio",
    },

    fr: {
      "meta.title": "NoREA — Stoppez la rétro-ingénierie de votre code | protection anti-REA (Antirea)",
      "meta.desc":
        "NoREA (Antirea) est une boîte à outils open source pour détecter, tromper et bloquer les outils de rétro-ingénierie comme REA. Protégez le code de votre site web, SaaS et application avec des honeypots, la détection CDP/DevTools, le WASM et une exécution hermétique côté serveur.",
      skip: "Aller au contenu principal",
      "nav.how": "Comment ça marche",
      "nav.quickstart": "Démarrage rapide",
      "nav.ai": "Agents IA",
      "nav.github": "GitHub ★",
      "hero.eyebrow": "Open source · Apache-2.0 · auto-hébergé",
      "hero.h1": 'Stoppez la <span class="accent">rétro-ingénierie</span> de votre code.',
      "hero.lead":
        "<strong>NoREA</strong> (“no REA”) est une boîte à outils prête à l’emploi qui <strong>détecte, trompe et bloque</strong> les outils de rétro-ingénierie — y compris ceux basés sur CDP/DevTools comme <strong>REA</strong> — et garde la logique importante entièrement hors du client. Pour sites web, SaaS et applications.",
      "hero.cta1": "Commencer",
      "hero.cta2": "Voir sur GitHub",
      "hero.honest":
        "Honnête par conception : seule l’exécution côté serveur est hermétique ; les couches côté client dissuadent, trompent et signalent.",
      "hero.imgAlt":
        "Panneau de contrôle NoREA montrant les tentatives de rétro-ingénierie par pays, signal et empreintes REA",
      "problem.h2": "Le problème",
      "problem.lead":
        "Les outils de rétro-ingénierie comme <strong>REA</strong> se connectent à un navigateur (via le Chrome DevTools Protocol), lisent vos bundles et source maps, et pilotent des sessions scriptées — transformant le JavaScript que vous livrez en plan de clonage. Toute entreprise qui publie une application web expose son code front-end.",
      "how.h2": "Comment NoREA protège — trois couches",
      "how.c1.h3": "1 · Détecter",
      "how.c1.p":
        "Un garde navigateur repère l’attache DevTools/CDP, l’automatisation (Playwright/Puppeteer), l’altération d’intégrité et une <strong>empreinte REA vérifiée</strong>. Chaque tentative est signalée à votre tableau de bord.",
      "how.c2.h3": "2 · Tromper",
      "how.c2.p":
        "Un honeypot côté serveur sert du code <strong>leurre inerte</strong> (avec canary tokens) aux requêtes jugées d’analyse — une détection comportementale qui ne fait pas confiance au User-Agent, donc falsifier les en-têtes augmente le score.",
      "how.c3.h3": "3 · Protéger",
      "how.c3.p":
        "La logique importante s’exécute <strong>côté serveur</strong> (hermétique — REA ne voit jamais l’algorithme) ; le code qui doit arriver au navigateur peut être compilé en <strong>WASM</strong> (un binaire opaque).",
      "more.h2": "D’autres façons de protéger",
      "more.c1.h3": "Preuve de travail",
      "more.c1.p":
        "Faites payer du CPU au scraping de masse : les clients suspects doivent résoudre un petit défi avant d’atteindre les routes protégées.",
      "more.c2.h3": "Tarpit et empreinte TLS",
      "more.c2.p":
        "Ralentissez les bots détectés et repérez <code>curl</code>/<code>python</code>/<code>scrapy</code> par leur handshake TLS (JA3) — pas seulement par le User-Agent.",
      "more.c3.h3": "WebAssembly",
      "more.c3.p":
        "Livrez la logique côté client sous forme de binaire WASM opaque plutôt que de JavaScript lisible — bien plus difficile à inverser.",
      "more.c4.h3": "Traçage des fuiteurs",
      "more.c4.p":
        "Filigranez chaque visiteur de façon invisible, scannez le code public à la recherche de fuites et recevez une alerte webhook quand les attaques s’intensifient.",
      "more.c5.h3": "Verrou de domaine",
      "more.c5.p":
        "Signalez — et désactivez au besoin — votre front-end quand il est réhébergé sur un domaine non autorisé (un site cloné).",
      "more.c6.h3": "Durcissement",
      "more.c6.p":
        "Obscurcissez le JavaScript livré, épinglez les ressources avec SRI, définissez une CSP stricte et livrez le vrai bundle chiffré — la clé n’atteint que les clients vérifiés.",
      "rea.h2": "Nous connaissons REA",
      "rea.lead":
        "NoREA fournit des empreintes <strong>vérifiées sur le code public de REA</strong>, chacune documentée avec son évitabilité :",
      "rea.li1":
        "<strong>Signal serveur</strong> — le récupérateur de source maps de REA envoie un <code>Accept: application/source-map+json</code> distinctif, sans cookie ni referer. Aucun navigateur ne fait cela → quasi certain, difficile à éviter.",
      "rea.li2":
        "<strong>Signal client</strong> — le profil Playwright par défaut de REA (headless + <code>navigator.webdriver</code> + 1280×720 + UTC + reduced-motion…) est une combinaison distinctive.",
      "rea.li3":
        "<strong>Adaptatif</strong> — un conseiller IA optionnel apprend les schémas d’attaque et propose des changements de défense <em>bornés</em> (que vous approuvez).",
      "qs.h2": "Démarrage rapide",
      "qs.s1.h3": "Ajoutez le garde à vos pages",
      "qs.s2.h3": "Ajoutez le honeypot à votre serveur",
      "qs.s3.h3": "Gardez les joyaux de la couronne hors du client",
      "qs.foot":
        'La documentation complète, le déploiement Docker et le panneau de contrôle se trouvent dans le <a href="https://github.com/diamondrubinny/Antirea" rel="noopener">dépôt GitHub</a>.',
      "ai.h2": "Installez-le avec un agent IA",
      "ai.lead":
        "Vous utilisez <strong>Claude Code</strong>, <strong>Cursor</strong>, <strong>GitHub Copilot</strong> ou un autre agent de code ? Collez cette instruction et laissez-le intégrer NoREA à votre projet :",
      "ai.tip":
        "Astuce : orientez l’agent vers le <code>README.md</code>, <code>docs/REA-SIGNATURES.md</code> et <code>docs/WASM.md</code> du dépôt pour les API exactes.",
      "who.h2": "À qui ça s’adresse",
      "who.lead":
        "Propriétaires de SaaS et de logiciels, agences et équipes produit qui publient des applications web propriétaires et veulent rendre le clonage et la rétro-ingénierie coûteux — et <em>visibles</em>. Auto-hébergé, respectueux de la vie privée (aucune IP brute stockée) et gratuit sous Apache-2.0.",
      "who.cta": "Protégez votre code →",
      "support.h2": "Soutenez ce projet",
      "support.lead":
        "NoREA est gratuit et open source (Apache-2.0). S’il vous aide, vous ou votre équipe, un petit don le garde maintenu et indépendant. Merci.",
      "support.donate": "Faire un don avec PayPal",
      "support.scan": "Scannez pour faire un don",
      "footer.tagline": "protection de code anti-REA",
      "footer.created":
        'Créé par <strong>Diamond Rubinny</strong> · Apache-2.0 · <a href="https://github.com/diamondrubinny/Antirea" rel="noopener">GitHub</a>',
      "footer.disclaimer":
        "NoREA est un logiciel indépendant ; « REA » n’est mentionné que pour décrire les outils de rétro-ingénierie contre lesquels NoREA aide à se défendre.",
      "footer.donate": "Faire un don",
      "footer.privacy": "Confidentialité et cookies",
      "footer.cookies": "Paramètres des cookies",
      "lang.label": "Langue",
      "p.meta.title": "Politique de confidentialité et de cookies — NoREA",
      "p.meta.desc": "Politique de confidentialité et de cookies du site web NoREA (Antirea).",
      "p.nav.home": "Accueil",
      "p.h1": "Politique de confidentialité et de cookies",
      "p.updated": "Dernière mise à jour : 2026-11-06",
      "p.lead":
        "Cette politique concerne uniquement le site vitrine <strong>norea.rubinny.net</strong>. Le logiciel NoREA / Antirea que vous auto-hébergez est régi par vos propres politiques.",
      "p.who.h2": "Qui nous sommes",
      "p.who.p":
        "Ce site est exploité par Diamond Rubinny. Pour toute question de confidentialité, utilisez les coordonnées publiées sur votre site principal.",
      "p.collect.h2": "Ce que ce site collecte",
      "p.collect.p1":
        "Ceci est un site statique. Il ne dépose <strong>aucun cookie d’analyse ou de marketing</strong> par défaut. Il utilise une petite quantité de <strong>stockage local</strong> sur votre appareil dans un seul but strictement nécessaire : mémoriser votre choix de consentement aux cookies. Ces données restent dans votre navigateur et ne nous sont pas transmises, ni à un tiers.",
      "p.collect.p2":
        "Les journaux standard du serveur web (p. ex. adresse IP, user-agent, horodatage) peuvent être traités par l’hébergeur à des fins de sécurité et de fiabilité. Si vous activez des outils d’analyse ou de marketing à l’avenir, documentez-les ici et conditionnez-les au consentement (le site est déjà prévu pour cela).",
      "p.cookies.h2": "Cookies et technologies similaires",
      "p.th.name": "Nom",
      "p.th.cat": "Catégorie",
      "p.th.purpose": "Finalité",
      "p.th.ret": "Conservation",
      "p.row.cat": "Essentiel",
      "p.row.purpose": "Mémorise votre choix de consentement aux cookies (stockage local).",
      "p.row.ret": "Jusqu’à ce que vous l’effaciez / que la version de la politique change.",
      "p.cookies.note":
        'Les catégories non essentielles (fonctionnel, analyse, marketing) sont <strong>désactivées par défaut</strong> et ne se chargent qu’avec votre consentement. Vous pouvez modifier ou retirer votre consentement à tout moment : <a href="#" data-cc-open>ouvrir les paramètres des cookies</a>.',
      "p.legal.h2": "Bases légales (RGPD) et droit israélien",
      "p.legal.p":
        "Lorsque le RGPD de l’UE s’applique, les cookies non essentiels reposent sur votre <strong>consentement</strong> ; le stockage essentiel repose sur l’intérêt légitime / la nécessité de fournir le service. Lorsque la loi israélienne sur la protection de la vie privée s’applique, nous visons à collecter le minimum nécessaire et à être transparents.",
      "p.rights.h2": "Vos droits",
      "p.rights.p":
        'Sous réserve du droit applicable, vous pouvez demander l’accès, la rectification, l’effacement ou la limitation de vos données personnelles, et retirer votre consentement. Comme ce site ne stocke le consentement que dans votre navigateur, vous pouvez exercer le retrait directement via les <a href="#" data-cc-open>paramètres des cookies</a> ou en effaçant le stockage de votre navigateur.',
      "p.third.h2": "Tiers",
      "p.third.p":
        "Le site est hébergé par un hébergeur et son code source se trouve sur GitHub. Aucun service tiers d’analyse, de publicité, de chat ou de pixel social n’est intégré par défaut. Ajoutez à cette politique et aux catégories de consentement tout service que vous introduisez.",
      "p.back": "← Retour à l’accueil",
    },

    de: {
      "meta.title": "NoREA — Stoppen Sie das Reverse-Engineering Ihres Codes | anti-REA-Schutz (Antirea)",
      "meta.desc":
        "NoREA (Antirea) ist ein Open-Source-Toolkit, um Reverse-Engineering-Tools wie REA zu erkennen, zu täuschen und zu blockieren. Schützen Sie den Quellcode Ihrer Website, SaaS und App mit Honeypots, CDP/DevTools-Erkennung, WASM und hermetischer serverseitiger Ausführung.",
      skip: "Zum Hauptinhalt springen",
      "nav.how": "So funktioniert es",
      "nav.quickstart": "Schnellstart",
      "nav.ai": "KI-Agenten",
      "nav.github": "GitHub ★",
      "hero.eyebrow": "Open Source · Apache-2.0 · selbst gehostet",
      "hero.h1": 'Stoppen Sie das <span class="accent">Reverse-Engineering</span> Ihres Codes.',
      "hero.lead":
        "<strong>NoREA</strong> („no REA“) ist ein sofort einsetzbares Toolkit, das Reverse-Engineering-Tools <strong>erkennt, täuscht und blockiert</strong> — darunter CDP/DevTools-basierte wie <strong>REA</strong> — und die wichtige Logik vollständig vom Client fernhält. Für Websites, SaaS und Apps.",
      "hero.cta1": "Loslegen",
      "hero.cta2": "Auf GitHub ansehen",
      "hero.honest":
        "Ehrlich konzipiert: Nur die serverseitige Ausführung ist hermetisch; die clientseitigen Schichten schrecken ab, täuschen und melden.",
      "hero.imgAlt":
        "NoREA-Steuerungskonsole mit Reverse-Engineering-Versuchen nach Land, Signal und REA-Fingerabdrücken",
      "problem.h2": "Das Problem",
      "problem.lead":
        "Reverse-Engineering-Tools wie <strong>REA</strong> hängen sich an einen Browser (über das Chrome DevTools Protocol), lesen Ihre Bundles und Source Maps und steuern skriptgesteuerte Sitzungen — und machen aus dem ausgelieferten JavaScript eine Blaupause zum Klonen. Jedes Unternehmen, das eine Web-App ausliefert, legt seinen Front-End-Code offen.",
      "how.h2": "Wie NoREA schützt — drei Schichten",
      "how.c1.h3": "1 · Erkennen",
      "how.c1.p":
        "Ein Browser-Guard meldet DevTools/CDP-Verbindung, Automatisierung (Playwright/Puppeteer), Integritätsmanipulation und einen <strong>verifizierten REA-Fingerabdruck</strong>. Jeder Versuch wird an Ihr Dashboard gemeldet.",
      "how.c2.h3": "2 · Täuschen",
      "how.c2.p":
        "Ein serverseitiger Honeypot liefert <strong>inerten Köder</strong>-Code (mit Canary-Tokens) an Anfragen, die als Analyse eingestuft werden — eine verhaltensbasierte Erkennung, die dem User-Agent nicht vertraut, sodass gefälschte Header den Score erhöhen.",
      "how.c3.h3": "3 · Schützen",
      "how.c3.p":
        "Die wichtige Logik läuft <strong>serverseitig</strong> (hermetisch — REA sieht den Algorithmus nie); Code, der in den Browser muss, kann zu <strong>WASM</strong> (einem undurchsichtigen Binär) kompiliert werden.",
      "more.h2": "Weitere Schutzmechanismen",
      "more.c1.h3": "Proof of Work",
      "more.c1.p":
        "Lassen Sie Massen-Scraping CPU kosten: Verdächtige Clients müssen eine kleine Aufgabe lösen, bevor sie geschützte Routen erreichen.",
      "more.c2.h3": "Tarpit &amp; TLS-Fingerabdruck",
      "more.c2.p":
        "Bremsen Sie erkannte Bots aus und erkennen Sie <code>curl</code>/<code>python</code>/<code>scrapy</code> an ihrem TLS-Handshake (JA3) — nicht nur am User-Agent.",
      "more.c3.h3": "WebAssembly",
      "more.c3.p":
        "Liefern Sie clientseitige Logik als undurchsichtiges WASM-Binär statt als lesbares JavaScript — deutlich schwerer rückzuentwickeln.",
      "more.c4.h3": "Verräter-Rückverfolgung",
      "more.c4.p":
        "Versehen Sie jeden Betrachter unsichtbar mit einem Wasserzeichen, scannen Sie öffentlichen Code auf Lecks und erhalten Sie eine Webhook-Warnung, wenn Angriffe ansteigen.",
      "more.c5.h3": "Domain-Sperre",
      "more.c5.p":
        "Melden Sie — und schalten Sie bei Bedarf ab — Ihr Front-End, wenn es auf einer nicht autorisierten Domain neu gehostet wird (eine geklonte Website).",
      "more.c6.h3": "Härtung",
      "more.c6.p":
        "Verschleiern Sie ausgeliefertes JavaScript, sichern Sie Assets mit SRI, setzen Sie eine strikte CSP und liefern Sie das echte Bundle verschlüsselt — der Schlüssel erreicht nur verifizierte Clients.",
      "rea.h2": "Wir kennen REA",
      "rea.lead":
        "NoREA liefert Fingerabdrücke, die <strong>gegen den öffentlichen Quellcode von REA verifiziert</strong> sind, jeder mit seiner Umgehbarkeit dokumentiert:",
      "rea.li1":
        "<strong>Serversignal</strong> — der Source-Map-Abrufer von REA sendet ein markantes <code>Accept: application/source-map+json</code> ohne Cookie oder Referer. Kein Browser tut das → nahezu sicher, schwer zu umgehen.",
      "rea.li2":
        "<strong>Clientsignal</strong> — das Standard-Playwright-Profil von REA (headless + <code>navigator.webdriver</code> + 1280×720 + UTC + reduced-motion …) ist eine markante Kombination.",
      "rea.li3":
        "<strong>Adaptiv</strong> — ein optionaler KI-Berater lernt Angriffsmuster und schlägt <em>begrenzte</em> Abwehränderungen vor (die Sie genehmigen).",
      "qs.h2": "Schnellstart",
      "qs.s1.h3": "Fügen Sie den Guard zu Ihren Seiten hinzu",
      "qs.s2.h3": "Fügen Sie den Honeypot zu Ihrem Server hinzu",
      "qs.s3.h3": "Halten Sie die Kronjuwelen vom Client fern",
      "qs.foot":
        'Vollständige Dokumentation, Docker-Deployment und die Steuerungskonsole finden Sie im <a href="https://github.com/diamondrubinny/Antirea" rel="noopener">GitHub-Repository</a>.',
      "ai.h2": "Mit einem KI-Agenten installieren",
      "ai.lead":
        "Sie nutzen <strong>Claude Code</strong>, <strong>Cursor</strong>, <strong>GitHub Copilot</strong> oder einen anderen Coding-Agenten? Fügen Sie diesen Prompt ein und lassen Sie ihn NoREA in Ihr Projekt einbinden:",
      "ai.tip":
        "Tipp: Verweisen Sie den Agenten für die genauen APIs auf <code>README.md</code>, <code>docs/REA-SIGNATURES.md</code> und <code>docs/WASM.md</code> im Repo.",
      "who.h2": "Für wen es ist",
      "who.lead":
        "SaaS- und Software-Inhaber, Agenturen und Produktteams, die proprietäre Web-Apps ausliefern und Klonen sowie Reverse-Engineering teuer — und <em>sichtbar</em> — machen wollen. Selbst gehostet, datenschutzfreundlich (keine rohen IPs gespeichert) und kostenlos unter Apache-2.0.",
      "who.cta": "Schützen Sie Ihren Code →",
      "support.h2": "Unterstützen Sie dieses Projekt",
      "support.lead":
        "NoREA ist kostenlos und Open Source (Apache-2.0). Wenn es Ihnen oder Ihrem Team hilft, hält eine kleine Spende es gepflegt und unabhängig. Danke.",
      "support.donate": "Mit PayPal spenden",
      "support.scan": "Zum Spenden scannen",
      "footer.tagline": "anti-REA-Codeschutz",
      "footer.created":
        'Erstellt von <strong>Diamond Rubinny</strong> · Apache-2.0 · <a href="https://github.com/diamondrubinny/Antirea" rel="noopener">GitHub</a>',
      "footer.disclaimer":
        "NoREA ist unabhängige Software; „REA“ wird nur genannt, um die Reverse-Engineering-Werkzeuge zu beschreiben, gegen die NoREA zu schützen hilft.",
      "footer.donate": "Spenden",
      "footer.privacy": "Datenschutz & Cookies",
      "footer.cookies": "Cookie-Einstellungen",
      "lang.label": "Sprache",
      "p.meta.title": "Datenschutz- & Cookie-Richtlinie — NoREA",
      "p.meta.desc": "Datenschutz- und Cookie-Richtlinie für die NoREA-(Antirea-)Website.",
      "p.nav.home": "Startseite",
      "p.h1": "Datenschutz- & Cookie-Richtlinie",
      "p.updated": "Zuletzt aktualisiert: 2026-11-06",
      "p.lead":
        "Dies ist die Richtlinie nur für die Marketing-Website <strong>norea.rubinny.net</strong>. Die von Ihnen selbst gehostete NoREA-/Antirea-Software unterliegt Ihren eigenen Richtlinien.",
      "p.who.h2": "Wer wir sind",
      "p.who.p":
        "Diese Website wird von Diamond Rubinny betrieben. Für Datenschutzfragen verwenden Sie die auf Ihrer Hauptseite veröffentlichten Kontaktdaten.",
      "p.collect.h2": "Was diese Website erfasst",
      "p.collect.p1":
        "Dies ist eine statische Website. Sie setzt standardmäßig <strong>keine Analyse- oder Marketing-Cookies</strong>. Sie nutzt eine kleine Menge <strong>lokalen Speicher</strong> auf Ihrem Gerät für genau einen zwingend erforderlichen Zweck: Ihre Cookie-Einwilligung zu merken. Diese Daten bleiben in Ihrem Browser und werden weder an uns noch an Dritte gesendet.",
      "p.collect.p2":
        "Standard-Webserver-Logs (z. B. IP-Adresse, User-Agent, Zeitstempel) können vom Hosting-Anbieter zu Sicherheits- und Zuverlässigkeitszwecken verarbeitet werden. Wenn Sie künftig Analyse- oder Marketing-Tools aktivieren, dokumentieren Sie sie hier und machen Sie sie von der Einwilligung abhängig (die Website ist dafür bereits vorbereitet).",
      "p.cookies.h2": "Cookies & ähnliche Technologien",
      "p.th.name": "Name",
      "p.th.cat": "Kategorie",
      "p.th.purpose": "Zweck",
      "p.th.ret": "Speicherdauer",
      "p.row.cat": "Essenziell",
      "p.row.purpose": "Speichert Ihre Cookie-Einwilligung (lokaler Speicher).",
      "p.row.ret": "Bis Sie ihn löschen / die Richtlinienversion sich ändert.",
      "p.cookies.note":
        'Nicht-essenzielle Kategorien (funktional, Analyse, Marketing) sind <strong>standardmäßig deaktiviert</strong> und werden nur mit Ihrer Einwilligung geladen. Sie können die Einwilligung jederzeit ändern oder widerrufen: <a href="#" data-cc-open>Cookie-Einstellungen öffnen</a>.',
      "p.legal.h2": "Rechtsgrundlagen (DSGVO) & israelisches Recht",
      "p.legal.p":
        "Wo die EU-DSGVO gilt, stützen sich nicht-essenzielle Cookies auf Ihre <strong>Einwilligung</strong>; essenzieller Speicher stützt sich auf berechtigtes Interesse / die Erforderlichkeit zur Erbringung des Dienstes. Wo das israelische Datenschutzgesetz gilt, erheben wir möglichst nur das Nötigste und legen dies transparent dar.",
      "p.rights.h2": "Ihre Rechte",
      "p.rights.p":
        'Vorbehaltlich des geltenden Rechts können Sie Auskunft, Berichtigung, Löschung oder Einschränkung Ihrer personenbezogenen Daten verlangen und die Einwilligung widerrufen. Da diese Website die Einwilligung nur in Ihrem Browser speichert, können Sie den Widerruf direkt über die <a href="#" data-cc-open>Cookie-Einstellungen</a> oder durch Löschen Ihres Browserspeichers ausüben.',
      "p.third.h2": "Dritte",
      "p.third.p":
        "Die Website wird von einem Hosting-Anbieter gehostet und ihr Quellcode liegt auf GitHub. Standardmäßig sind keine Analyse-, Werbe-, Chat- oder Social-Pixel von Dritten eingebunden. Nehmen Sie alle von Ihnen eingeführten in diese Richtlinie und in die Einwilligungskategorien auf.",
      "p.back": "← Zurück zur Startseite",
    },

    ar: {
      "meta.title": "NoREA — أوقف الهندسة العكسية لشفرتك | حماية anti-REA (Antirea)",
      "meta.desc":
        "NoREA (Antirea) هي مجموعة أدوات مفتوحة المصدر لاكتشاف أدوات الهندسة العكسية مثل REA وخداعها وحظرها. احمِ شفرة موقعك وتطبيق SaaS والتطبيق باستخدام مصائد honeypot، واكتشاف CDP/DevTools، وWASM، والتنفيذ المحكم من جهة الخادم.",
      skip: "تخطَّ إلى المحتوى الرئيسي",
      "nav.how": "كيف يعمل",
      "nav.quickstart": "بدء سريع",
      "nav.ai": "وكلاء الذكاء الاصطناعي",
      "nav.github": "GitHub ★",
      "hero.eyebrow": "مفتوح المصدر · Apache-2.0 · استضافة ذاتية",
      "hero.h1": 'أوقف <span class="accent">الهندسة العكسية</span> لشفرتك.',
      "hero.lead":
        "<strong>NoREA</strong> (“no REA”) هي مجموعة أدوات جاهزة للدمج <strong>تكتشف وتخدع وتحظر</strong> أدوات الهندسة العكسية — بما فيها المعتمدة على CDP/DevTools مثل <strong>REA</strong> — وتبقي المنطق المهم بعيدًا عن العميل تمامًا. للمواقع وتطبيقات SaaS والتطبيقات.",
      "hero.cta1": "ابدأ الآن",
      "hero.cta2": "عرض على GitHub",
      "hero.honest":
        "صادق بالتصميم: التنفيذ من جهة الخادم وحده محكم؛ أما طبقات جهة العميل فتردع وتخدع وتُبلّغ.",
      "hero.imgAlt": "لوحة تحكم NoREA تعرض محاولات الهندسة العكسية حسب الدولة والإشارة وبصمات REA",
      "problem.h2": "المشكلة",
      "problem.lead":
        "ترتبط أدوات الهندسة العكسية مثل <strong>REA</strong> بالمتصفح (عبر Chrome DevTools Protocol)، وتقرأ الحِزم وخرائط المصدر لديك، وتدير جلسات مبرمَجة — محوِّلةً شفرة JavaScript التي تطرحها إلى مخطط للاستنساخ. كل شركة تطرح تطبيق ويب تكشف شفرة الواجهة الأمامية لديها.",
      "how.h2": "كيف تحمي NoREA — ثلاث طبقات",
      "how.c1.h3": "1 · الاكتشاف",
      "how.c1.p":
        "يرصد حارس المتصفح ارتباط DevTools/CDP، والأتمتة (Playwright/Puppeteer)، والعبث بالسلامة، و<strong>بصمة REA مُتحقَّق منها</strong>. وتُبلَّغ كل محاولة إلى لوحتك.",
      "how.c2.h3": "2 · الخداع",
      "how.c2.p":
        "يقدّم honeypot من جهة الخادم شفرة <strong>طُعم خاملة</strong> (مع canary tokens) للطلبات المصنَّفة كتحليل — اكتشاف سلوكي لا يثق في User-Agent، لذا فإن تزوير الترويسات يرفع النتيجة.",
      "how.c3.h3": "3 · الحماية",
      "how.c3.p":
        "يُنفَّذ المنطق المهم <strong>من جهة الخادم</strong> (محكم — لا ترى REA الخوارزمية أبدًا)؛ أما الشفرة التي يجب أن تصل إلى المتصفح فيمكن تصريفها إلى <strong>WASM</strong> (ثنائي معتم).",
      "more.h2": "طرق إضافية للحماية",
      "more.c1.h3": "إثبات العمل",
      "more.c1.p":
        "اجعل السحب الجماعي يكلّف وحدة المعالجة: على العملاء المشبوهين حلّ تحدٍّ صغير قبل الوصول إلى المسارات المحمية.",
      "more.c2.h3": "Tarpit وبصمة TLS",
      "more.c2.p":
        "أبطئ الروبوتات المكتشَفة، وميّز <code>curl</code>/<code>python</code>/<code>scrapy</code> من مصافحة TLS (JA3) الخاصة بها — لا من User-Agent وحده.",
      "more.c3.h3": "WebAssembly",
      "more.c3.p":
        "اطرح منطق جهة العميل كثنائي WASM معتم بدلًا من JavaScript قابل للقراءة — أصعب بكثير في العكس.",
      "more.c4.h3": "تعقّب المُسرِّبين",
      "more.c4.p":
        "ضع علامة مائية غير مرئية لكل مُشاهِد، وافحص الشفرة العامة بحثًا عن التسريبات، واحصل على تنبيه webhook عند تصاعد الهجمات.",
      "more.c5.h3": "قفل النطاق",
      "more.c5.p":
        "ميّز — ويمكن أيضًا تعطيل — واجهتك الأمامية عند إعادة استضافتها على نطاق لم تصرّح به (موقع مستنسخ).",
      "more.c6.h3": "التحصين",
      "more.c6.p":
        "شوّش JavaScript المطروح، وثبّت الأصول بـ SRI، واضبط سياسة CSP صارمة، وقدّم الحِزمة الحقيقية مشفّرة — ولا يصل المفتاح إلا للعملاء المُتحقَّق منهم.",
      "rea.h2": "نحن نعرف REA",
      "rea.lead":
        "تتضمن NoREA بصمات <strong>مُتحقَّقًا منها مقابل شفرة REA العامة</strong>، كل منها موثّقة بمدى قابلية التحايل عليها:",
      "rea.li1":
        "<strong>إشارة الخادم</strong> — يرسل جالب خرائط المصدر في REA ترويسة <code>Accept: application/source-map+json</code> مميّزة دون cookie أو referer. لا متصفح يفعل ذلك ← شبه مؤكد، يصعب التحايل عليه.",
      "rea.li2":
        "<strong>إشارة العميل</strong> — ملف Playwright الافتراضي في REA (headless + <code>navigator.webdriver</code> + 1280×720 + UTC + reduced-motion…) تركيبة مميّزة.",
      "rea.li3":
        "<strong>تكيّفي</strong> — مستشار ذكاء اصطناعي اختياري يتعلّم أنماط الهجوم ويقترح تغييرات دفاع <em>محدودة</em> (أنت تعتمدها).",
      "qs.h2": "بدء سريع",
      "qs.s1.h3": "أضف الحارس إلى صفحاتك",
      "qs.s2.h3": "أضف honeypot إلى خادمك",
      "qs.s3.h3": "أبقِ جواهر التاج بعيدًا عن العميل",
      "qs.foot":
        'التوثيق الكامل ونشر Docker ولوحة التحكم موجودة في <a href="https://github.com/diamondrubinny/Antirea" rel="noopener">مستودع GitHub</a>.',
      "ai.h2": "ثبّتها عبر وكيل ذكاء اصطناعي",
      "ai.lead":
        "تستخدم <strong>Claude Code</strong> أو <strong>Cursor</strong> أو <strong>GitHub Copilot</strong> أو أي وكيل برمجة؟ الصق هذا الموجّه ودعه يدمج NoREA في مشروعك:",
      "ai.tip":
        "نصيحة: وجّه الوكيل إلى <code>README.md</code> و<code>docs/REA-SIGNATURES.md</code> و<code>docs/WASM.md</code> في المستودع للحصول على واجهات البرمجة الدقيقة.",
      "who.h2": "لمن هذا",
      "who.lead":
        "مالكو SaaS والبرمجيات، والوكالات، وفرق المنتجات الذين يطرحون تطبيقات ويب خاصة ويريدون جعل الاستنساخ والهندسة العكسية مكلفَين — و<em>مرئيَّين</em>. استضافة ذاتية، يحترم الخصوصية (لا تُخزَّن عناوين IP الخام)، ومجاني بموجب Apache-2.0.",
      "who.cta": "احمِ شفرتك →",
      "support.h2": "ادعم هذا المشروع",
      "support.lead":
        "NoREA مجانية ومفتوحة المصدر (Apache-2.0). إن ساعدتك أو ساعدت فريقك، فإن تبرعًا صغيرًا يُبقيها مصانة ومستقلة. شكرًا لك.",
      "support.donate": "تبرّع عبر PayPal",
      "support.scan": "امسح للتبرّع",
      "footer.tagline": "حماية الشفرة anti-REA",
      "footer.created":
        'أنشأها <strong>Diamond Rubinny</strong> · Apache-2.0 · <a href="https://github.com/diamondrubinny/Antirea" rel="noopener">GitHub</a>',
      "footer.disclaimer":
        "NoREA برنامج مستقل؛ ويُذكر “REA” فقط لوصف أدوات الهندسة العكسية التي تساعد NoREA على الدفاع ضدها.",
      "footer.donate": "تبرّع",
      "footer.privacy": "الخصوصية وملفات تعريف الارتباط",
      "footer.cookies": "إعدادات ملفات تعريف الارتباط",
      "lang.label": "اللغة",
      "p.meta.title": "سياسة الخصوصية وملفات تعريف الارتباط — NoREA",
      "p.meta.desc": "سياسة الخصوصية وملفات تعريف الارتباط لموقع NoREA (Antirea).",
      "p.nav.home": "الرئيسية",
      "p.h1": "سياسة الخصوصية وملفات تعريف الارتباط",
      "p.updated": "آخر تحديث: 2026-11-06",
      "p.lead":
        "هذه السياسة خاصة بموقع التسويق <strong>norea.rubinny.net</strong> فقط. أما برنامج NoREA / Antirea الذي تستضيفه بنفسك فيخضع لسياساتك الخاصة.",
      "p.who.h2": "من نحن",
      "p.who.p":
        "يُدار هذا الموقع بواسطة Diamond Rubinny. لأسئلة الخصوصية، استخدم بيانات التواصل التي تنشرها على موقعك الرئيسي.",
      "p.collect.h2": "ما الذي يجمعه هذا الموقع",
      "p.collect.p1":
        "هذا موقع ثابت. ولا يضبط <strong>أي ملفات تعريف ارتباط للتحليلات أو التسويق</strong> افتراضيًا. يستخدم قدرًا صغيرًا من <strong>التخزين المحلي</strong> على جهازك لغرض ضروري واحد فقط: تذكّر اختيارك بشأن الموافقة على ملفات تعريف الارتباط. تبقى هذه البيانات في متصفحك ولا تُرسَل إلينا أو إلى أي طرف ثالث.",
      "p.collect.p2":
        "قد تعالِج سجلات خادم الويب القياسية (مثل عنوان IP وUser-Agent والطابع الزمني) جهةُ الاستضافة لأغراض الأمان والموثوقية. إذا فعّلت أدوات تحليلات أو تسويق مستقبلًا، فوثّقها هنا واجعلها مشروطة بالموافقة (الموقع مُهيّأ لذلك بالفعل).",
      "p.cookies.h2": "ملفات تعريف الارتباط والتقنيات المشابهة",
      "p.th.name": "الاسم",
      "p.th.cat": "الفئة",
      "p.th.purpose": "الغرض",
      "p.th.ret": "مدة الاحتفاظ",
      "p.row.cat": "أساسي",
      "p.row.purpose": "يخزّن اختيارك بشأن الموافقة على ملفات تعريف الارتباط (تخزين محلي).",
      "p.row.ret": "حتى تمسحه / تتغيّر نسخة السياسة.",
      "p.cookies.note":
        'الفئات غير الأساسية (وظيفية، تحليلات، تسويق) <strong>معطّلة افتراضيًا</strong> ولا تُحمَّل إلا بموافقتك. يمكنك تغيير الموافقة أو سحبها في أي وقت: <a href="#" data-cc-open>افتح إعدادات ملفات تعريف الارتباط</a>.',
      "p.legal.h2": "الأسس القانونية (GDPR) والقانون الإسرائيلي",
      "p.legal.p":
        "حيثما ينطبق نظام GDPR الأوروبي، تعتمد ملفات تعريف الارتباط غير الأساسية على <strong>موافقتك</strong>؛ ويعتمد التخزين الأساسي على المصلحة المشروعة / ضرورة تقديم الخدمة. وحيثما ينطبق قانون حماية الخصوصية الإسرائيلي، نسعى لجمع الحد الأدنى اللازم وللشفافية بشأنه.",
      "p.rights.h2": "حقوقك",
      "p.rights.p":
        'مع مراعاة القانون المعمول به، يمكنك طلب الوصول إلى بياناتك الشخصية أو تصحيحها أو حذفها أو تقييدها، وسحب الموافقة. وبما أن هذا الموقع يخزّن الموافقة في متصفحك فقط، يمكنك ممارسة السحب مباشرةً عبر <a href="#" data-cc-open>إعدادات ملفات تعريف الارتباط</a> أو بمسح تخزين متصفحك.',
      "p.third.h2": "الأطراف الثالثة",
      "p.third.p":
        "يستضيف الموقعَ مزوّدُ استضافة، وشفرته المصدرية على GitHub. ولا تُضمَّن افتراضيًا أي أدوات تحليلات أو إعلانات أو دردشة أو بكسلات اجتماعية لأطراف ثالثة. أضِف أيًّا تُدخِله إلى هذه السياسة وإلى فئات الموافقة.",
      "p.back": "← العودة إلى الرئيسية",
    },
  };

  function pick() {
    try {
      var u = new URLSearchParams(location.search).get("lang");
      if (u && DICT[u]) return u;
    } catch (e) {
      /* ignore */
    }
    try {
      var s = localStorage.getItem("norea_lang");
      if (s && DICT[s]) return s;
    } catch (e) {
      /* ignore */
    }
    var n = (navigator.language || "en").slice(0, 2).toLowerCase();
    return DICT[n] ? n : "en";
  }

  function apply(lang) {
    var d = DICT[lang] || DICT.en;
    document.documentElement.lang = lang;
    document.documentElement.dir = RTL[lang] ? "rtl" : "ltr";

    var nodes = document.querySelectorAll("[data-i18n]");
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      var k = el.getAttribute("data-i18n");
      var v = d[k] != null ? d[k] : DICT.en[k];
      if (v != null) el.innerHTML = v;
    }
    var alts = document.querySelectorAll("[data-i18n-alt]");
    for (var j = 0; j < alts.length; j++) {
      var a = alts[j];
      var ak = a.getAttribute("data-i18n-alt");
      var av = d[ak] != null ? d[ak] : DICT.en[ak];
      if (av != null) a.setAttribute("alt", av);
    }
    // Attribute values (e.g. <meta name="description" data-i18n-content="...">).
    var conts = document.querySelectorAll("[data-i18n-content]");
    for (var m = 0; m < conts.length; m++) {
      var cel = conts[m];
      var ck = cel.getAttribute("data-i18n-content");
      var cv = d[ck] != null ? d[ck] : DICT.en[ck];
      if (cv != null) cel.setAttribute("content", cv);
    }

    // Page declares its own title/description keys on <html> so each page
    // (index, privacy) swaps its own, sharing one dictionary file.
    var root = document.documentElement;
    var tKey = root.getAttribute("data-i18n-title");
    if (tKey && (d[tKey] != null || DICT.en[tKey] != null)) {
      document.title = d[tKey] != null ? d[tKey] : DICT.en[tKey];
    }
    var dKey = root.getAttribute("data-i18n-desc");
    var md = document.querySelector('meta[name="description"]');
    if (md && dKey && (d[dKey] != null || DICT.en[dKey] != null)) {
      md.setAttribute("content", d[dKey] != null ? d[dKey] : DICT.en[dKey]);
    }

    var sel = document.getElementById("lang-select");
    if (sel) {
      sel.value = lang;
      sel.setAttribute("aria-label", d["lang.label"] || "Language");
    }

    // Broadcast so other components (e.g. the cookie banner) can re-localize.
    window.noreaLang = lang;
    try {
      window.dispatchEvent(new CustomEvent("norea:langchange", { detail: { lang: lang, dir: root.dir } }));
    } catch (e) {
      /* ignore */
    }
  }

  function init() {
    var sel = document.getElementById("lang-select");
    if (sel && !sel.options.length) {
      for (var i = 0; i < LANGS.length; i++) {
        var c = LANGS[i];
        var o = document.createElement("option");
        o.value = c;
        o.textContent = NAMES[c];
        sel.appendChild(o);
      }
      sel.addEventListener("change", function () {
        var l = sel.value;
        try {
          localStorage.setItem("norea_lang", l);
        } catch (e) {
          /* ignore */
        }
        apply(l);
        try {
          var url = new URL(location.href);
          url.searchParams.set("lang", l);
          history.replaceState(null, "", url);
        } catch (e) {
          /* ignore */
        }
      });
    }
    apply(pick());
  }

  if (document.readyState !== "loading") init();
  else document.addEventListener("DOMContentLoaded", init);
})();
