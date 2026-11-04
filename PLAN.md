# Antirea — Code Protection & Reverse-Engineering Intelligence

> **מסמך תכנון. טיוטה טכנית — מחייב בדיקה משפטית (פרטיות/GDPR) לפני פרודקשן.**

## 1. מטרת המוצר (Value)

מערכת נגד הנדסה-לאחור (anti-RE) שכל אתר/מערכת/אפליקציה יכולים "לשתול" (drop-in), ומספקת:

1. **הקשחה + הרתעה** בצד הלקוח מפני ניתוח קוד (DevTools / CDP / כלי אוטומציה כמו Playwright/Puppeteer — מסלול הניתוח של כלים כמו REA דרך הדפדפן).
2. **מודיעין (Telemetry):** כל ניסיון ניתוח מדווח לשרת.
3. **Dashboard:** כמה ניסיונות, מאיזו מדינה, אילו סימנים (signals), ציר-זמן, ואילו עמודים.

## 2. האמת ההנדסית (מגבלות מחייבות)

- **אין הגנת צד-לקוח מוחלטת.** כל קוד שנשלח לדפדפן ניתן לקריאה. אנו **מאטים, מרתיעים ומזהים** — לא "חוסמים" הרמטית.
- כלי כמו REA נצמד ל-Chrome שהמשתמש **עצמו** הפעיל (CDP על `--remote-debugging-port`). התוקף הוא בעל-הבית במכונה שלו ויכול לנטרל קוד הגנה. לכן:
  - **ההגנה האמיתית על IP = לא לשלוח אותו ללקוח.** לוגיקה קניינית → שרת מאחורי API.
  - שכבת הלקוח = הקשחה + מודיעין (הערך: *לדעת* שמנתחים אותך, ממי ומאיפה).
- **לא מכנים שום רכיב "חוסם REA".** זו תהיה הבטחת שווא.

## 3. ארכיטקטורה

```
packages/
  guard/       → ספריית לקוח נייד (IIFE ל-<script> + ESM ל-npm). מזהה ומדווח.
  honeypot/    → middleware שרת (Express/connect). מנקד בקשות ל-assets, מגיש decoy
                 לבקשות "ניתוח", מדווח ל-collector. ברירת מחדל: Shadow Mode (תיעוד בלבד).
  collector/   → Backend API: קולט אירועים, מעשיר ב-GeoIP, שומר ב-SQLite, מגיש Dashboard.
```

### Honeypot / Deception (שרת)

- **למה בשרת ולא בלקוח:** REA דרך CDP קורא מקור ישירות מהמנוע ועוקף JS. honeypot של לקוח עובד רק מול מסלול Playwright/fetch. honeypot של שרת עובד מול קצירת bundles ללא הרצת JS.
- **ניקוד בקשה:** headless UA, `navigator.webdriver`-markers בבקשה, היעדר header-ים של דפדפן אמיתי (Accept/Sec-Fetch), דפוס קצירה (בקשת `.js` בלי בקשות ל-assets נלווים), קצב.
- **Decoy:** JS תקין תחבירית, ללא לוגיקה קניינית, עם ערכי-פיתיון ייחודיים (canary) כדי לזהות אם ה-decoy דלף/שוכפל.
- **Shadow Mode (ברירת מחדל):** רק מתעד "מי היה נלכד". **Live Mode:** מגיש decoy בפועל. מעבר ל-Live רק אחרי tuning.
- **Allowlist חובה:** בוטים לגיטימיים (Googlebot/Bingbot — אימות reverse-DNS), כתובות מוכרות, כדי למנוע נזק ל-SEO ולמשתמשים.
- **Canary tokens:** כל decoy מכיל מזהה ייחודי; אם הוא צץ "בטבע" → ראיה לשכפול, מוצג ב-Dashboard.

זרימה:
```
[אתר הלקוח + antirea-guard] --(sendBeacon JSON)--> [collector /api/events]
                                                        |-- GeoIP (country only)
                                                        |-- hash(IP+salt)
                                                        |-- SQLite
[Dashboard] --(/api/stats, /api/events)--> [collector] --> גרפים RTL נגישים
```

## 4. החלטות טכנולוגיות וחלופות

| רכיב | בחירה | למה | חלופות / מגבלות |
|---|---|---|---|
| שפה | TypeScript | טיפוסים, תחזוקה | — |
| בילד guard | Vite (lib mode) | IIFE+ESM בקלות | Rollup/esbuild ישירות |
| Backend | Node + Express | סטנדרטי, נייד | Fastify (מהיר יותר) |
| DB | better-sqlite3 | קובץ יחיד, סינכרוני, אפס-תשתית | Postgres לסקייל גדול |
| GeoIP | geoip-lite | אופליין, ללא API חיצוני | MaxMind GeoIP2 (דיוק גבוה) — **רישוי GeoLite2 מחייב בדיקה לשימוש מסחרי** |
| Charts | SVG/CSS ידני | אפס תלות, CSP-friendly, נגיש | Chart.js (עשיר יותר, CSP מורכב) |

## 5. אבטחה, פרטיות, נגישות

### אבטחה
- Collector: Rate limiting, הגבלת payload size, ולידציה מלאה של כל שדה, CORS מוגדר, headers (CSP/HSTS/X-Frame-Options).
- Dashboard מאחורי אימות (טוקן admin ב-ENV) — אין חשיפת מודיעין בפומבי.
- אין סודות בקוד; הכל ב-ENV.

### פרטיות (GDPR / חוק הגנת הפרטיות IL)
- **לא נשמר IP גולמי.** נגזרת ממנו *מדינה* בלבד, ונשמר `sha256(ip + SALT)` לספירת ייחודיים.
- guard אוסף מינימום: סוג אירוע, שמות signals, path (ללא query כברירת מחדל), UA, שפה, גודל מסך, timezone, sessionId אקראי לא-מתמשך.
- Retention: ברירת מחדל 90 יום, מחיקה אוטומטית (מחייב אישור מדיניות).
- **טבלת מידע אישי + מדיניות פרטיות — טיוטות, מחייבות בדיקה משפטית.**

### נגישות (WCAG 2.1 AA + ת"י 5568)
- Dashboard: RTL, HTML סמנטי, ניווט מקלדת, ניגודיות, טבלאות עם scope, גרפים עם חלופה טקסטואלית.
- guard במצב אגרסיבי: ברירת מחדל **כבוי** — עצירת אפליקציה פוגעת במשתמשים לגיטימיים/נגישות.

## 6. סימני זיהוי (Detection Signals)

- **DevTools:** timing של `debugger`, getter-trap על `console.log`, הפרש `outerWidth-innerWidth`.
- **Automation (Playwright/Puppeteer):** `navigator.webdriver`, `HeadlessChrome` ב-UA, היעדר `window.chrome`, חוסר עקביות `plugins/languages`, אי-התאמת Permissions API, שרידי `cdc_`/`__playwright`.
- **Integrity / anti-tamper:** בדיקת `Function.prototype.toString`, זיהוי hooking.
- **Console lockdown** בפרודקשן.

כל signal מתועד עם **מגבלת עקיפה** בקוד (כנות הנדסית).

## 6.1 פתרון CDP

**ההבחנה המכרעת:** CDP קורא את מה שהמנוע מחזיק. אם האלגוריתם לא בלקוח — אין מה לקרוא.

### הפתרון ההרמטי ללוגיקה: `packages/secure-fn`
הפונקציות הקנייניות רצות **רק בשרת** (`createSecureFnRouter`). הלקוח (`createSecureClient`) שולח input ומקבל output. REA רואה רק תעבורת רשת, לא את הקוד. סביב ה-API: session token חתום HMAC (סוד לא עוזב את השרת), nonce נגד replay, rate-limit, ודיווח אנומליות ל-Dashboard נגד דגימת-התנהגות המונית. **מגן על האלגוריתם; לא על ה-input/output הגלוי למורשה.**

### ולקוד שחייב להיות בלקוח (UI) — 3 שכבות שמייקרות (לא הרמטיות)
REA נצמד ל-Chrome שהמשתמש הפעיל וקורא מקור ישירות מהמנוע — עוקף JS. **אין חסימה מוחלטת לקוד בלקוח.** שלוש שכבות:

1. **זיהוי (client, `detectors/cdp.ts`):**
   - `debugger`-timing: REA ב-passive מפעיל דומיין Debugger ו*לא* מדכא pauses → השהיה נמדדת (הסיגנל החזק).
   - `Error.stack` getter-trap + `RegExp.toString`-trap: console של CDP קורא אותם בעת רינדור preview.
2. **אספקה מותנית-אטסטציה (`protected.ts` + honeypot):** המודול הקנייני לא ב-bundle. הלקוח מביא אותו ב-`fetch` עם header `X-Antirea-Attest` (תוצאת probe + nonce). השרת: probe נקי → אמיתי; CDP/ניקוד-אוטומציה → **decoy**. השרת **לא סומך** על הלקוח — מנקד גם עצמאית.
3. **ארכיטקטורה (ההגנה המוחלטת היחידה):** לוגיקה קריטית בשרת (API); מה שחייב בלקוח → **WASM** (אין source קריא; CDP רואה בינארי מהודר בלבד).

**מגבלות כנות:** blackboxing / כיבוי "pause on debugger" מנטרל את מלכודת ה-timing; header האטסטציה ניתן לזיוף (`cdp:false`). מכאן החשיבות של ניקוד-שרת עצמאי + nonce + WASM. זו העלאת-עלות ותפיסת ברירת-המחדל, לא חומה.

## 7. שלבי עבודה

- [x] שלב 0: תכנון (מסמך זה)
- [ ] שלב 1: `packages/guard` — detectors + reporter + build
- [ ] שלב 2: `packages/collector` — API + DB + GeoIP + אבטחה
- [ ] שלב 3: Dashboard (RTL, נגיש)
- [ ] שלב 4: README, `.env.example`, בדיקות, Checklist לפרודקשן

## 8. סיכונים ונושאים לבדיקה מקצועית

1. **משפטי:** שמירת UA+מדינה+hash(IP) = מידע אישי. מחייב מדיניות פרטיות, בסיס חוקי (אינטרס לגיטימי?), ואולי הסכמה. **בדיקת עו"ד.**
2. **רישוי GeoLite2** לשימוש מסחרי — **בדיקה.**
3. **False positives:** הרחבות דפדפן/כלי נגישות עלולים להיראות כאוטומציה. דרוש tuning.
4. **עקיפה:** תוקף מתוחכם עם CDP עוקף את כל שכבת הלקוח. זו הרתעה, לא חומה.
