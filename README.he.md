<div dir="rtl">

# Antirea / NoREA (עברית)

**הגנה drop-in מפני הנדסה-לאחור ושכפול קוד — עם פאנל ניהול שמראה מי ניסה, מאיפה, וכמה.**

> התיעוד המלא הוא באנגלית: [`README.md`](./README.md). זהו תקציר בעברית.
> אתר הפרויקט (6 שפות): [norea.rubinny.net](https://norea.rubinny.net)

## ⚠️ חוזה אמת — מה הרמטי ומה לא

| מה מגנים | CDP/REA יכול להנדס? | התשובה |
|---|---|---|
| **לוגיקה/אלגוריתם קנייני** | **לא** — אם לא נשלח ללקוח, אין מה לקרוא | ✅ **`@antirea/secure-fn` — ריצה בשרת. הרמטי.** |
| קוד שחייב להישלח ללקוח (UI) | כן, בסופו של דבר | ⚠️ זיהוי + honeypot + מנוע התנהגותי. **מייקר ומרתיע — לא חומה.** |

**אין טכניקת צד-לקוח שהופכת JavaScript שנשלח לדפדפן לבלתי-ניתן-להנדסה.** ההבטחה ההרמטית היחידה היא ריצה בשרת. כל השאר = הרתעה, הטעיה, זיהוי ודיווח.

## חבילות (8)

| חבילה | תפקיד |
|---|---|
| **`@antirea/secure-fn`** | **הליבה ההרמטית.** פונקציות קנייניות רצות בשרת בלבד; הלקוח שולח קלט ומקבל פלט. |
| `@antirea/honeypot` | Middleware ל-Express: זיהוי התנהגותי (IP, קצב, תזמון, אי-יציבות header) + הגשת קוד-פיתיון. ברירת מחדל Shadow. |
| `@antirea/guard` | ספריית דפדפן: מזהה DevTools/CDP/אוטומציה ו-REA, ומדווחת. |
| `@antirea/challenge` | **Proof-of-work** — גורם לגרידה המונית "לשלם" ב-CPU; tarpit וזיהוי TLS (JA3). |
| `@antirea/harden` | הקשחת קוד-לקוח: SRI/CSP/כותרות אבטחה, ערפול, אספקת bundle מוצפן, **נעילת דומיין**. |
| `@antirea/watermark` | **איתור מדליפים**: סימן-מים לכל צופה, סריקת דליפות ב-GitHub, התראות webhook על זינוק תקיפות. |
| `@antirea/adaptive` | לומדת מתקיפות ומציעה שינויי הגנה תחומים. AI אופציונלי (מפתח שלך); הצעה בלבד כברירת מחדל. |
| `@antirea/collector` | API קליטה + GeoIP + SQLite + **פאנל ניהול ב-20 שפות** (RTL לעברית, ערבית ופרסית). |

## התחלה מהירה

דורש **Node.js 22+** (מומלץ 24 LTS).

1. **collector + פאנל:**
   ```bash
   npm install
   npm run build            # בונה את כל החבילות (ה-collector תלוי ב-adaptive ו-watermark)
   cd packages/collector && cp .env.example .env
   # הגדר ב-.env ערכים אקראיים חזקים ל-IP_SALT ול-ADMIN_TOKEN (לפחות 32 תווים)
   npm start                # ואז פתח http://localhost:8080/
   ```
2. **honeypot בשרת שלך:**
   ```ts
   app.use(honeypot({ siteId: "my-site", protect: [/\.js$/, /\.map$/], mode: "shadow",
     reportUrl: "https://collector/api/events", allowlist: { verifyReverseDns: true } }));
   ```
3. **guard בדפים:** `<script src="antirea-guard.iife.js" data-site-id="..." data-endpoint="...">`
4. **לוגיקה קניינית — הרמטית:** `createSecureFnRouter` בשרת, `createSecureClient().invoke(...)` בלקוח.

> מאחורי reverse proxy: הגדר `TRUST_PROXY` ל**מספר** ה-proxies שלפני ה-collector (`true` = 1).
> רק ה-hop הזה ב-`X-Forwarded-For` נאמן — לקוח לא יכול לזייף IP כדי לעקוף הגבלות קצב.

## פריסה

- **Docker:** `docker compose up --build` — רץ על Node 24 כמשתמש לא-מורשה (`node`), הנתונים בווליום `/data`.
- **Windows Server:** כ-Windows Service — ראה [`packages/collector/windows/README.md`](./packages/collector/windows/README.md).

## פאנל ניהול

סטטיסטיקות חיות, מקורות מובילים, והגדרות הגנה חיות: הפעלה/כיבוי, Shadow/Live, סף זיהוי, רשימות Allow/Block IP ו-Site key. ה-honeypot מושך שינויים תוך ~30 שניות ללא redeploy. **20 שפות** עם בורר מיידי.

## זיהוי התנהגותי — עמיד לזיוף header

המנוע **לא סומך על headers של הלקוח**. מנקד לפי velocity, סדירות תזמון, קצב, דפוס קצירה ו**אי-יציבות header** (אותו IP עם זהויות מתחלפות → זיוף → ניקוד גבוה יותר). זיוף ה-header פועל נגד התוקף.

**כנות:** זו הרתעה סטטיסטית. scraper איטי בזהות אחת יכול להישאר מתחת לסף. ללוגיקה שחייבת להישאר סודית — `secure-fn`.

## אבטחה ופרטיות

- לא נשמר IP גולמי — רק מדינה + גיבוב מומלח (`sha256(salt|ip)`). איסוף מינימלי ומחיקה אוטומטית (retention).
- גישת ניהול: השוואת טוקן constant-time, הגבלת ניסיונות כושלים, ו-audit log לפעולות רגישות (ללא סודות וללא IP גולמי).
- **מי שמפעיל את ה-collector באתר שלו** אחראי למדיניות הפרטיות שלו ולבדיקה משפטית מול השימוש הספציפי (חוק הגנת הפרטיות / תיקון 13, ואם רלוונטי GDPR).

## מגבלות

קוד-לקוח לא ניתן להפוך לבלתי-קריא (רק `secure-fn` הרמטי) · הזיהוי ההתנהגותי סטטיסטי (Shadow כברירת מחדל) · CDP עוקף הגנות-לקוח · state התנהגותי per-instance (לסקייל אופקי נדרש store משותף כמו Redis) · רישוי GeoLite2 לשימוש מסחרי — דורש בדיקה.

## יוצר וקרדיט

נוצר על ידי **Diamond Rubinny**. בכל העתקה או נגזרת יש לשמור את הודעת הקרדיט ואת קובץ [`NOTICE`](./NOTICE) (Apache-2.0 §4).

## רישיון

Apache-2.0 — ראה [`LICENSE`](./LICENSE).

</div>
