# Antirea (עברית)

**הגנה drop-in מפני הנדסה-לאחור ושכפול, עם פאנל ניהול שמראה מי ניסה, מאיפה, וכמה.**

> התיעוד הרשמי הוא באנגלית: [`README.md`](./README.md). זהו תקציר בעברית.

## ⚠️ חוזה אמת — מה הרמטי ומה לא

| מה מגנים | CDP/REA יכול להנדס? | התשובה |
|---|---|---|
| **לוגיקה/אלגוריתם קנייני** | **לא** — אם לא בלקוח, אין מה לקרוא | ✅ **`@antirea/secure-fn` — ריצה בשרת. הרמטי.** |
| קוד שחייב להישלח ללקוח (UI) | כן, בסוף | ⚠️ זיהוי + honeypot + מנוע התנהגותי. **מייקר, לא חומה.** |

**אין טכניקת צד-לקוח שהופכת JavaScript שנשלח לדפדפן לבלתי-ניתן-להנדסה.** ההבטחה ההרמטית היחידה היא ריצה בשרת. כל השאר = הרתעה, זיהוי ודיווח.

## חבילות

- **`@antirea/secure-fn`** — הליבה ההרמטית. פונקציות קנייניות רצות בשרת בלבד.
- `@antirea/honeypot` — middleware: זיהוי התנהגותי (IP, קצב, תזמון, אי-יציבות header) + הגשת decoy. ברירת מחדל Shadow.
- `@antirea/guard` — ספריית דפדפן: מזהה DevTools/CDP/אוטומציה ומדווחת.
- `@antirea/collector` — API + GeoIP + SQLite + פאנל ניהול רב-לשוני.

## התחלה מהירה

1. **collector + פאנל:** `npm install`, ואז ב-`packages/collector`: צור `.env` עם `IP_SALT` ו-`ADMIN_TOKEN` (ראה `.env.example`), `npm run build && npm start`, פתח `http://localhost:8080/`.
2. **honeypot בשרת שלך:**
   ```ts
   app.use(honeypot({ siteId: "my-site", protect: [/\.js$/, /\.map$/], mode: "shadow",
     reportUrl: "https://collector/api/events", allowlist: { verifyReverseDns: true } }));
   ```
3. **guard בדפים:** תגית `<script src="antirea-guard.iife.js" data-site-id=... data-endpoint=...>`.
4. **לוגיקה קניינית — הרמטית:** `createSecureFnRouter` בשרת, `createSecureClient().invoke(...)` בלקוח.

## פאנל ניהול

סטטיסטיקות חיות, "מקורות מובילים", והגדרות הגנה חיות: הפעלה/כיבוי, Shadow/Live, סף זיהוי, רשימות Allow/Block IP, ו-Site key. השינויים נמשכים ע"י ה-honeypot תוך ~30 שניות ללא redeploy. בורר שפה (כולל RTL לעברית/ערבית).

## זיהוי התנהגותי — עמיד לזיוף header

המנוע **לא סומך על headers של הלקוח**. מנקד לפי: velocity, סדירות תזמון (CV נמוך), קצב מהיר מדי, דפוס קצירה (assets בלי navigations), ו**אי-יציבות header** (אותו IP עם זהויות שונות → זיוף → מעלה ניקוד). זיוף ה-header פועל נגד התוקף.

**כנות:** זו הרתעה סטטיסטית. scraper איטי בזהות אחת יכול להישאר מתחת לסף. ללוגיקה שחייבת להישאר סודית — `secure-fn`.

## פרטיות

לא נשמר IP גולמי — רק מדינה + `sha256(ip+salt)`. איסוף מינימלי. Retention אוטומטי. **מחייב מדיניות פרטיות ובדיקה משפטית.**

## מגבלות

קוד-לקוח לא ניתן להפוך לבלתי-קריא (רק `secure-fn` הרמטי) · זיהוי התנהגותי סטטיסטי (Shadow כברירת מחדל) · CDP עוקף הגנות-לקוח · state התנהגותי per-instance (לסקייל: Redis) · רישוי GeoLite2 — בדיקה.

## רישיון

ראה [`LICENSE`](./LICENSE).
