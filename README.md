# Antirea

מערכת הגנה נגד הנדסה-לאחור (anti-RE) + מודיעין על ניסיונות ניתוח קוד, עם Dashboard.

> **אזהרה הנדסית מחייבת:** אין הגנת צד-לקוח מוחלטת. כל קוד שנשלח לדפדפן ניתן לקריאה.
> המערכת **מאטה, מרתיעה ומזהה** — היא **לא "חוסמת" הרמטית**. ההגנה היחידה המוחלטת
> על קוד קנייני היא **לא לשלוח אותו ללקוח** (לוגיקה קריטית בשרת). ראה `PLAN.md §2`.

## מה יש כאן

| חבילה | תפקיד |
|---|---|
| `packages/secure-fn` | **הפתרון ל-CDP:** ריצת לוגיקה קניינית **בשרת** בלבד. הלקוח שולח input ומקבל output. ✅ נבדק (6/6). |
| `packages/guard` | ספריית לקוח: מזהה DevTools/CDP/אוטומציה ומדווחת. `<script>` או npm. |
| `packages/honeypot` | Middleware שרת: מגיש **decoy** לבקשות שמזוהות כניתוח. ברירת מחדל: **Shadow**. |
| `packages/collector` | API לקליטת אירועים + GeoIP + SQLite + **Dashboard** (RTL, נגיש). |
| `examples/protected-site` | דוגמה רצה מקצה לקצה. |

## דרישות

- Node.js ≥ 20
- `better-sqlite3` ו-`geoip-lite` מתקמפלים בהתקנה (native). דרוש toolchain בסיסי.

## התקנה

```bash
npm install
npm run build:guard         # בונה את ה-guard ל-dist/
```

## הרצת ה-collector + Dashboard

```bash
cd packages/collector
cp .env.example .env
# צור סודות:
node -e "console.log('IP_SALT='+require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log('ADMIN_TOKEN='+require('crypto').randomBytes(32).toString('hex'))"
# הדבק אותם ל-.env, ואז:
npm run build && npm start
```

- API קליטה: `POST http://localhost:8080/api/events`
- Dashboard: `http://localhost:8080/` (הזן את ה-`ADMIN_TOKEN`).

## שימוש ב-guard באתר

```html
<script src="/path/antirea-guard.iife.js"
        data-site-id="my-site"
        data-endpoint="https://collector.example.com/api/events"
        data-mode="silent"></script>
```

או כמודול:

```ts
import { initGuard } from "@antirea/guard";
initGuard({ siteId: "my-site", endpoint: "https://collector.example.com/api/events" });
```

מצבים: `silent` (ברירת מחדל, מומלץ) · `obstruct` (נועל console) · `aggressive` (עוצר אפליקציה — **פוגע בנגישות, opt-in בלבד**).

## שימוש ב-honeypot בשרת האתר

```ts
import express from "express";
import { honeypot } from "@antirea/honeypot";

const app = express();
app.use(honeypot({
  siteId: "my-site",
  protect: [/^\/assets\/app\.[a-f0-9]+\.js$/, /\.map$/],
  mode: "shadow",                 // התחל ב-shadow, עבור ל-"live" אחרי tuning
  threshold: 0.7,
  reportUrl: "https://collector.example.com/api/events",
  allowlist: { verifyReverseDns: true },   // לפרודקשן
}));
app.use(express.static("public"));
```

**תמיד להתחיל ב-Shadow Mode** — המערכת רק מתעדת מי *הייתה* נלכד, בלי לשבור משתמשים. עוברים ל-`live` רק אחרי שרואים בנתונים שאין false positives.

## הרצת הדוגמה

```bash
# טרמינל 1: collector (כמו למעלה)
# טרמינל 2:
npm run build:guard
HONEYPOT_MODE=shadow COLLECTOR=http://localhost:8080/api/events node examples/protected-site/server.mjs
# פתח http://localhost:3000, ואז בדוק את ה-Dashboard
```

## בדיקות ידניות

1. **guard:** פתח את הדף, פתח DevTools → צפה באירוע ב-Dashboard.
2. **honeypot shadow:** `curl -A "HeadlessChrome" http://localhost:3000/assets/app.js` → מקבל קוד אמיתי, אבל נרשם `would_decoy`.
3. **honeypot live:** הפעל `HONEYPOT_MODE=live` → אותו `curl` מקבל **decoy** עם canary.
4. **allowlist:** `curl -A "Googlebot" ...` → לא נלכד.
5. **unique:** רענן מכמה IP → "מקורות ייחודיים" עולה.

## פתרון CDP

### ההבחנה שקובעת הכול

| מה מגנים | CDP יכול להנדס? | פתרון |
|---|---|---|
| **לוגיקה/אלגוריתם קנייני** (הערך האמיתי) | **לא** — הקוד לא בלקוח | ✅ **ריצה בשרת (`@antirea/secure-fn`). הרמטי.** |
| קוד שחייב להישלח ללקוח (UI) | כן, בסוף | WASM + obfuscation + אספקה מותנית (רק מייקר) |

### הפתרון ההרמטי: `@antirea/secure-fn`

הלוגיקה הקניינית **רצה רק בשרת**. הלקוח שולח input ומקבל output. REA/CDP רואה `{x:2} → {result:2691}` ברשת — **לעולם לא את הנוסחה, כי היא לא בלקוח.** אין קוד להנדס.

```ts
// server (האלגוריתם נשאר כאן לנצח)
import express from "express";
import { createSecureFnRouter } from "@antirea/secure-fn";
const app = express();
app.use("/secure", createSecureFnRouter({
  secret: process.env.SECUREFN_SECRET,   // random חזק מ-env
  reportUrl: "https://collector.example.com/api/events",
  maxInvokesPerMin: 60,                  // spike של scraper → מדווח ל-Dashboard
  functions: {
    pricing: (args) => ({ result: args.x * 1337 + 17 }), // סוד
  },
}));
```

```ts
// client (אפס לוגיקה קניינית, אפס סוד)
import { createSecureClient } from "@antirea/secure-fn/client";
const api = createSecureClient({ endpoint: "/secure" });
const { result } = await api.invoke("pricing", { x: 2 });
```

הגנות סביב ה-API כדי שלא יוכלו "לדגום התנהגות" בכמות: **session token חתום ב-HMAC** (הסוד לא עוזב את השרת), **nonce נגד replay**, **rate-limit לכל session**, ו**דיווח אנומליות** ל-Dashboard.

**מה זה לא פותר:** מי שמורשה לקרוא ל-API רואה input/output. זה מגן על ה*אלגוריתם*, לא על ה*התנהגות הגלויה*. לכן ה-rate-limit + הדיווח.

### ולקוד שחייב להיות בלקוח — 3 שכבות (מייקרות, לא הרמטיות)

כלי שנצמד לדפדפן דרך CDP קורא מקור ישירות מהמנוע ועוקף JS. **אין חסימה מוחלטת לקוד שנשלח ללקוח** — שלוש שכבות שמעלות עלות ותופסות את ברירת-המחדל:

1. **זיהוי** (`detectors/cdp.ts`): `debugger`-timing (REA ב-passive לא מדכא pauses), `Error.stack` getter-trap, `RegExp.toString`-trap.
2. **אספקה מותנית-אטסטציה:** המודול הקנייני לא ב-bundle. מביאים אותו דרך `importProtected`:

   ```ts
   import { importProtected } from "@antirea/guard";
   const mod = await importProtected("core", { endpoint: "/__p/" });
   // תחת CDP/אוטומציה — השרת מחזיר decoy אינרטי במקום הקוד האמיתי.
   ```

   בשרת: הוסף את מסלול האספקה ל-`protect` של ה-honeypot (למשל `/^\/__p\//`), והגש את המודול האמיתי מתיקייה **לא-ציבורית** אחרי ה-middleware. ה-honeypot קורא את header `X-Antirea-Attest` **וגם** מנקד עצמאית (לא סומך על הלקוח).
   > דרוש CSP שמתיר `blob:` ב-`script-src` עבור `importProtected`. דרוש `<meta name="antirea-nonce" content="...">` לכל דף.
3. **ארכיטקטורה (ההגנה המוחלטת היחידה):** לוגיקה קריטית ב-API; מה שחייב בלקוח → **WASM**.

**מגבלות:** blackboxing / כיבוי "pause on debugger" מנטרל את מלכודת ה-timing; `X-Antirea-Attest` ניתן לזיוף. לכן ניקוד-שרת עצמאי + nonce + WASM הם מה שמחזיק.

### בדיקת מסלול CDP

- `curl -H 'X-Antirea-Attest: {"cdp":true}' http://localhost:3000/__p/core` במצב `live` → מחזיר **decoy**.
- אותו `curl` עם `{"cdp":false}` וללא סימני-אוטומציה אחרים → מחזיר קוד **אמיתי** (ממחיש שזיוף header *כן* אפשרי → ראה "מגבלות").

## פרטיות (GDPR / חוק הגנת הפרטיות IL) — טיוטה, מחייב בדיקה משפטית

- **לא נשמר IP גולמי.** נגזרת מדינה בלבד + `sha256(ip+salt)` לספירת ייחודיים.
- נאסף מינימום: סוג אירוע, שמות signals, path (ללא query כברירת מחדל), UA, שפה, מסך, timezone.
- Retention אוטומטי (`RETENTION_DAYS`, ברירת מחדל 90). אשר מול מדיניות הפרטיות שלך.
- **חובה:** מדיניות פרטיות + בסיס חוקי לעיבוד (אינטרס לגיטימי/הסכמה) — **בדיקת עו"ד**.

## מגבלות וסיכונים (כנות הנדסית)

- **CDP:** נלכד **חלקית** — ה-probe תופס את ההתנהגות הדיפולטיבית/passive (ראה "פתרון CDP"), אך תוקף שעושה blackboxing או מזייף את ה-header עוקף. ההגנה המוחלטת: לוגיקה בשרת + WASM.
- **False positives:** הרחבות/כלי נגישות/בוטים עלולים להיראות כאוטומציה. לכן Shadow כברירת מחדל.
- **רישוי GeoLite2** (geoip-lite) לשימוש מסחרי — **בדיקה משפטית**.
- כל signal מתועד בקוד עם הערת-עקיפה.

## רישיון

ראה `LICENSE`.
