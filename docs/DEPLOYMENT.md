# دليل التشغيل والنشر - ZM Academy

## 1) المتطلبات
- Cloudflare Worker مع D1 binding باسم `DB`
- مستودع GitHub Pages للواجهة الأمامية
- أسرار Worker: `GITHUB_STORAGE_TOKEN`, `ADMIN_SETUP_KEY`, `AI_API_KEY` (اختياري)

## 2) قاعدة البيانات D1
1. تأكد من وجود قاعدة `zm-academy-db` وربطها في `wrangler.toml`.
2. نفّذ ملفات migrations بالترتيب:
   - `migrations/001_platform_core.sql`
   - أي migrations إضافية.
3. يمكن التنفيذ عبر Wrangler:
   ```bash
   wrangler d1 execute zm-academy-db --file=./migrations/001_platform_core.sql
   ```

## 3) Cloudflare Worker
1. حدّث `wrangler.toml` بالقيم الصحيحة.
2. اضبط الأسرار:
   ```bash
   wrangler secret put GITHUB_STORAGE_TOKEN
   wrangler secret put ADMIN_SETUP_KEY
   wrangler secret put AI_API_KEY
   ```
3. انشر:
   ```bash
   wrangler deploy
   ```

## 4) الواجهة الأمامية
- ارفع ملفات HTML/CSS/JS/assets إلى مستودع GitHub Pages.
- تأكد أن `API` في الملفات يشير إلى Worker الصحيح.

## 5) ملاحظات
- لا تضع الأسرار في ملفات الواجهة.
- اختبر تسجيل الدخول، الطلبات، الأجهزة، بوابة ولي الأمر، الاختبارات، والإشعارات بعد النشر.
