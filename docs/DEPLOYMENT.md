# دليل التشغيل والنشر - ZM Academy

## 1) المتطلبات
- Cloudflare Worker مع D1 binding باسم `DB`
- مستودع GitHub Pages للواجهة الأمامية
- أسرار Worker: `GITHUB_STORAGE_TOKEN`, `ADMIN_SETUP_KEY`، و`AI_API_KEY` لتفعيل مساعد الذكاء الاصطناعي. يمكن ضبط `AI_API_URL` و`AI_MODEL` اختياريًا.

## 2) قاعدة البيانات D1
1. تأكد من وجود قاعدة `zm-academy-db` وربطها في `wrangler.toml`.
2. نفّذ ملف التأسيس الآمن التالي مرة واحدة:
   ```bash
   wrangler d1 execute zm-academy-db --file=./migrations/001_platform_core.sql
   ```
3. **لا تنفّذ `migrations/002_column_extensions.sql` يدويًا.** الملف ملاحظة تاريخية فقط؛ أعمدة الجداول القديمة يضيفها Worker تلقائيًا بعد فحص `PRAGMA table_info` والتحقق من النتيجة. أوامر `ALTER TABLE ADD COLUMN` المباشرة ليست آمنة عند تكرارها في SQLite/D1.
4. احتفظ بنسخة احتياطية من قاعدة البيانات قبل أي تغيير على بيئة الإنتاج.

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
- يرفع النظام ملفات المحتوى حتى 25 MB، بينما تظل صور الطلاب محدودة بـ5 MB.
- سير عمل النشر يشغّل فحوصات المشروع قبل النشر، ثم يتحقق من استجابة `/api/health` واتصال D1.
- اختبر تسجيل الدخول، الطلبات، الأجهزة، بوابة ولي الأمر، الاختبارات، الإشعارات، رفع ملف أكبر من 8 MB، عرضه وحذفه في بيئة Preview قبل الاعتماد على الإنتاج.
- واجهات AI لا تعمل فعليًا دون ضبط `AI_API_KEY`. لا توجد بوابة دفع إلكتروني حقيقية مهيأة في النسخة الحالية.
