# إعداد Cloudflare D1 والأسرار

## D1
- اسم قاعدة البيانات: `zm-academy-db`
- Binding: `DB`
- نفّذ `migrations/001_platform_core.sql` فقط لتأسيس جداول المنصة.
- لا تنفّذ `migrations/002_column_extensions.sql`؛ فهو ملف توثيقي فقط. Worker يضيف أعمدة التوافق القديمة بعد فحص المخطط والتحقق من نجاح كل تعديل.

## أسرار Worker المطلوبة/الموصى بها
- `GITHUB_STORAGE_TOKEN`: للرفع والتخزين في مستودع التخزين.
- `ADMIN_SETUP_KEY`: لإنشاء أول حساب إدارة فقط.
- `AI_API_KEY`: مفتاح مزود AI (OpenAI-compatible أو حسب `AI_API_URL`).
- `AI_API_URL` (اختياري): افتراضي `https://api.openai.com/v1/chat/completions`
- `AI_MODEL` (اختياري): افتراضي `gpt-4o-mini`

## الأوامر
```bash
wrangler d1 execute zm-academy-db --file=./migrations/001_platform_core.sql
wrangler secret put GITHUB_STORAGE_TOKEN
wrangler secret put ADMIN_SETUP_KEY
wrangler secret put AI_API_KEY
wrangler deploy
```
