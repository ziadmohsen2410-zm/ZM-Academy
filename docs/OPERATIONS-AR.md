# دليل التشغيل والنشر — ZM Academy

## 1. قبل البدء

نفّذ الأوامر من جذر المشروع. يلزم Node.js حديث وPython 3 وWrangler CLI. لا تنفذ migration مباشرة على قاعدة الإنتاج قبل تصدير نسخة احتياطية ومراجعة الملف SQL.

## 2. فحوص المشروع محليًا

```bash
npm test
npm run check
npm run check:migrations
```

الاختبار المحلي يختبر منطق الدوال المصدرة وصياغة ملفات JavaScript وHTML وتطبيق migrations على SQLite. لا يختبر اتصال Cloudflare الحي.

## 3. نسخة D1 احتياطية قبل الترحيل

تأكد من اختيار الحساب والمشروع الصحيحين، ثم:

```bash
mkdir -p backups
npx wrangler d1 export zm-academy-db --remote --output backups/zm-academy-before-platform-extensions.sql
```

احتفظ بالنسخة خارج المستودع أيضًا، مع ضبط وصول محدود إليها لأنها قد تحتوي بيانات طلاب. لا ترفعها إلى GitHub العام.

## 4. تطبيق ترحيلات D1

يعرف `wrangler.toml` قاعدة البيانات باسم `zm-academy-db` والربط `DB` ومجلد الترحيلات `migrations`.

```bash
npx wrangler d1 migrations list zm-academy-db --remote
npx wrangler d1 migrations apply zm-academy-db --remote
npx wrangler d1 migrations list zm-academy-db --remote
```

راجع نتيجة كل أمر. الترحيل المضاف `0001_platform_extensions.sql` ينشئ جداول إضافية فقط. لا تحذف أو تعدل ملفات migrations بعد تطبيقها على قاعدة حية؛ أضف migration جديدة لأي تغيير لاحق.

**لا تستخدم ملف export كأمر استعادة على الإنتاج مباشرة.** اختبر الاستعادة أولًا على قاعدة D1 منفصلة أو نسخة محلية. استعادة قاعدة كاملة قد تستبدل بيانات أحدث.

## 5. إعداد أسرار Worker

اضبط الأسرار على Worker `zm-academy-api` من مجلد المشروع:

```bash
npx wrangler secret put ADMIN_SETUP_KEY
npx wrangler secret put GITHUB_STORAGE_TOKEN
npx wrangler secret put AI_API_KEY
npx wrangler secret put AI_MODEL
```

- `ADMIN_SETUP_KEY`: رمز طويل وعشوائي لاستخدام endpoint الإنشاء الأولي للإدارة مرة واحدة فقط إذا لم يوجد أي admin سابق. إذا كانت قاعدة البيانات تحتوي مسؤولًا بالفعل، لا تستخدم endpoint؛ سجّل دخولك بالحساب القائم.
- `GITHUB_STORAGE_TOKEN`: Token محدود الصلاحيات إلى مستودع التخزين `ziadmohsen2410-zm/ZM-Academy-Storage`، ويجب أن تكون صلاحياته على قدر الحاجة لقراءة/كتابة الملفات.
- `AI_API_KEY`: مفتاح مزود AI. لا تضعه في HTML أو JavaScript أو متغيرات عامة.
- `AI_MODEL`: اسم النموذج الذي يدعمه مزودك.
- `AI_API_URL` اختياري: عنوان HTTPS متوافق مع واجهة OpenAI Chat Completions. الافتراضي `https://api.openai.com/v1/chat/completions`.

لا تُنشئ قيمًا وهمية للأسرار بغرض إظهار أن التكامل يعمل. إذا لم يتوفر مفتاح AI، ستعيد واجهات AI حالة غير مفعلة.

## 6. إعداد حساب الإدارة لأول مرة

استخدم endpoint التالي مرة واحدة فقط على قاعدة جديدة ليس بها أي مستخدم إداري:

`POST https://zm-academy-api.ziadmohsen4567.workers.dev/api/admin/setup`

Body JSON:

```json
{
  "setupKey": "القيمة التي خزنتها في ADMIN_SETUP_KEY",
  "username": "اسم_المسؤول",
  "password": "كلمة مرور قوية لا تقل عن 12 حرفًا"
}
```

الـendpoint يغلق تلقائيًا إذا وجد سجل admin سابقًا. لا تشارك `setupKey` أو كلمة المرور في سجل عام.

## 7. نشر Worker

بعد مراجعة `wrangler.toml` وسلامة migrations:

```bash
npx wrangler deploy
```

تحقق من سجلات Worker بعد النشر. لا يعني نجاح deploy أن جميع endpoints تعمل؛ اختبر تسجيل الدخول وD1 والأجهزة والصفحات والاختبارات في حساب تجريبي أولًا.

## 8. نشر الواجهات الثابتة

ارفع صفحات HTML وملفات JS/CSS والأصول إلى نفس جذر GitHub Pages للمشروع الحالي، مع الحفاظ على مسارات `assets/`. أضف الملفات الجديدة:

- `parent.html`
- `page.html`
- `admin-extensions.js`
- `admin-extensions.css`

لا تحذف Service Worker/manifest أو الصور الحالية. بعد النشر، امسح Cache الموقع أو حدّث إصدار Service Worker إذا لاحظت استمرار ملفات قديمة.

## 9. فحص تشغيل سريع

1. افتح الصفحة الرئيسية ثم سجّل دخول طالب تجريبي.
2. تحقق من حفظ إعدادات التخصيص بعد إعادة تسجيل الدخول.
3. افتح حساب ولي الأمر، وجرّب إرسال طلب ربط برقم هاتف موجود في `students.parent_phone` ثم اعتمده من لوحة الإدارة.
4. أنشئ اختبارًا تجريبيًا، انشره، وحاول الإجابة كطالب؛ تأكد أن مفتاح الإجابة لا يظهر قبل التصحيح.
5. أنشئ إعلانًا محدود المدة وإشعارًا لطالب تجريبي.
6. اختبر صلاحيات حساب Admin محدود عبر الواجهة وطلب API مباشر.
7. اختبر رفع ملف صغير من لوحة الإدارة عند إعداد GitHub Storage Token.
8. ارفع صورة اختبار إلى مكتبة الوسائط؛ راجعها خاصة أولًا، ثم انشرها كرابط عام وانسخ Worker URL لاستخدامه داخل عنصر صورة في محرر الصفحات. تأكد أن إلغاء النشر لا يعمل إذا كانت الصورة مرتبطة بصفحة.
9. اختبر AI فقط بعد إضافة أسرار مزود حقيقية، وتحقق من حدود التكلفة والخصوصية.

## 10. حدود التشغيل المعروفة

- لا يوجد في هذه الحزمة SMS أو WhatsApp OTP أو بريد استعادة كلمة مرور ولي الأمر.
- ملفات الوسائط تُرفع إلى مستودع GitHub Storage عبر Worker؛ الصور لا تصبح عامة إلا بعد تفعيل `is_public`. ملفات PDF تبقى خاصة ولا تُعرض عبر مسار الصورة العامة.
- لا يوجد تكامل دفع حي.
- لا يوجد فهرس RAG كامل للدروس والملفات، ولا رفع صور/ملفات إلى مساعد الطالب.
- لا يوجد نسخ D1 تلقائي مجدول من داخل التطبيق؛ استخدم تصدير D1 المنتظم وسياسة تخزين آمنة.
- بوابة ولي الأمر تطابق رقم الهاتف المدخل مع رقم ولي الأمر المسجل في بيانات الطالب؛ يجب مراجعة جودة أرقام الهواتف الحالية.
- راجع `IMPLEMENTATION-STATUS-AR.txt` قبل اعتبار المشروع مستوفيًا لكل المتطلبات.

## 11. وثائق Cloudflare الرسمية

- D1 migrations: https://developers.cloudflare.com/d1/reference/migrations/
- D1 Wrangler commands: https://developers.cloudflare.com/d1/wrangler-commands/
- Workers secrets: https://developers.cloudflare.com/workers/configuration/secrets/
