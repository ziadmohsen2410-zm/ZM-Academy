ZM Academy - الحزمة الكاملة

محتويات الحزمة:
- صفحات الموقع: index.html و welcome.html و login.html و register.html
- لوحة الإدارة: admin.html
- لوحة الطالب: student.html
- Backend: worker.js
- إعدادات Cloudflare: wrangler.toml
- PWA: manifest.webmanifest و sw.js
- الصور والأيقونات داخل assets/ والصورة الرئيسية في مجلد المشروع.

تعديلات Worker المضمنة في هذه الحزمة:
1) إضافة إنشاء جدول archived_subjects تلقائيًا قبل استخدامه.
2) إضافة إنشاء جدول student_hidden_purchases تلقائيًا قبل عرض/إخفاء مشتريات الطالب.
3) إضافة تنظيف سجلات الإخفاء عند حذف حساب الطالب.
4) الحفاظ على بقية منطق الجلسات والأجهزة الموجود في النسخة المصدر.

ملاحظات النشر:
- ارفع ملفات الواجهة إلى مستودع GitHub Pages مع الحفاظ على نفس المجلدات.
- انشر worker.js على Cloudflare Workers.
- تأكد أن ربط قاعدة D1 باسم DB موجود كما في wrangler.toml.
- متغيرات الأسرار الخاصة بمستودع التخزين يجب ضبطها في إعدادات Cloudflare Workers، ولا تضع أي Token داخل الملفات العامة.

تم فحص صياغة worker.js و sw.js باستخدام Node.js، والتحقق من صحة manifest.webmanifest.
هذا فحص ثابت للملفات وليس اختبارًا حيًا لاتصال Cloudflare أو قاعدة D1.


تحديث مركز التصميم الشامل (26-11-2026):
- أضيفت إعدادات ثيمات جاهزة وألوان مخصصة وقوالب Future / Glass / Minimal / Luxury / Editorial.
- تُحفظ إعدادات التصميم ضمن إعدادات الصفحة الرئيسية في قاعدة البيانات (draft/published).
- أضيف محمّل تصميم موحد إلى صفحات index وstudent وlogin وregister وwelcome وadmin ليقرأ الإعدادات المنشورة من /api/homepage.
- أضيفت إعدادات الشعار وصورة الخلفية وروابط التواصل ورقم واتساب.
- يجب نشر Worker المحدّث والملفات الثابتة معًا، ثم اختبار النشر الفعلي على Cloudflare Pages/Workers وD1.
