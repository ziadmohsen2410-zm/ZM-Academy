import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const read = (name) => fs.readFileSync(path.join(process.cwd(), name), "utf8");

test("all primary platform files are present", () => {
  for (const file of [
    "worker.js", "admin.html", "student.html", "parent.html",
    "index.html", "login.html", "register.html", "migrations/001_platform_core.sql"
  ]) assert.ok(fs.existsSync(path.join(process.cwd(), file)), "Missing " + file);
});

test("admin dashboard sections exist for core platform tools", () => {
  const admin = read("admin.html");
  for (const id of [
    "sec-dashboard", "sec-students", "sec-parents", "sec-exams",
    "sec-ads", "sec-notifications", "sec-pages", "sec-theme",
    "sec-ai", "sec-media", "sec-roles", "sec-backups", "sec-audit"
  ]) assert.ok(admin.includes('id="' + id + '"'), "Missing admin section " + id);
});

test("worker exposes the platform routes used by the admin and student areas", () => {
  const worker = read("worker.js");
  for (const route of [
    "/api/admin/platform/pages", "/api/admin/platform/ads",
    "/api/admin/platform/notifications", "/api/admin/platform/roles",
    "/api/admin/platform/backup/export", "/api/admin/platform/media",
    "/api/admin/platform/exams", "exam-questions",
    "/api/student/platform/notifications", "/api/student/platform/exams",
    "/api/student/platform/ai", "/api/parent/login"
  ]) assert.ok(worker.includes(route), "Worker route missing: " + route);
});

test("admin permission helpers initialize before route handlers can invoke the role guard", () => {
  const worker = read("worker.js");
  const permissions = worker.indexOf("const hasPerm =");
  const route = worker.indexOf("async function route(");
  assert.notEqual(permissions, -1, "Permission helper must exist");
  assert.notEqual(route, -1, "Worker route must exist");
  assert.ok(permissions < route, "Permission helpers must initialize before the first request enters route()");
});

test("student area includes notifications, exams, and AI integration", () => {
  const student = read("student.html");
  for (const route of [
    "/api/student/platform/notifications",
    "/api/student/platform/exams",
    "/api/student/platform/ai"
  ]) assert.ok(student.includes(route), "Student integration missing: " + route);
});

test("admin content forms send every field required by the Worker", () => {
  const admin = read("admin.html");
  assert.match(admin, /id="matType"/, "Material type selector is required");
  assert.ok(admin.includes("type:$('#matType').value"), "Material creation must send type");
  assert.match(admin, /id="matSubjectId"/, "Materials must select an existing subject");
  assert.ok(admin.includes("اختر المادة"), "Subject selector must have a clear prompt");
  assert.match(admin, /if\(!name\|\|!grade\)/, "Subject creation must validate grade");
});

test("admin materials listing safely adds the file_key column on older D1 databases", () => {
  const worker = read("worker.js");
  const start = worker.indexOf('if (method === "GET" && path === "/api/admin/materials")');
  const end = worker.indexOf("// أرشفة درس أو استعادته", start);
  assert.notEqual(start, -1, "Admin materials listing route must exist");
  const route = worker.slice(start, end);
  assert.ok(route.includes('ensureColumn(env, "materials", "file_key", "TEXT")'));
  assert.ok(route.indexOf('ensureColumn(env, "materials", "file_key", "TEXT")') < route.indexOf("SELECT m.id"));
  assert.ok(route.includes("await ensureArchivedMaterialsTable(env)"));
});

test("admin can archive and restore subjects and materials without deleting records", () => {
  const admin = read("admin.html");
  const worker = read("worker.js");
  assert.match(admin, /api\/admin\/subjects\/\$\{id\}\/\$\{action\}/);
  assert.match(admin, /api\/admin\/materials\/\$\{id\}\/\$\{action\}/);
  assert.ok(worker.includes('^\\/api\\/admin\\/subjects\\/(\\d+)\\/(archive|restore)$'));
  assert.ok(worker.includes('^\\/api\\/admin\\/materials\\/(\\d+)\\/(archive|restore)$'));
});

test("private provider credentials are not embedded in public pages", () => {
  for (const file of ["index.html", "welcome.html", "login.html", "register.html", "admin.html", "student.html", "parent.html"]) {
    const source = fs.readFileSync(path.join(process.cwd(), file), "utf8");
    assert.doesNotMatch(source, /(?:AI_API_KEY|GITHUB_STORAGE_TOKEN)\s*[:=]\s*["'][^"']{8,}/, "Possible secret embedded in " + file);
  }
});

test("platform schema bootstrap does not silently swallow table, index, or role initialization failures", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes("PLATFORM_SCHEMA_TABLE_ERROR:"));
  assert.ok(worker.includes("PLATFORM_SCHEMA_INDEX_ERROR:"));
  assert.ok(worker.includes("PLATFORM_SCHEMA_ROLE_SEED_ERROR:"));
  assert.match(worker, /throw new Error\(`Platform database setup failed while creating schema table group item/);
  assert.match(worker, /throw new Error\(`Platform database setup failed while creating schema index/);
  assert.ok(worker.includes("Required database table is missing:"));
});

test("legacy column extension SQL is not documented or exposed as a repeatable manual migration", () => {
  const legacy = read("migrations/002_column_extensions.sql");
  const deployment = read("docs/DEPLOYMENT.md");
  const secrets = read("docs/CLOUDFLARE-D1-SECRETS.md");
  const executableSql = legacy.replace(/^\s*--.*$/gm, "");
  assert.doesNotMatch(executableSql, /\bALTER\s+TABLE\b/i);
  assert.match(legacy, /DO NOT EXECUTE/i);
  assert.match(deployment, /لا تنفّذ.*002_column_extensions\.sql.*يدويًا/s);
  assert.match(secrets, /لا تنفّذ.*002_column_extensions\.sql/s);
});

test("the platform core migration is additive and repeat-safe by declaration", () => {
  const sql = read("migrations/001_platform_core.sql");
  assert.doesNotMatch(sql, /\bDROP\s+(?:TABLE|COLUMN|INDEX)\b|\bDELETE\s+FROM\b|\bTRUNCATE\b/i);
  assert.match(sql, /CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+roles/i);
  assert.match(sql, /CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+exams/i);
});

test("admin can schedule notifications with validated local-to-UTC timestamps", () => {
  const worker = read("worker.js");
  const admin = read("admin.html");
  assert.ok(admin.includes('id="notifSchedule"'));
  assert.ok(admin.includes("new Date(schedule).toISOString()"));
  assert.ok(worker.includes("scheduledAt&&!Number.isFinite(Date.parse(scheduledAt.replace(' ','T')+'Z'))"));
  assert.ok(worker.includes("scheduledAt?null:nowIso()"));
});

test("parent portal does not expose partial or hidden exam scores", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes("CASE WHEN a.status='graded' AND e.show_results<>0 THEN a.score ELSE NULL END AS score"));
  assert.ok(worker.includes("CASE WHEN a.status='graded' AND e.show_results<>0 THEN a.max_score ELSE NULL END AS max_score"));
});

test("parent portal receives parent-targeted notifications and can mark them read", () => {
  const worker = read("worker.js");
  const parent = read("parent.html");
  assert.ok(worker.includes("path==='/api/parent/notifications'"));
  assert.ok(worker.includes("n.audience_type='parents'"));
  assert.ok(worker.includes("r.user_type='parent'"));
  assert.ok(parent.includes('id="parentNotifications"'));
  assert.ok(parent.includes("loadParentNotifications()"));
  assert.ok(parent.includes("/api/parent/notifications/"));
});

test("notification creation validates supported audiences and target values", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes("!['all','parents','student','grade'].includes(audienceType)"));
  assert.ok(worker.includes("!/^\\d+$/.test(audienceValue)"));
  assert.ok(worker.includes("audienceType==='grade'&&!audienceValue"));
});

test("scheduled student notifications remain hidden until their scheduled time", () => {
  const worker = read("worker.js");
  const start = worker.indexOf("if (method==='GET' && path==='/api/student/platform/notifications')");
  const end = worker.indexOf("if (method==='POST' && /^\\/api\\/student\\/platform\\/notifications",start);
  const route = worker.slice(start,end);
  assert.ok(route.includes("n.scheduled_at IS NULL OR datetime(n.scheduled_at)<=datetime('now')"));
});

test("student notifications are scoped to broadcast, matching student, or matching grade", () => {
  const worker = read("worker.js");
  const start = worker.indexOf("if (method==='GET' && path==='/api/student/platform/notifications')");
  assert.notEqual(start, -1, "Student notifications route must exist");
  const end = worker.indexOf("if (method==='POST' && /^\\/api\\/student\\/platform\\/notifications", start);
  const route = worker.slice(start, end === -1 ? start + 1800 : end);
  assert.ok(route.includes("n.audience_type='all'"));
  assert.ok(route.includes("n.audience_type='student' AND n.audience_value=CAST(? AS TEXT)"));
  assert.ok(route.includes("n.audience_type='grade'"));
  assert.ok(!route.includes("audience_type IN ('all','student')"));
});

test("student preferences accept only supported themes, colors, and font sizes", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes("const normalizeStudentPreferences = (value) =>"));
  assert.ok(worker.includes("/^#[0-9a-fA-F]{6}$/"));
  assert.ok(worker.includes("['dark','light'].includes(raw.mode)"));
  assert.ok(worker.includes("['normal','large','xlarge'].includes(raw.fontSize)"));
  assert.ok(worker.includes("normalizeStudentPreferences(body?.preferences)"));
});

test("students can delete rejected purchases and hide completed purchases without deleting records", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes('if (order.status === "rejected")'));
  assert.ok(worker.includes("DELETE FROM orders"));
  assert.ok(worker.includes('if (order.status === "approved" || order.status === "completed")'));
  assert.ok(worker.includes("INSERT OR IGNORE INTO student_hidden_purchases"));
  assert.ok(worker.includes("لا يمكن حذف طلب قيد المراجعة"));
});

test("student exam visibility and start enforce grade, schedule, open-attempt, and question checks", () => {
  const worker = read("worker.js");
  const start = worker.indexOf("if (method==='GET' && path==='/api/student/platform/exams')");
  const end = worker.indexOf("if (method==='POST' && path==='/api/student/platform/ai')", start);
  const routes = worker.slice(start, end);
  assert.ok(routes.includes("e.grade=(SELECT s.grade FROM students s WHERE s.id=?)"));
  assert.ok(routes.includes("datetime(e.starts_at)<=datetime('now')"));
  assert.ok(routes.includes("datetime(e.ends_at)>=datetime('now')"));
  assert.ok(routes.includes("status='in_progress'"));
  assert.ok(routes.includes("الاختبار لا يحتوي على أسئلة"));
  assert.ok(routes.includes("datetime(exam_attempts.started_at, '+' || e.duration_minutes || ' minutes')<=datetime('now')"));
  assert.ok(routes.includes("status='expired'"));
  assert.ok(routes.includes("e.duration_minutes"));
  assert.ok(routes.includes("انتهى الوقت المحدد للاختبار"));
});

test("student exam routes lazily ensure the resume-order database column", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes("const isExamResumeRoute="));
  assert.ok(worker.includes("const isExamStartRoute="));
  assert.ok(worker.includes("ensureColumn(env,'exam_attempts','question_order_json','TEXT')"));
});

test("shuffled question order is preserved across exam resume", () => {
  const worker = read("worker.js");
  const migration = read("migrations/001_platform_core.sql");
  assert.ok(worker.includes("question_order_json"));
  assert.ok(worker.includes("JSON.stringify(questions.map(q=>q.id))"));
  assert.ok(worker.includes("const savedOrder=safeJsonParse(attempt.question_order_json,[])"));
  assert.ok(migration.includes("question_order_json TEXT"));
});

test("exam answer autosave is rate limited per attempt", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes("consumeApiRateLimit(env,request,'exam-autosave',attemptId,120,60)"));
  assert.ok(worker.includes("طلبات حفظ كثيرة جدًا"));
});

test("exam answers are autosaved and restored when a student resumes", () => {
  const worker = read("worker.js");
  const student = read("student.html");
  assert.ok(worker.includes("method==='PUT' && /^\\/api\\/student\\/platform\\/exam-attempts\\/\\d+\\/answers$/.test(path)"));
  assert.ok(worker.includes("UPDATE exam_attempts SET answers_json=?"));
  assert.ok(worker.includes("answers:safeJsonParse(attempt.answers_json,{})"));
  assert.ok(student.includes("/answers\x60"));
  assert.ok(student.includes("form.addEventListener('change'"));
  assert.ok(student.includes("const saved=d.answers||{}"));
});

test("student exam timer is based on the server-recorded attempt start time", () => {
  const worker = read("worker.js");
  const student = read("student.html");
  assert.ok(worker.includes("started_at:started?.started_at||null"));
  assert.ok(student.includes("data-exam-timer"));
  assert.ok(student.includes("startedMs+duration*60000-Date.now()"));
  assert.ok(student.includes("setInterval(updateTimer,1000)"));
});

test("student exam UI disables new attempts when the allowed count is exhausted", () => {
  const student = read("student.html");
  assert.ok(student.includes("Number(e.my_attempts||0)>=Number(e.attempts_allowed||1)?'disabled':''"));
  assert.ok(student.includes("انتهت المحاولات"));
});

test("students can resume an in-progress exam after reopening the page", () => {
  const worker = read("worker.js");
  const student = read("student.html");
  assert.ok(worker.includes("active_attempt_id"));
  assert.ok(worker.includes("exam-attempts\\/\\d+$"));
  assert.ok(worker.includes("a.status='in_progress'"));
  assert.ok(student.includes('data-active="'));
  assert.ok(student.includes("استكمال الاختبار"));
  assert.ok(student.includes("activeAttemptId?await api"));
});

test("released exam results include teacher feedback for essay questions", () => {
  const worker = read("worker.js");
  const student = read("student.html");
  assert.ok(worker.includes("question_text:q.question_text,comment:saved[q.id]||''"));
  assert.ok(student.includes("result.feedback||[]"));
  assert.ok(student.includes("esc(x.comment)"));
});

test("students can refresh final exam results after manual essay grading", () => {
  const worker = read("worker.js");
  const student = read("student.html");
  assert.ok(worker.includes("exam-attempts\\/\\d+\\/result"));
  assert.ok(worker.includes("results_pending_manual:attempt.status==='submitted'"));
  assert.ok(worker.includes("attempt.status==='graded'?attempt.score:null"));
  assert.ok(worker.includes("score:showResults&&!needsManual?score:null"));
  assert.ok(student.includes('id="refreshExamResult"'));
  assert.ok(student.includes("/result\x60"));
});

test("essay attempts have an admin review and bounded manual grading workflow", () => {
  const worker = read("worker.js");
  const admin = read("admin.html");
  assert.ok(worker.includes("path==='/api/admin/platform/exam-attempts'"));
  assert.ok(worker.includes("exam-attempts\\/\\d+\\/grade"));
  assert.ok(worker.includes("attempt.status!=='submitted'"));
  assert.ok(worker.includes("value<0 || value>max"));
  assert.ok(worker.includes("if (!(gradeUpdate.meta?.changes||0))"));

  assert.ok(worker.includes("status='graded',graded_by=?"));
  assert.ok(admin.includes('id="examAttemptsList"'));
  assert.ok(admin.includes("window.__reviewAttempt=async(id)=>"));
  assert.ok(admin.includes("window.__loadExamAttempts(id)"));
  assert.ok(admin.includes("a.status==='submitted'"));
});

test("exam scoring configuration is locked after the first student attempt", () => {
  const worker = read("worker.js");
  const admin = read("admin.html");
  assert.ok(worker.includes("settings_locked:true"));
  assert.ok(worker.includes("UPDATE exams SET title=?,description=?,status=?,updated_at=datetime('now') WHERE id=?"));
  assert.ok(admin.includes("const settingsLocked=Number(e.attempts_count||0)>0"));
  assert.ok(admin.includes("$('#'+field).disabled=settingsLocked"));
});

test("exam history cannot be destroyed or have questions changed after attempts begin", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes("لا يمكن حذف اختبار له محاولات طلاب"));
  assert.ok(worker.includes("لا يمكن تعديل أسئلة اختبار بدأه الطلاب"));
  assert.ok(worker.includes("لا يمكن تعديل أو حذف سؤال بعد بدء الطلاب للاختبار"));
});

test("exam validation preserves the archived lifecycle state", () => {
  const worker = read("worker.js");
  const admin = read("admin.html");
  assert.ok(worker.includes("['draft','published','closed','archived']"));
  assert.ok(admin.includes('<option value="archived">مؤرشف</option>'));
});

test("AI homepage apply action is hidden when switching away from builder mode", () => {
  const admin = read("admin.html");
  assert.ok(admin.includes("$('#aiMode').addEventListener('change'"));
  assert.ok(admin.includes("if($('#aiMode').value!=='builder')$('#applyAiHomepageBtn').style.display='none'"));
});

test("AI Builder can apply structured homepage settings without publishing automatically", () => {
  const worker = read("worker.js");
  const admin = read("admin.html");
  assert.ok(worker.includes("brandName, tagline, theme, hero, about, branding, announcement, sections"));
  assert.ok(admin.includes('id="applyAiHomepageBtn"'));
  assert.ok(admin.includes("const generated=JSON.parse($('#aiResult').textContent)"));
  assert.ok(admin.includes("await loadHomepage();const generated=JSON.parse"));
  assert.ok(admin.includes("theme:{...(homepageDraft.theme||{}),...(generated.theme||{})}"));

  assert.ok(admin.includes("تم تطبيق مسودة AI في النموذج"));
  assert.ok(admin.includes("لم يتم حفظه أو نشره بعد"));
});

test("homepage editor preserves unsaved edits when navigating between sections", () => {
  const admin = read("admin.html");
  assert.ok(admin.includes("let homepageDraftDirty=false"));
  assert.ok(admin.includes("if(homepageDraftDirty)return"));
  assert.ok(admin.includes("homepageDraftDirty=true"));
  assert.ok(admin.includes("سيتم تجاهل التعديلات غير المحفوظة"));
  assert.equal((admin.match(/\$\('#loadHomepageBtn'\)\.onclick=/g)||[]).length,1);

});

test("public page renderer rejects protocol-relative external links", () => {
  const page = read("page.html");
  assert.ok(page.includes("if(raw.startsWith('//'))return ''"));
  assert.ok(page.includes("/^https:\\/\\//i.test(raw)"));
});

test("page builder accepts only URL-safe public page keys", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes("/^[a-z0-9][a-z0-9_-]{0,79}$/i.test(key)"));
  assert.ok(worker.includes("مفتاح الصفحة يجب أن يبدأ بحرف أو رقم"));
});

test("admin page-builder preview blocks unsafe link schemes", () => {
  const admin = read("admin.html");
  assert.ok(admin.includes("const safePreviewLink=value=>"));
  assert.ok(admin.includes("if(!raw||raw.startsWith('//'))return '#'"));
  assert.ok(admin.includes("safePreviewLink(b.buttonUrl)"));
});

test("public page renderer inherits the published homepage brand theme", () => {
  const page = read("page.html");
  assert.ok(page.includes("fetch(API+'/api/homepage'"));
  assert.ok(page.includes("applyBrandTheme(d.settings)"));
  assert.ok(page.includes("settings.brandName"));
  assert.ok(page.includes("theme.mode==='system'&&window.matchMedia"));
  assert.ok(page.includes("media.addEventListener?.('change',sync)"));

  assert.ok(page.includes("['primary','--blue']"));
  assert.ok(page.includes("document.body.classList.add('light')"));
});

test("published page builder pages render through the public API", () => {
  const page = read("page.html");
  const admin = read("admin.html");
  const worker = read("worker.js");
  assert.ok(page.includes("/api/public/pages/"));
  assert.ok(page.includes("d.page.content||{}"));
  assert.ok(page.includes("content.blocks"));
  assert.ok(admin.includes('id="openPublishedPageBtn"'));
  assert.ok(admin.includes("./page.html?key="));
  assert.ok(worker.includes("path.startsWith('/api/public/pages/')"));
});

test("homepage settings sanitize links, colors, and visitor-facing text", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes("function sanitizeHomepageSettings(value)"));
  assert.ok(worker.includes("if(!raw||raw.startsWith('//'))return ''"));
  assert.ok(worker.includes("primaryUrl:safeLink(hero.primaryUrl)"));
  assert.ok(worker.includes("facebook:safeLink(branding.facebook)"));
  assert.ok(worker.includes("const url=new URL(raw)"));
  assert.ok(worker.includes("forbidden.some(ch=>raw.includes(ch))"));

  assert.ok(worker.includes("settings: sanitizeHomepageSettings(parseHomepageJson(row?.published_json))"));
  assert.ok(worker.includes("const settings = sanitizeHomepageSettings(body?.settings)"));
});

test("admin homepage editor is connected to the homepage draft and publish APIs", () => {
  const admin = read("admin.html");
  const worker = read("worker.js");
  const index = read("index.html");
  assert.ok(admin.includes('id="sec-homepage"'));
  assert.ok(admin.includes("async function loadHomepage()"));
  assert.ok(admin.includes("api('/api/admin/homepage'"));
  assert.ok(admin.includes("api('/api/admin/homepage/publish'"));
  for (const id of ['homeSurface','homeText','homeMuted','homeFont','homeCorners','homeButtons','homeCards','homeMotion']) assert.ok(admin.includes('id="'+id+'"'));

  assert.ok(admin.includes("homepage:'page_builder'"));
  assert.ok(worker.includes('path === "/api/admin/homepage"'));
  assert.ok(index.includes("fetch(API+'/api/homepage'"));
});

test("admin exam editor exposes and saves all supported exam settings", () => {
  const admin = read("admin.html");
  assert.ok(admin.includes('id="examDuration"'));
  assert.ok(admin.includes('id="examAttempts"'));
  assert.ok(admin.includes('id="examShuffle"'));
  assert.ok(admin.includes('id="examShowResults"'));
  assert.ok(admin.includes('id="examStartsAt"'));
  assert.ok(admin.includes('id="examEndsAt"'));
  assert.ok(admin.includes("method:id?'PUT':'POST'"));
  assert.ok(admin.includes("new Date(value).toISOString()"));
  assert.ok(admin.includes("String(value).replace(' ','T')+'Z'"));
  assert.ok(admin.includes("window.__editExam=async(id)=>"));
  assert.ok(admin.includes("$('#examShuffle').checked=Number(e.shuffle_questions)===1"));
  assert.ok(admin.includes("$('#examShowResults').checked=Number(e.show_results)!==0"));
});

test("student and admin AI endpoints enforce per-user rate limits", () => {
  const worker = read("worker.js");
  const student = worker.slice(worker.indexOf("if (method==='POST' && path==='/api/student/platform/ai')"));
  const admin = worker.slice(worker.indexOf("if (method==='POST' && path==='/api/admin/platform/ai')"));
  assert.ok(student.includes("consumeApiRateLimit(env,request,'student_ai',session.student_id,10,60)"));
  assert.ok(admin.includes("consumeApiRateLimit(env,request,'admin_ai',admin.id,20,60)"));
  assert.ok(student.includes("code:'RATE_LIMITED'"));
  assert.ok(admin.includes("code:'RATE_LIMITED'"));
});

test("exam creation and question mutations validate unsafe values", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes("const validateExamInput = (b) =>"));
  assert.ok(worker.includes("duration < 1 || duration > 600"));
  assert.ok(worker.includes("attempts < 1 || attempts > 20"));
  assert.ok(worker.includes("ends <= starts"));
  assert.ok(worker.includes("const validateExamQuestion = (b) =>"));
  assert.ok(worker.includes("points <= 0 || points > 1000"));
  assert.ok(worker.includes("type === 'mcq' && (!Array.isArray(b?.options) || b.options.length < 2)"));
  const adminExamRoutes = worker.slice(worker.indexOf("if (path==='/api/admin/platform/exams')"), worker.indexOf("// Analytics"));
  assert.ok((adminExamRoutes.match(/validateExamInput\(b\)/g)||[]).length >= 2);
  assert.ok((adminExamRoutes.match(/validateExamQuestion\(b\)/g)||[]).length >= 2);
});

test("student exam start honors shuffle_questions without changing question IDs", () => {
  const worker = read("worker.js");
  const start = worker.indexOf("if (method==='POST' && /^\\/api\\/student\\/platform\\/exams\\/");
  const end = worker.indexOf("if (method==='POST' && /^\\/api\\/student\\/platform\\/exam-attempts", start);
  const route = worker.slice(start, end);
  assert.ok(route.includes("Number(exam.shuffle_questions) === 1"));
  assert.ok(route.includes("Math.random()"));
  assert.ok(route.includes("[questions[i],questions[j]]=[questions[j],questions[i]]"));
  assert.ok(route.includes("questions:questions.map"));
  assert.ok(route.includes("const maxScore = questions.reduce"));
});

test("student exam results respect the exam show_results setting", () => {
  const worker = read("worker.js");
  const start = worker.indexOf("if (method==='POST' && /^\\/api\\/student\\/platform\\/exam-attempts");
  const end = worker.indexOf("if (method==='POST' && path==='/api/student/platform/ai')", start);
  const route = worker.slice(start, end);
  assert.ok(route.includes("e.show_results"));
  assert.ok(route.includes("score:showResults&&!needsManual?score:null"));
  assert.ok(route.includes("results_hidden:!showResults"));
});

test("parent-to-student link requests are rate limited per parent", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes("consumeApiRateLimit(env,request,'parent-link-request',ps.parent_id,5,3600)"));
  assert.ok(worker.includes("تجاوزت عدد طلبات ربط الطلاب المسموح بها"));
});

test("admin creation form hides super-admin for lower-privilege administrators", () => {
  const admin = read("admin.html");
  assert.ok(admin.includes("superOption.hidden=!d.permissions_map?.super_admin"));
  assert.ok(admin.includes("$('#newAdminRole').value==='super_admin'"));
});

test("role controls are disabled for the current admin and protected super-admin rows", () => {
  const worker = read("worker.js");
  const admin = read("admin.html");
  assert.ok(worker.includes("current_role:admin.role,current_admin_id:admin.id"));
  assert.ok(admin.includes("const protectedAccount=a.role==='super_admin'&&d.current_role!=='super_admin'"));
  assert.ok(admin.includes("const self=Number(a.id)===Number(d.current_admin_id)"));
  assert.ok(admin.includes("${locked?'disabled':''}"));
});

test("lower-privilege admins do not receive super-admin as an assignable role", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes("if(admin.role!=='super_admin') delete permissionsMap.super_admin"));
  assert.ok(worker.includes("permissions_map: permissionsMap"));
});

test("admin role management protects super-admin privilege and account continuity", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes("role==='super_admin' && admin.role!=='super_admin'"));
  assert.ok(worker.includes("لا يمكنك تغيير دور حسابك الحالي"));
  assert.ok(worker.includes("لا يمكنك إيقاف حسابك الحالي"));
  assert.ok(worker.includes("يجب أن يظل هناك مدير أعلى نشط واحد على الأقل"));
  assert.ok(worker.includes("لا يمكن إيقاف حساب مدير أعلى إلا بواسطة مدير أعلى"));
  assert.ok(worker.includes("لا يمكن تعديل دور مدير أعلى إلا بواسطة مدير أعلى"));
  assert.ok(worker.includes("لا يمكن تعديل حساب مدير أعلى إلا بواسطة مدير أعلى"));

});

test("legacy admin APIs enforce role permissions instead of authentication alone", () => {
  const worker = read("worker.js");
  const start = worker.indexOf("// جميع مسارات الإدارة محمية");
  const end = worker.indexOf("// إدارة إعدادات الصفحة الرئيسية", start);
  const guard = worker.slice(start, end);
  assert.ok(guard.includes("legacyPermission"));
  assert.ok(guard.includes("requireAdminRole(request, env, legacyPermission)"));
  assert.ok(guard.includes('path === "/api/admin/students" && method === "GET" ? "students.view"'));
  assert.ok(guard.includes('path.startsWith("/api/admin/orders") ? "orders"'));
  assert.ok(guard.includes('path.startsWith("/api/admin/device-requests") ? "devices"'));
  assert.ok(guard.includes('path.startsWith("/api/admin/materials")'));
});

test("admin navigation is filtered by server-provided role permissions", () => {
  const admin = read("admin.html");
  assert.ok(admin.includes("function canSeeSection(key)"));
  assert.ok(admin.includes("state.admin?.permissions"));
  assert.ok(admin.includes("visibleItems=g.items.filter(([k])=>canSeeSection(k))"));
  assert.ok(admin.includes("if(!canSeeSection(key))"));
  assert.ok(admin.includes("$('#bottomNav button[data-sec]')"));
  assert.ok(admin.includes("permissions.includes('audit.view')"));
});

test("admin student directory uses a matching platform API route without hiding the original error", () => {
  const admin = read("admin.html");
  const worker = read("worker.js");
  assert.ok(admin.includes("api('/api/admin/students')"));
  assert.ok(!admin.includes("catch { data = await api('/api/admin/platform/students'); }"));
  assert.ok(worker.includes('path === "/api/admin/students"'));
  assert.ok(worker.includes("SELECT id, name, phone, parent_phone, grade, school, governorate, created_at"));
  assert.ok(worker.includes('path === "/api/admin/students" && method === "GET" ? "students.view"'));
});

test("admin health badge checks the HTTP response and database health payload", () => {
  const admin = read("admin.html");
  assert.ok(admin.includes("!response.ok||data?.success!==true||data?.database!=='connected'"));
});

test("content managers can use the protected upload endpoint without media permission", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes('path.startsWith("/api/admin/upload") ? null : "settings"'));
  assert.ok(worker.includes('!hasPerm(auth.admin.role, "media")'));
  assert.ok(worker.includes('!hasPerm(auth.admin.role, "content")'));
});

test("material creation form uploads supported files and stores the returned file key", () => {
  const admin = read("admin.html");
  assert.ok(admin.includes('id="matFile"'));
  assert.ok(admin.includes("new FormData()"));
  assert.ok(admin.includes("fd.append('file',file,file.name)"));
  assert.ok(admin.includes("body.file_key=uploaded.file_key"));
  assert.ok(admin.includes("8*1024*1024"));
});

test("backup export includes core academy data and filters credentials", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes("'students','subjects','materials','orders'"));
  assert.ok(worker.includes("sensitiveColumn=/password|token|secret|credential|api[_-]?key/i"));
  assert.ok(worker.includes("version:2"));
  assert.ok(!worker.includes("'admin_sessions'"));
  assert.ok(!worker.includes("'student_sessions'"));
});

test("worker internal errors receive a request id and structured server-side context", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes('requestId = crypto.randomUUID()'));
  assert.ok(worker.includes('path: url.pathname'));
  assert.ok(worker.includes('request_id: requestId'));
});

test("admin student directory uses the established legacy students endpoint", () => {
  const admin = read("admin.html");
  const worker = read("worker.js");
  assert.ok(admin.includes("api('/api/admin/students')"));
  assert.ok(worker.includes('path === "/api/admin/students" && method === "GET"'));
});

test("material upload picker is visibly labeled and reports the selected mobile file", () => {
  const admin = read("admin.html");
  assert.ok(admin.includes('class="file-pick" for="matFile"'));
  assert.ok(admin.includes('id="matFileName"'));
  assert.ok(admin.includes("$('#matFile').addEventListener('change'"));
  assert.ok(admin.includes("اختيار ملف من الهاتف"));
  assert.ok(admin.includes("جارٍ رفع الملف..."));
});

test("upload validation detects real file signatures even when mobile MIME type is missing", () => {
  const worker = read("worker.js");
  assert.ok(worker.includes('signature.startsWith("%PDF-")'));
  assert.ok(worker.includes('bytes[0]===0xff && bytes[1]===0xd8 && bytes[2]===0xff'));
  assert.ok(worker.includes('signature.slice(8,12)==="WEBP"'));
  assert.ok(worker.includes('signature.slice(1,4)==="PNG"'));
});

test("login and registration pages show WhatsApp first and configured Facebook second", () => {
  for (const file of ["login.html", "register.html"]) {
    const page = read(file);
    assert.ok(page.includes('id="zmContactLinks"'));
    assert.ok(page.includes("['whatsapp',whatsappDigits?'https://wa.me/'+whatsappDigits:'']"));
    assert.ok(page.includes("['facebook',b.facebook||'']"));
  }
});

test("homepage footer includes account creation, login, WhatsApp and configured Facebook contact", () => {
  const page = read("index.html");
  assert.ok(page.includes('href="./register.html">إنشاء حساب جديد</a>'));
  assert.ok(page.includes('href="./login.html">تسجيل الدخول</a>'));
  assert.ok(page.includes('id="zmContactLinks"'));
});

test("student support uses valid contact links without nested interactive buttons", () => {
  const page = read("student.html");
  assert.ok(page.includes('id="zmContactLinks"'));
  assert.ok(!page.includes('<a href="https://wa.me/201115336341" target="_blank" rel="noopener">\\n            <button'));
});


test("materials schema migration verifies existing columns and does not swallow a failed ALTER", () => {
  const worker = read("worker.js");
  const start = worker.indexOf("async function ensureColumn(env, table, column, ddl)");
  const end = worker.indexOf("async function ensurePlatformSchema", start);
  const migration = worker.slice(start, end);
  assert.ok(migration.includes("PRAGMA table_info"));
  assert.ok(migration.includes("SCHEMA_COLUMN_MIGRATION_ERROR"));
  assert.ok(migration.includes("throw new Error"));
  assert.ok(!migration.includes("catch (_) {}"));
});

test("student and admin default visual identity is black and gold with white and gold light mode", () => {
  const css = read("assets/zm-future-theme.css");
  const student = read("student.html");
  const admin = read("admin.html");
  assert.ok(css.includes("--zm-bg:#070707"));
  assert.ok(css.includes("--zm-primary:#D4AF62"));
  assert.ok(css.includes("--zm-bg:#FFFFFF"));
  assert.ok(css.includes("--zm-text:#27231B"));
  assert.ok(student.includes("#D4AF62"));
  assert.ok(admin.includes("t.primary||'#D4AF62'"));
});


test("admin order filter can see every order status, not only pending", () => {
  const worker = read("worker.js");
  const admin = read("admin.html");
  const start = worker.indexOf('if (method === "GET" && path === "/api/admin/orders")');
  const end = worker.indexOf("// تحديث حالة الطلب", start);
  const route = worker.slice(start, end);
  assert.ok(route.includes("FROM orders o"));
  assert.ok(route.includes("ORDER BY o.id DESC"));
  assert.ok(!route.includes("WHERE o.status = 'pending'"));
  for (const status of ["pending", "approved", "rejected", "completed"]) {
    assert.ok(admin.includes('value="' + status + '"'));
  }
});

test("all primary pages reference the refreshed shared black-gold stylesheet", () => {
  for (const page of ["index.html","admin.html","login.html","register.html","student.html","parent.html"]) {
    assert.ok(read(page).includes("zm-future-theme.css?v=4"), "Stale theme cache key in " + page);
  }
});


test("student content viewer serves attached images as images and keeps PDF delivery", () => {
  const worker = read("worker.js");
  const student = read("student.html");
  assert.ok(worker.includes("const contentTypes ="));
  assert.ok(worker.includes('jpg: "image/jpeg"'));
  assert.ok(worker.includes('png: "image/png"'));
  assert.ok(worker.includes('webp: "image/webp"'));
  assert.ok(worker.includes('/^(materials|media)\\//.test(fileKey)'));
  assert.ok(student.includes('responseType.startsWith("image/")'));
  assert.ok(student.includes("URL.createObjectURL(imageBlob)"));
  assert.ok(student.includes("pdfjsLib.getDocument"));
  assert.ok(student.includes("URL.revokeObjectURL(activeImageObjectUrl)"));
});


test("admin material list exposes archive, restore, and separately confirmed permanent deletion", () => {
  const admin = read("admin.html");
  const worker = read("worker.js");
  assert.ok(admin.includes("حذف نهائي"));
  assert.ok(admin.includes("تأكيد الحذف النهائي:"));
  assert.ok(admin.includes("data-material-action"));
  assert.ok(admin.includes("materialsTbody').addEventListener('click'"));
  assert.ok(admin.includes("method:'DELETE'"));
  assert.ok(worker.includes('if (method === "DELETE" && path === "/api/admin/materials")'));
  assert.ok(worker.includes('SELECT COUNT(*) AS total FROM orders WHERE material_id = ?'));
  assert.ok(worker.includes('MATERIAL_HAS_ORDERS'));
  assert.ok(!worker.includes('DELETE FROM orders WHERE material_id = ?'));
  assert.ok(worker.includes('DELETE FROM materials WHERE id = ?'));
  assert.ok(worker.includes('DELETE FROM archived_materials WHERE material_id = ?'));
  assert.ok(worker.includes('const tableNames = new Set((tableResult.results || []).map((item) => String(item.name || "")))'));
  assert.ok(worker.includes('if (!tableNames.has(tableName)) return;'));
});
