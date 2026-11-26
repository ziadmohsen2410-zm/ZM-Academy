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
  assert.match(admin, /id="matSubjectId"><option value="">اختر المادة/, "Materials must select an existing subject");
  assert.match(admin, /if\(!name\|\|!grade\)/, "Subject creation must validate grade");
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
  assert.ok(worker.includes("n.audience_type IN ('all','parents')"));
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
  assert.ok(worker.includes("path.includes('/exam-attempts/') || (path.startsWith('/api/student/platform/exams/') && path.endsWith('/start'))"));
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
