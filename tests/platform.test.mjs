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
});

test("student exam results respect the exam show_results setting", () => {
  const worker = read("worker.js");
  const start = worker.indexOf("if (method==='POST' && /^\\/api\\/student\\/platform\\/exam-attempts");
  const end = worker.indexOf("if (method==='POST' && path==='/api/student/platform/ai')", start);
  const route = worker.slice(start, end);
  assert.ok(route.includes("e.show_results"));
  assert.ok(route.includes("score:showResults?score:null"));
  assert.ok(route.includes("results_hidden:!showResults"));
});

test("legacy admin APIs enforce role permissions instead of authentication alone", () => {
  const worker = read("worker.js");
  const start = worker.indexOf("// جميع مسارات الإدارة محمية");
  const end = worker.indexOf("// إدارة إعدادات الصفحة الرئيسية", start);
  const guard = worker.slice(start, end);
  assert.ok(guard.includes("legacyPermission"));
  assert.ok(guard.includes("requireAdminRole(request, env, legacyPermission)"));
  assert.ok(guard.includes('path.startsWith("/api/admin/orders") ? "orders"'));
  assert.ok(guard.includes('path.startsWith("/api/admin/device-requests") ? "devices"'));
  assert.ok(guard.includes('path.startsWith("/api/admin/materials") ? "content"'));
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
