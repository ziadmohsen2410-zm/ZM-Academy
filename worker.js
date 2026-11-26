const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100000;
const MAX_FILE_SIZE = 8 * 1024 * 1024;
const MAX_PRICE = 1000000;
const GITHUB_REPO = "ziadmohsen2410-zm/ZM-Academy-Storage";
const GITHUB_API = "https://api.github.com/repos/" + GITHUB_REPO + "/contents";

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers,
    },
  });
}

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "*")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
  const allowOrigin =
    allowed.includes("*") || allowed.includes(origin)
      ? allowed.includes("*")
        ? "*"
        : origin
      : "";

  return {
    ...(allowOrigin
      ? {
          "access-control-allow-origin": allowOrigin,
          vary: "Origin",
        }
      : {}),
    "access-control-allow-methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "access-control-allow-headers": "Content-Type, Authorization",
    "access-control-max-age": "86400",
  };
}

function reply(request, env, data, status = 200) {
  return json(data, status, corsHeaders(request, env));
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function clean(value, max = 200) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

async function ensureApiRateLimitTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS api_rate_limits (
      rate_key TEXT PRIMARY KEY,
      window_start INTEGER NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0
    )
  `).run();

  const cleanupBefore = Math.floor(Date.now() / 1000) - 86400;
  await env.DB.prepare(
    "DELETE FROM api_rate_limits WHERE window_start < ?"
  ).bind(cleanupBefore).run();
}

async function consumeApiRateLimit(env, request, scope, identity, maxAttempts, windowSeconds) {
  await ensureApiRateLimitTable(env);

  const ip = clean(request.headers.get("CF-Connecting-IP"), 80) || "unknown";
  const key = await sha256(`${scope}|${ip}|${String(identity || "*").toLowerCase()}`);
  const now = Math.floor(Date.now() / 1000);

  await env.DB.prepare(`
    INSERT INTO api_rate_limits (rate_key, window_start, attempts)
    VALUES (?, ?, 1)
    ON CONFLICT(rate_key) DO UPDATE SET
      attempts = CASE
        WHEN window_start + ? <= ? THEN 1
        ELSE attempts + 1
      END,
      window_start = CASE
        WHEN window_start + ? <= ? THEN ?
        ELSE window_start
      END
  `).bind(key, now, windowSeconds, now, windowSeconds, now, now).run();

  const row = await env.DB.prepare(
    "SELECT attempts FROM api_rate_limits WHERE rate_key = ?"
  ).bind(key).first();

  return Number(row?.attempts || 0) <= maxAttempts;
}

function randomToken(bytes = 32) {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

function toBase64Url(bytes) {
  return bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function fromBase64Url(value) {
  const padded =
    String(value || "").replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (String(value || "").length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function safeEqual(a, b) {
  const aa = String(a ?? "");
  const bb = String(b ?? "");
  if (aa.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < aa.length; i++) {
    diff |= aa.charCodeAt(i) ^ bb.charCodeAt(i);
  }
  return diff === 0;
}

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return toBase64Url(new Uint8Array(digest));
}

async function passwordHash(
  password,
  salt = crypto.getRandomValues(new Uint8Array(16))
) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: PBKDF2_ITERATIONS,
    },
    key,
    256
  );

  return `pbkdf2$${PBKDF2_ITERATIONS}$${toBase64Url(salt)}$${toBase64Url(
    new Uint8Array(bits)
  )}`;
}

async function verifyPassword(password, stored) {
  try {
    const parts = String(stored || "").split("$");

    if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;

    const iterations = Number(parts[1]);

    if (
      !Number.isInteger(iterations) ||
      iterations < 100000 ||
      iterations > 1000000
    ) {
      return false;
    }

    const salt = fromBase64Url(parts[2]);
    const expected = fromBase64Url(parts[3]);

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt,
          iterations,
        },
        key,
        expected.length * 8
      )
    );

    if (bits.length !== expected.length) return false;

    let diff = 0;
    for (let i = 0; i < bits.length; i++) {
      diff |= bits[i] ^ expected[i];
    }
    return diff === 0;
  } catch {
    return false;
  }
}

function bearer(request) {
  const value = request.headers.get("Authorization") || "";
  return value.startsWith("Bearer ") ? value.slice(7).trim() : "";
}

async function adminSession(request, env) {
  const token = bearer(request);
  if (!token) return null;

  const tokenHash = await sha256(token);

  const row = await env.DB.prepare(
    `SELECT s.id, s.admin_id, a.username
     FROM admin_sessions s
     JOIN admin_users a ON a.id = s.admin_id
     WHERE s.token_hash = ?
       AND s.expires_at > datetime('now')`
  )
    .bind(tokenHash)
    .first();

  return row ? { ...row, tokenHash } : null;
}

async function requireAdmin(request, env) {
  return await adminSession(request, env);
}

async function studentSession(request, env) {
  const token = bearer(request);
  if (!token) return null;

  const tokenHash = await sha256(token);

  const row = await env.DB.prepare(
    `SELECT ss.id, ss.student_id, s.name, s.phone, s.grade
     FROM student_sessions ss
     JOIN students s ON s.id = ss.student_id
     JOIN student_devices d
       ON d.student_id = ss.student_id
      AND d.device_token_hash = ss.device_token_hash
      AND d.status = 'approved'
     WHERE ss.token_hash = ?
       AND ss.expires_at > datetime('now')`
  )
    .bind(tokenHash)
    .first();

  return row ? { ...row, tokenHash } : null;
}

async function purgeExpiredSessions(env) {
  try {
    await Promise.all([
      env.DB.prepare(
        "DELETE FROM admin_sessions WHERE expires_at <= datetime('now')"
      ).run(),
      env.DB.prepare(
        "DELETE FROM student_sessions WHERE expires_at <= datetime('now')"
      ).run(),
    ]);
  } catch (error) {
    console.error("SESSION_PURGE_ERROR:", error?.message || error);
  }
}

function githubContentsUrl(fileKey) {
  const encodedPath = fileKey.split("/").map(encodeURIComponent).join("/");
  return `${GITHUB_API}/${encodedPath}`;
}

function githubHeaders(env, accept = "application/vnd.github+json") {
  return {
    Authorization: `Bearer ${env.GITHUB_STORAGE_TOKEN}`,
    Accept: accept,
    "User-Agent": "ZM-Academy",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

async function uploadToGitHub(env, fileBytes, fileName, contentType) {
  if (!env.GITHUB_STORAGE_TOKEN) {
    throw new Error("GitHub storage token is missing.");
  }

  const allowedTypes = [
    "application/pdf",
    "image/jpeg",
    "image/png",
    "image/webp",
  ];

  if (!allowedTypes.includes(contentType)) {
    throw new Error("File type is not allowed.");
  }

  if (fileBytes.length > MAX_FILE_SIZE) {
    throw new Error("File size must not exceed 8 MB.");
  }

  const safeName =
    fileName
      .replace(/[^a-zA-Z0-9._-]/g, "_")
      .slice(-100) || "file";

  const path = `materials/${crypto.randomUUID()}-${safeName}`;

  const response = await fetch(githubContentsUrl(path), {
    method: "PUT",
    headers: {
      ...githubHeaders(env),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      message: `Upload academy file: ${safeName}`,
      content: bytesToBase64(fileBytes),
    }),
  });

  if (!response.ok) {
    const responseText = await response.text();
    console.error("GitHub status:", response.status);
    console.error("GitHub response:", responseText.slice(0, 500));

    throw new Error(
      "GitHub storage upload failed: " +
        response.status +
        " - " +
        responseText.slice(0, 500)
    );
  }

  return path;
}

async function deleteFromGitHub(env, fileKey) {
  if (!env.GITHUB_STORAGE_TOKEN) return;
  if (
    !fileKey ||
    !fileKey.startsWith("materials/") ||
    fileKey.includes("..")
  ) {
    return;
  }

  const url = githubContentsUrl(fileKey);

  const current = await fetch(url, { headers: githubHeaders(env) });
  if (!current.ok) return;

  const meta = await current.json();
  if (!meta?.sha) return;

  const removed = await fetch(url, {
    method: "DELETE",
    headers: {
      ...githubHeaders(env),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      message: `Delete academy file: ${fileKey}`,
      sha: meta.sha,
    }),
  });

  if (!removed.ok) {
    console.error("GitHub delete failed:", removed.status);
  }
}

async function uploadStudentPhotoToGitHub(env, fileBytes, contentType, studentId) {
  if (!env.GITHUB_STORAGE_TOKEN) {
    throw new Error("GitHub storage token is missing.");
  }

  const extensions = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
  };

  const extension = extensions[contentType];

  if (!extension) {
    throw new Error("نوع الصورة غير مسموح.");
  }

  if (!fileBytes || fileBytes.length < 1 || fileBytes.length > 5 * 1024 * 1024) {
    throw new Error("حجم الصورة يجب ألا يتجاوز 5 ميجابايت.");
  }

  const fileKey =
    `student-photos/${studentId}/${crypto.randomUUID()}.${extension}`;

  const response = await fetch(githubContentsUrl(fileKey), {
    method: "PUT",
    headers: {
      ...githubHeaders(env),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      message: `Upload student photo: ${studentId}`,
      content: bytesToBase64(fileBytes),
    }),
  });

  if (!response.ok) {
    const details = await response.text();
    console.error("Student photo upload failed:", response.status, details.slice(0, 300));
    throw new Error("تعذر رفع الصورة إلى التخزين.");
  }

  return fileKey;
}

async function deleteStudentPhotoFromGitHub(env, fileKey, studentId) {
  const prefix = `student-photos/${studentId}/`;

  if (
    !env.GITHUB_STORAGE_TOKEN ||
    !fileKey ||
    !fileKey.startsWith(prefix) ||
    fileKey.includes("..")
  ) {
    return;
  }

  const fileUrl = githubContentsUrl(fileKey);
  const current = await fetch(fileUrl, {
    headers: githubHeaders(env),
  });

  if (!current.ok) return;

  const metadata = await current.json();
  if (!metadata?.sha) return;

  const removed = await fetch(fileUrl, {
    method: "DELETE",
    headers: {
      ...githubHeaders(env),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      message: `Delete old student photo: ${studentId}`,
      sha: metadata.sha,
    }),
  });

  if (!removed.ok) {
    console.error("Old student photo delete failed:", removed.status);
  }
}

function validStudentPhoto(bytes, contentType) {
  if (contentType === "image/jpeg") {
    return bytes.length >= 3 &&
      bytes[0] === 0xff &&
      bytes[1] === 0xd8 &&
      bytes[2] === 0xff;
  }

  if (contentType === "image/png") {
    return bytes.length >= 8 &&
      bytes[0] === 0x89 &&
      bytes[1] === 0x50 &&
      bytes[2] === 0x4e &&
      bytes[3] === 0x47 &&
      bytes[4] === 0x0d &&
      bytes[5] === 0x0a &&
      bytes[6] === 0x1a &&
      bytes[7] === 0x0a;
  }

  if (contentType === "image/webp") {
    return bytes.length >= 12 &&
      String.fromCharCode(...bytes.slice(0, 4)) === "RIFF" &&
      String.fromCharCode(...bytes.slice(8, 12)) === "WEBP";
  }

  return false;
}

// إنشاء جدول أرشيف المواد الدراسية
async function ensureHomepageSettingsTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS homepage_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      draft_json TEXT NOT NULL DEFAULT '{}',
      published_json TEXT NOT NULL DEFAULT '{}',
      status TEXT NOT NULL DEFAULT 'published',
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  await env.DB.prepare(`
    INSERT OR IGNORE INTO homepage_settings
      (id, draft_json, published_json, status)
    VALUES (1, '{}', '{}', 'published')
  `).run();
}

function parseHomepageJson(value) {
  try {
    const parsed = JSON.parse(String(value || '{}'));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed
      : {};
  } catch {
    return {};
  }
}

function parseJsonValue(value, fallback = null) {
  try { return JSON.parse(String(value ?? "null")); }
  catch { return fallback; }
}


// إنشاء جدول أرشيف الدروس
async function ensureArchivedMaterialsTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS archived_materials (
      material_id INTEGER PRIMARY KEY,
      archived_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
}

// إنشاء جدول أرشيف المواد الدراسية الرئيسية
async function ensureArchivedSubjectsTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS archived_subjects (
      subject_id INTEGER PRIMARY KEY,
      archived_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
}

// إنشاء جدول العناصر التي أخفاها الطالب من سجل مشترياته
async function ensureStudentHiddenPurchasesTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS student_hidden_purchases (
      student_id INTEGER NOT NULL,
      order_id INTEGER NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (student_id, order_id)
    )
  `).run();
}
async function ensurePasswordResetRequestsTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS password_reset_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      phone TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      reviewed_at TEXT,
      reviewed_by INTEGER
    )
  `).run();
}

// إنشاء جدول صور الطلاب
async function ensureStudentPhotosTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS student_photos (
      student_id INTEGER PRIMARY KEY,
      file_key TEXT NOT NULL,
      content_type TEXT NOT NULL,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
}

// جداول متابعة تقدم الطالب والمفضلة وأيام النشاط
async function ensureStudentLearningTables(env) {
  await env.DB.batch([
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS student_material_progress (
        student_id INTEGER NOT NULL,
        material_id INTEGER NOT NULL,
        last_page INTEGER NOT NULL DEFAULT 1,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (student_id, material_id)
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS student_favorites (
        student_id INTEGER NOT NULL,
        material_id INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (student_id, material_id)
      )
    `),
    env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS student_activity_days (
        student_id INTEGER NOT NULL,
        activity_date TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (student_id, activity_date)
      )
    `)
  ]);
}

const ADMIN_ROLE_PERMISSIONS = {
  super_admin: new Set(["pages", "content", "students", "orders", "security", "parent_links", "ads", "notifications", "analytics", "ai", "quizzes", "roles", "backups"]),
  admin: new Set(["pages", "content", "students", "orders", "security", "parent_links", "ads", "notifications", "analytics", "ai", "quizzes"]),
  content_manager: new Set(["pages", "content", "ads", "notifications", "analytics", "ai", "quizzes"]),
  teacher: new Set(["content", "notifications", "analytics", "ai", "quizzes"]),
  support: new Set(["students", "orders", "security", "parent_links", "notifications"]),
};

export function validatePageDocument(input) {
  if (!input || typeof input !== "object" || Array.isArray(input) || input.version !== 1 || !Array.isArray(input.blocks)) {
    return { ok: false, error: "مخطط الصفحة غير صالح." };
  }
  if (input.blocks.length > 60) return { ok: false, error: "الصفحة تحتوي على عدد عناصر أكبر من المسموح (60)." };
  const allowedTypes = new Set(["heading", "text", "button", "card", "image", "alert", "section", "spacer", "video"]);
  const allowedStyle = new Set(["color", "background", "align", "padding", "radius", "fontSize", "maxWidth"]);
  const cleanText = (value, max = 2000) => typeof value === "string" ? value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "").slice(0, max) : "";
  const safeUrl = (value, allowAnchor = true) => {
    if (typeof value !== "string" || value.length > 1000) return "";
    const v = value.trim();
    if (!v || v.includes("\\")) return "";
    if (/^https:\/\//i.test(v)) {
      try {
        const parsed = new URL(v);
        return parsed.protocol === "https:" && !parsed.username && !parsed.password ? v : "";
      } catch { return ""; }
    }
    if (/^\/(?!\/)[a-z0-9_./#-]*$/i.test(v)) {
      const segments = v.split("/");
      if (segments.some((segment) => segment === "." || segment === "..")) return "";
      return v;
    }
    if (allowAnchor && /^#[a-z0-9_-]+$/i.test(v)) return v;
    return "";
  };
  const blocks = [];
  for (const raw of input.blocks) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw) || !allowedTypes.has(raw.type)) {
      return { ok: false, error: "يوجد عنصر غير مسموح داخل الصفحة." };
    }
    const id = cleanText(raw.id, 40);
    if (!/^[A-Za-z0-9_-]{1,40}$/.test(id)) return { ok: false, error: "معرّف عنصر الصفحة غير صالح." };
    const content = raw.content && typeof raw.content === "object" && !Array.isArray(raw.content) ? raw.content : {};
    const safeContent = {
      title: cleanText(content.title, 180),
      text: cleanText(content.text, 3000),
      buttonText: cleanText(content.buttonText, 80),
      alt: cleanText(content.alt, 180),
      href: safeUrl(content.href),
      src: safeUrl(content.src, false),
    };
    if ((raw.type === "button" || raw.type === "card") && content.href && !safeContent.href) {
      return { ok: false, error: "رابط أحد العناصر غير آمن. استخدم HTTPS أو رابطًا داخليًا." };
    }
    if (raw.type === "image" && content.src && !safeContent.src) {
      return { ok: false, error: "رابط الصورة غير آمن. استخدم HTTPS أو مسارًا داخل assets." };
    }
    const style = {};
    if (raw.style && typeof raw.style === "object" && !Array.isArray(raw.style)) {
      for (const [key, value] of Object.entries(raw.style)) {
        if (!allowedStyle.has(key)) continue;
        if (["color", "background"].includes(key) && /^#[0-9a-f]{6}$/i.test(String(value))) style[key] = String(value);
        if (key === "align" && ["right", "center", "left"].includes(value)) style.align = value;
        if (["padding", "radius", "fontSize", "maxWidth"].includes(key)) {
          const n = Number(value);
          const limits = { padding: [0, 64], radius: [0, 48], fontSize: [12, 48], maxWidth: [280, 1400] }[key];
          if (Number.isFinite(n) && n >= limits[0] && n <= limits[1]) style[key] = n;
        }
      }
    }
    const responsive = {};
    if (raw.responsive && typeof raw.responsive === "object" && !Array.isArray(raw.responsive)) {
      for (const device of ["mobile", "tablet", "desktop"]) {
        const cfg = raw.responsive[device];
        if (!cfg || typeof cfg !== "object" || Array.isArray(cfg)) continue;
        const deviceConfig = {};
        if (typeof cfg.hidden === "boolean") deviceConfig.hidden = cfg.hidden;
        const width = Number(cfg.width);
        if (Number.isFinite(width) && width >= 20 && width <= 100) deviceConfig.width = width;
        responsive[device] = deviceConfig;
      }
    }
    blocks.push({ id, type: raw.type, visible: raw.visible !== false, content: safeContent, style, responsive });
  }
  return { ok: true, value: { version: 1, blocks } };
}

export function sanitizeQuizDefinition(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return { ok: false, error: "تعريف الاختبار غير صالح." };
  const title = clean(input.title, 160);
  const grade = clean(input.grade, 80);
  const description = clean(input.description, 1200);
  const duration = Number(input.duration_minutes ?? 30);
  const maxAttempts = Number(input.max_attempts ?? 1);
  const subjectId = input.subject_id === null || input.subject_id === undefined || input.subject_id === "" ? null : Number(input.subject_id);
  if (!title || !grade || !Number.isInteger(duration) || duration < 5 || duration > 300 || !Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 20 || (subjectId !== null && (!Number.isInteger(subjectId) || subjectId < 1))) {
    return { ok: false, error: "تحقق من العنوان والصف والمدة وعدد المحاولات والمادة." };
  }
  if (!Array.isArray(input.questions) || input.questions.length < 1 || input.questions.length > 100) return { ok: false, error: "يجب إضافة سؤال واحد على الأقل، وبحد أقصى 100 سؤال." };
  const questions = [];
  for (let index = 0; index < input.questions.length; index++) {
    const item = input.questions[index];
    if (!item || typeof item !== "object" || Array.isArray(item)) return { ok: false, error: `السؤال ${index + 1} غير صالح.` };
    const type = item.type;
    const prompt = clean(item.prompt, 1200);
    const points = Number(item.points ?? 1);
    if (!prompt || !["mcq", "true_false", "essay"].includes(type) || !Number.isFinite(points) || points <= 0 || points > 100) return { ok: false, error: `بيانات السؤال ${index + 1} غير صالحة.` };
    let options = [];
    let answer = null;
    if (type === "mcq") {
      options = Array.isArray(item.options) ? item.options.map((x) => clean(x, 220)).filter(Boolean).slice(0, 6) : [];
      const correct = Number(item.correct_index);
      if (options.length < 2 || !Number.isInteger(correct) || correct < 0 || correct >= options.length) return { ok: false, error: `خيارات أو إجابة السؤال ${index + 1} غير صالحة.` };
      answer = correct;
    } else if (type === "true_false") {
      if (typeof item.correct_value !== "boolean") return { ok: false, error: `حدد إجابة صح أو خطأ للسؤال ${index + 1}.` };
      options = ["صح", "خطأ"];
      answer = item.correct_value;
    }
    questions.push({ type, prompt, points, options, answer, sort_order: index });
  }
  const startsAt = input.starts_at ? new Date(input.starts_at) : null;
  const endsAt = input.ends_at ? new Date(input.ends_at) : null;
  if ((startsAt && Number.isNaN(startsAt.getTime())) || (endsAt && Number.isNaN(endsAt.getTime())) || (startsAt && endsAt && startsAt >= endsAt)) return { ok: false, error: "موعد بداية الاختبار أو نهايته غير صالح." };
  return { ok: true, value: { title, grade, description, duration_minutes: duration, max_attempts: maxAttempts, subject_id: subjectId, starts_at: startsAt?.toISOString() || null, ends_at: endsAt?.toISOString() || null, questions } };
}

export function sanitizeStudentPreferences(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const result = {};
  const choices = {
    mode: ["system", "dark", "light"],
    cardStyle: ["solid", "glass", "outline"],
    contentLayout: ["grid", "list"],
    template: ["future", "glass", "minimal", "luxury", "editorial"],
  };
  for (const [key, allowed] of Object.entries(choices)) {
    if (allowed.includes(input[key])) result[key] = input[key];
  }
  for (const key of ["primary", "accent", "background"]) {
    if (typeof input[key] === "string" && /^#[0-9a-f]{6}$/i.test(input[key])) result[key] = input[key];
  }
  const scale = Number(input.fontScale);
  if (Number.isFinite(scale) && scale >= 0.9 && scale <= 1.15) result.fontScale = scale;
  if (typeof input.reduceMotion === "boolean") result.reduceMotion = input.reduceMotion;
  if (Array.isArray(input.dashboardOrder)) {
    const allowed = new Set(["progress", "subjects", "favorites", "announcements", "activity"]);
    result.dashboardOrder = [...new Set(input.dashboardOrder.filter((x) => allowed.has(x)))].slice(0, 5);
  }
  return result;
}

function normalizePhone(value) {
  return clean(value, 30).replace(/[^0-9]/g, "").slice(-20);
}

async function getAdminRole(env, adminId) {
  const row = await env.DB.prepare("SELECT role FROM admin_role_assignments WHERE admin_id = ?").bind(adminId).first();
  return row?.role || "super_admin"; // Existing administrators remain fully functional until explicitly assigned a restricted role.
}

async function requireAdminPermission(env, session, permission) {
  const role = await getAdminRole(env, session.admin_id);
  return ADMIN_ROLE_PERMISSIONS[role]?.has(permission) === true;
}

function adminPermissionForPath(path) {
  if (path === "/api/admin/me") return null;
  if (/^\/api\/admin\/(homepage|pages)(\/|$)/.test(path)) return "pages";
  if (path === "/api/subjects" || /^\/api\/admin\/(subjects|materials|upload|media)(\/|$)/.test(path)) return "content";
  if (/^\/api\/admin\/students(\/|$)/.test(path)) return "students";
  if (/^\/api\/admin\/orders(\/|$)/.test(path)) return "orders";
  if (/^\/api\/admin\/(device-requests|password-reset-requests)(\/|$)/.test(path)) return "security";
  if (/^\/api\/admin\/parent-link-requests(\/|$)/.test(path)) return "parent_links";
  if (/^\/api\/admin\/ads(\/|$)/.test(path)) return "ads";
  if (/^\/api\/admin\/notifications(\/|$)/.test(path)) return "notifications";
  if (/^\/api\/admin\/(analytics|audit-logs)(\/|$)/.test(path)) return "analytics";
  if (/^\/api\/admin\/roles(\/|$)/.test(path)) return "roles";
  if (/^\/api\/admin\/ai(\/|$)/.test(path)) return "ai";
  if (/^\/api\/admin\/(quizzes|quiz-attempts)(\/|$)/.test(path)) return "quizzes";
  // Unclassified administrative endpoints are reserved for Super Admin until explicitly mapped.
  return "roles";
}

async function writeAuditLog(request, env, actorType, actorId, action, entityType = "", entityId = "", details = {}) {
  try {
    const serialized = JSON.stringify(details && typeof details === "object" ? details : {}).slice(0, 4000);
    await env.DB.prepare(`
      INSERT INTO audit_logs (actor_type, actor_id, action, entity_type, entity_id, details_json, ip_address)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(actorType, actorId || null, clean(action, 100), clean(entityType, 80), String(entityId || "").slice(0, 100), serialized, clean(request.headers.get("CF-Connecting-IP"), 80)).run();
  } catch (error) {
    console.error("AUDIT_LOG_WRITE_FAILED:", error?.message || error);
  }
}

async function parentSession(request, env) {
  const token = bearer(request);
  if (!token) return null;
  const tokenHash = await sha256(token);
  const row = await env.DB.prepare(`
    SELECT s.id, s.parent_id, p.name, p.phone
    FROM parent_sessions s
    JOIN parent_accounts p ON p.id = s.parent_id
    WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND p.is_active = 1
  `).bind(tokenHash).first();
  return row ? { ...row, tokenHash } : null;
}

export function isValidMediaBytes(bytes, contentType) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > MAX_FILE_SIZE) return false;
  if (contentType === "application/pdf") return bytes.length >= 5 && new TextDecoder().decode(bytes.slice(0, 5)) === "%PDF-";
  if (contentType === "image/jpeg") return bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  if (contentType === "image/png") return bytes.length >= 8 && [137,80,78,71,13,10,26,10].every((v, i) => bytes[i] === v);
  if (contentType === "image/webp") return bytes.length >= 12 && new TextDecoder().decode(bytes.slice(0, 4)) === "RIFF" && new TextDecoder().decode(bytes.slice(8, 12)) === "WEBP";
  return false;
}

async function requestAI(env, messages, options = {}) {
  if (!env.AI_API_KEY) throw new Error("AI_NOT_CONFIGURED");
  const endpoint = clean(env.AI_API_URL || "https://api.openai.com/v1/chat/completions", 500);
  if (!/^https:\/\//i.test(endpoint)) throw new Error("AI_ENDPOINT_INVALID");
  const model = clean(env.AI_MODEL, 100);
  if (!model) throw new Error("AI_MODEL_NOT_CONFIGURED");
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Authorization": `Bearer ${env.AI_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ model, messages, temperature: options.temperature ?? 0.4, max_tokens: options.maxTokens ?? 900 }),
  });
  if (!response.ok) {
    console.error("AI_PROVIDER_RESPONSE:", response.status);
    throw new Error("AI_PROVIDER_ERROR");
  }
  const data = await response.json();
  const content = data?.choices?.[0]?.message?.content;
  if (typeof content !== "string" || !content.trim()) throw new Error("AI_EMPTY_RESPONSE");
  return content.slice(0, 12000);
}

async function route(request, env) {
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders(request, env),
    });
  }

  if (!env.DB) {
    return reply(
      request,
      env,
      {
        success: false,
        error: "Database binding DB is missing.",
      },
      500
    );
  }

  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";

  if (method === "GET" && path === "/api/health") {
    try {
      await env.DB.prepare("SELECT 1").first();

      return reply(request, env, {
        success: true,
        database: "connected",
      });
    } catch {
      return reply(
        request,
        env,
        {
          success: false,
          database: "error",
        },
        500
      );
    }
  }

  // إعدادات الصفحة الرئيسية المنشورة للزوار
  if (method === "GET" && path === "/api/homepage") {
    try {
      await ensureHomepageSettingsTable(env);

      const row = await env.DB.prepare(`
        SELECT published_json
        FROM homepage_settings
        WHERE id = 1
      `).first();

      return reply(request, env, {
        success: true,
        settings: parseHomepageJson(row?.published_json)
      });
    } catch (error) {
      return reply(request, env, {
        success: false,
        error: "تعذر تحميل إعدادات الصفحة الرئيسية."
      }, 500);
    }
  }

  // بوابة ولي الأمر: حساب منفصل وجلسات مستقلة عن حساب الطالب.
  if (method === "POST" && path === "/api/parents/register") {
    const body = await readBody(request);
    const name = clean(body?.name, 120);
    const phone = normalizePhone(body?.phone);
    const password = typeof body?.password === "string" ? body.password : "";
    if (name.length < 2 || phone.length < 8 || phone.length > 20 || password.length < 10 || password.length > 200) {
      return reply(request, env, { success: false, error: "أدخل اسمًا صحيحًا ورقم هاتف من 8 إلى 20 رقمًا وكلمة مرور لا تقل عن 10 أحرف." }, 400);
    }
    const ipAllowed = await consumeApiRateLimit(env, request, "parent-register-ip", "*", 8, 3600);
    const phoneAllowed = await consumeApiRateLimit(env, request, "parent-register-phone", phone, 3, 3600);
    if (!ipAllowed || !phoneAllowed) return reply(request, env, { success: false, error: "محاولات التسجيل كثيرة. حاول لاحقًا." }, 429);
    const hash = await passwordHash(password);
    try {
      const result = await env.DB.prepare(`INSERT INTO parent_accounts (name, phone, password_hash) VALUES (?, ?, ?)`)
        .bind(name, phone, hash).run();
      await writeAuditLog(request, env, "parent", result.meta?.last_row_id, "parent.register", "parent_account", result.meta?.last_row_id, {});
      return reply(request, env, { success: true, parent_id: result.meta?.last_row_id, message: "تم إنشاء الحساب. يمكنك تسجيل الدخول وطلب ربط حساب الأبناء." }, 201);
    } catch (error) {
      if (String(error?.message || "").toLowerCase().includes("unique")) return reply(request, env, { success: false, error: "رقم الهاتف مسجل بالفعل." }, 409);
      throw error;
    }
  }

  if (method === "POST" && path === "/api/parents/login") {
    const body = await readBody(request);
    const phone = normalizePhone(body?.phone);
    const password = typeof body?.password === "string" ? body.password : "";
    if (!phone || !password) return reply(request, env, { success: false, error: "أدخل رقم الهاتف وكلمة المرور." }, 400);
    const ipAllowed = await consumeApiRateLimit(env, request, "parent-login-ip", "*", 40, 900);
    const phoneAllowed = await consumeApiRateLimit(env, request, "parent-login-phone", phone, 8, 900);
    if (!ipAllowed || !phoneAllowed) return reply(request, env, { success: false, error: "محاولات تسجيل الدخول كثيرة. انتظر قليلًا." }, 429);
    const account = await env.DB.prepare(`SELECT id, name, phone, password_hash FROM parent_accounts WHERE phone = ? AND is_active = 1`).bind(phone).first();
    if (!account || !(await verifyPassword(password, account.password_hash))) return reply(request, env, { success: false, error: "رقم الهاتف أو كلمة المرور غير صحيحة." }, 401);
    const token = randomToken();
    const tokenHash = await sha256(token);
    await env.DB.prepare(`INSERT INTO parent_sessions (parent_id, token_hash, expires_at) VALUES (?, ?, datetime('now', ?))`)
      .bind(account.id, tokenHash, `+${SESSION_DAYS} days`).run();
    return reply(request, env, { success: true, token, expiresInDays: SESSION_DAYS, parent: { id: account.id, name: account.name, phone: account.phone } });
  }

  if (path.startsWith("/api/parent/")) {
    const parent = await parentSession(request, env);
    if (!parent) return reply(request, env, { success: false, error: "يلزم تسجيل دخول ولي الأمر." }, 401);

    if (method === "POST" && path === "/api/parent/logout") {
      await env.DB.prepare("DELETE FROM parent_sessions WHERE token_hash = ?").bind(parent.tokenHash).run();
      return reply(request, env, { success: true });
    }
    if (method === "GET" && path === "/api/parent/me") {
      return reply(request, env, { success: true, parent: { id: parent.parent_id, name: parent.name, phone: parent.phone } });
    }
    if (method === "POST" && path === "/api/parent/link-requests") {
      const body = await readBody(request);
      const studentPhone = normalizePhone(body?.student_phone);
      if (studentPhone.length < 8) return reply(request, env, { success: false, error: "أدخل رقم هاتف الطالب المسجل." }, 400);
      const student = await env.DB.prepare(`SELECT id, parent_phone FROM students WHERE phone = ? OR replace(replace(replace(replace(replace(phone, '+', ''), ' ', ''), '-', ''), '(', ''), ')', '') = ? LIMIT 1`).bind(studentPhone, studentPhone).first();
      // لا نكشف ما إذا كان رقم الطالب مسجلًا؛ يجب أن يطابق هاتف ولي الأمر المسجل مع الطالب.
      if (!student || normalizePhone(student.parent_phone) !== normalizePhone(parent.phone)) {
        return reply(request, env, { success: false, error: "تعذر إرسال الطلب. تحقق من رقم الطالب أو تواصل مع الإدارة." }, 400);
      }
      const alreadyLinked = await env.DB.prepare("SELECT 1 AS ok FROM parent_student_links WHERE parent_id = ? AND student_id = ?").bind(parent.parent_id, student.id).first();
      if (alreadyLinked) return reply(request, env, { success: false, error: "هذا الطالب مرتبط بالفعل بحسابك." }, 409);
      const result = await env.DB.prepare(`INSERT INTO parent_link_requests (parent_id, student_id, status) VALUES (?, ?, 'pending') ON CONFLICT(parent_id, student_id) DO UPDATE SET status = 'pending', created_at = CURRENT_TIMESTAMP, reviewed_at = NULL, reviewed_by = NULL`)
        .bind(parent.parent_id, student.id).run();
      await writeAuditLog(request, env, "parent", parent.parent_id, "parent.link_request", "student", student.id, {});
      return reply(request, env, { success: true, request_id: result.meta?.last_row_id || null, message: "تم إرسال طلب الربط لمراجعة الإدارة." }, 201);
    }
    if (method === "GET" && path === "/api/parent/link-requests") {
      const rows = await env.DB.prepare(`
        SELECT r.id, r.status, r.created_at, r.reviewed_at, s.name AS student_name, s.grade
        FROM parent_link_requests r JOIN students s ON s.id = r.student_id
        WHERE r.parent_id = ? ORDER BY r.id DESC LIMIT 100
      `).bind(parent.parent_id).all();
      return reply(request, env, { success: true, requests: rows.results || [] });
    }
    if (method === "GET" && path === "/api/parent/children") {
      await ensureStudentLearningTables(env);
      const rows = await env.DB.prepare(`
        SELECT s.id, s.name, s.grade, s.school, s.governorate, l.linked_at,
          (SELECT COUNT(*) FROM student_material_progress p WHERE p.student_id = s.id) AS progress_count,
          (SELECT COUNT(*) FROM orders o WHERE o.student_id = s.id) AS order_count
        FROM parent_student_links l JOIN students s ON s.id = l.student_id
        WHERE l.parent_id = ? ORDER BY s.name
      `).bind(parent.parent_id).all();
      return reply(request, env, { success: true, children: rows.results || [] });
    }
    const childMatch = path.match(/^\/api\/parent\/children\/(\d+)$/);
    if (method === "GET" && childMatch) {
      await ensureStudentLearningTables(env);
      const studentId = Number(childMatch[1]);
      const linked = await env.DB.prepare("SELECT student_id FROM parent_student_links WHERE parent_id = ? AND student_id = ?")
        .bind(parent.parent_id, studentId).first();
      if (!linked) return reply(request, env, { success: false, error: "الطالب غير مرتبط بهذا الحساب." }, 404);
      const [student, subjects, orders, progress, quizResults] = await Promise.all([
        env.DB.prepare("SELECT id, name, grade, school, governorate, created_at FROM students WHERE id = ?").bind(studentId).first(),
        env.DB.prepare(`SELECT sub.id, sub.name, sub.grade FROM student_subjects ss JOIN subjects sub ON sub.id = ss.subject_id WHERE ss.student_id = ? ORDER BY sub.name`).bind(studentId).all(),
        env.DB.prepare(`SELECT o.id, o.status, o.created_at, m.title AS material_title, m.price FROM orders o LEFT JOIN materials m ON m.id = o.material_id WHERE o.student_id = ? ORDER BY o.id DESC LIMIT 50`).bind(studentId).all(),
        env.DB.prepare(`SELECT COUNT(*) AS total, MAX(updated_at) AS last_activity FROM student_material_progress WHERE student_id = ?`).bind(studentId).first(),
        env.DB.prepare(`SELECT a.id, q.title AS quiz_title, a.score, a.max_score, a.status, a.submitted_at, a.graded_at, a.teacher_feedback FROM quiz_attempts a JOIN quizzes q ON q.id = a.quiz_id WHERE a.student_id = ? AND a.status = 'graded' ORDER BY a.graded_at DESC, a.id DESC LIMIT 50`).bind(studentId).all(),
      ]);
      return reply(request, env, { success: true, student, subjects: subjects.results || [], orders: orders.results || [], progress: progress || { total: 0, last_activity: null }, quiz_results: quizResults.results || [] });
    }
    if (method === "GET" && path === "/api/parent/ads") {
      const rows = await env.DB.prepare(`SELECT id, title, body, image_url, target_url, button_text, placement FROM ads WHERE is_active = 1 AND audience IN ('all','parents') AND placement = 'parent' AND (starts_at IS NULL OR datetime(starts_at) <= datetime('now')) AND (ends_at IS NULL OR datetime(ends_at) >= datetime('now')) ORDER BY priority DESC, id DESC LIMIT 20`).all();
      if (rows.results?.length) await env.DB.batch(rows.results.map((ad) => env.DB.prepare("UPDATE ads SET impressions = impressions + 1 WHERE id = ?").bind(ad.id)));
      return reply(request, env, { success: true, ads: rows.results || [] });
    }
    if (method === "GET" && path === "/api/parent/notifications") {
      const rows = await env.DB.prepare(`
        SELECT n.id, n.title, n.body, n.is_important, n.scheduled_at, r.read_at
        FROM notification_recipients r JOIN notifications n ON n.id = r.notification_id
        WHERE r.recipient_type = 'parent' AND r.recipient_id = ? AND n.scheduled_at <= datetime('now')
        ORDER BY n.is_important DESC, n.id DESC LIMIT 100
      `).bind(parent.parent_id).all();
      return reply(request, env, { success: true, notifications: rows.results || [] });
    }
    const parentReadMatch = path.match(/^\/api\/parent\/notifications\/(\d+)\/read$/);
    if (method === "POST" && parentReadMatch) {
      const result = await env.DB.prepare(`UPDATE notification_recipients SET read_at = CURRENT_TIMESTAMP WHERE notification_id = ? AND recipient_type = 'parent' AND recipient_id = ?`)
        .bind(Number(parentReadMatch[1]), parent.parent_id).run();
      if (!(result.meta?.changes || 0)) return reply(request, env, { success: false, error: "الإشعار غير موجود." }, 404);
      return reply(request, env, { success: true });
    }
    return reply(request, env, { success: false, error: "Parent endpoint not found." }, 404);
  }

  // الإعلانات العامة: لا تعرض إلا العناصر النشطة ضمن فترة العرض.
  if (method === "GET" && path === "/api/ads") {
    const placement = clean(url.searchParams.get("placement") || "home", 30);
    const rows = await env.DB.prepare(`
      SELECT id, title, body, image_url, target_url, button_text, placement
      FROM ads
      WHERE is_active = 1 AND audience = 'all' AND placement = ?
        AND (starts_at IS NULL OR datetime(starts_at) <= datetime('now'))
        AND (ends_at IS NULL OR datetime(ends_at) >= datetime('now'))
      ORDER BY priority DESC, id DESC LIMIT 20
    `).bind(placement).all();
    if (rows.results?.length) {
      await env.DB.batch(rows.results.map((ad) => env.DB.prepare("UPDATE ads SET impressions = impressions + 1 WHERE id = ?").bind(ad.id)));
    }
    return reply(request, env, { success: true, ads: rows.results || [] });
  }
  const adClick = path.match(/^\/api\/ads\/(\d+)\/click$/);
  if (method === "POST" && adClick) {
    const result = await env.DB.prepare(`UPDATE ads SET clicks = clicks + 1 WHERE id = ? AND is_active = 1`).bind(Number(adClick[1])).run();
    return reply(request, env, { success: true, tracked: Boolean(result.meta?.changes) });
  }

  // Public media endpoint serves only explicitly-public image assets from private GitHub Storage.
  const publicMediaMatch = path.match(/^\/api\/media\/(\d+)$/);
  if (method === "GET" && publicMediaMatch) {
    const asset = await env.DB.prepare("SELECT file_key, content_type FROM media_assets WHERE id = ? AND is_public = 1 AND content_type LIKE 'image/%'")
      .bind(Number(publicMediaMatch[1])).first();
    if (!asset || !asset.file_key?.startsWith("materials/") || asset.file_key.includes("..")) {
      return reply(request, env, { success: false, error: "الوسيط غير موجود أو غير منشور." }, 404);
    }
    if (!env.GITHUB_STORAGE_TOKEN) return reply(request, env, { success: false, error: "خدمة الوسائط غير مهيأة." }, 503);
    const stored = await fetch(githubContentsUrl(asset.file_key), { headers: githubHeaders(env, "application/vnd.github.raw") });
    if (!stored.ok) return reply(request, env, { success: false, error: "تعذر تحميل الملف من التخزين." }, 502);
    return new Response(stored.body, { status: 200, headers: {
      ...corsHeaders(request, env), "Content-Type": asset.content_type, "X-Content-Type-Options": "nosniff",
      "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400"
    }});
  }

  // Published custom pages only. A missing slug is never auto-generated from a user request.
  const publishedPageMatch = path.match(/^\/api\/pages\/([a-z0-9][a-z0-9-]{1,59})$/);
  if (method === "GET" && publishedPageMatch) {
    const page = await env.DB.prepare("SELECT slug, title, published_json, updated_at FROM platform_pages WHERE slug = ? AND status = 'published'").bind(publishedPageMatch[1]).first();
    if (!page) return reply(request, env, { success: false, error: "الصفحة غير موجودة أو غير منشورة." }, 404);
    const validated = validatePageDocument(parseHomepageJson(page.published_json));
    if (!validated.ok) return reply(request, env, { success: false, error: "تعذر عرض الصفحة المنشورة." }, 500);
    return reply(request, env, { success: true, page: { slug: page.slug, title: page.title, document: validated.value, updated_at: page.updated_at } });
  }

  // إنشاء حساب الإدارة لأول مرة
  if (method === "POST" && path === "/api/admin/setup") {
    const setupKey = String(env.ADMIN_SETUP_KEY || "").trim();
    if (!setupKey) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "Admin setup is not configured.",
        },
        503
      );
    }

    const body = await readBody(request);

    if (!safeEqual(clean(body?.setupKey, 300), setupKey)) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "Invalid setup key.",
        },
        403
      );
    }

    const username = clean(body?.username, 60);
    const password = typeof body?.password === "string" ? body.password : "";

    if (
      !/^[A-Za-z0-9_.-]{3,60}$/.test(username) ||
      password.length < 12 ||
      password.length > 200
    ) {
      return reply(
        request,
        env,
        {
          success: false,
          error:
            "Username must be 3-60 characters; password must be at least 12 characters.",
        },
        400
      );
    }

    const count = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM admin_users"
    ).first();

    if ((count?.n || 0) > 0) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "An admin already exists. Setup is closed.",
        },
        409
      );
    }


    const hash = await passwordHash(password);

    try {
      const result = await env.DB.prepare(
        `INSERT INTO admin_users (username, password_hash)
         SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM admin_users)`
      )
        .bind(username, hash)
        .run();

      if (!(result.meta?.changes || 0)) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "An admin already exists. Setup is closed.",
          },
          409
        );
      }

      return reply(
        request,
        env,
        {
          success: true,
          message: "Admin account created. You can now sign in.",
        },
        201
      );
    } catch {
      return reply(
        request,
        env,
        {
          success: false,
          error: "Could not create admin account.",
        },
        500
      );
    }
  }

  // تسجيل دخول الإدارة
  if (method === "POST" && path === "/api/admin/login") {
    await purgeExpiredSessions(env);

    const body = await readBody(request);
    const username = clean(body?.username, 60);
    const password = typeof body?.password === "string" ? body.password : "";

    if (!username || !password) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "Username and password are required.",
        },
        400
      );
    }

    const adminIpAllowed = await consumeApiRateLimit(env, request, "admin-login-ip", "*", 60, 900);
    const adminUserAllowed = await consumeApiRateLimit(env, request, "admin-login-user", username, 8, 900);
    if (!adminIpAllowed || !adminUserAllowed) {
      return reply(request, env, {
        success: false,
        error: "محاولات تسجيل الدخول كثيرة. انتظر 15 دقيقة ثم حاول مرة أخرى.",
      }, 429);
    }

    const admin = await env.DB.prepare(
      "SELECT id, username, password_hash FROM admin_users WHERE username = ?"
    )
      .bind(username)
      .first();

    if (!admin || !(await verifyPassword(password, admin.password_hash))) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "Invalid username or password.",
        },
        401
      );
    }

    const token = randomToken();
    const tokenHash = await sha256(token);

    await env.DB.prepare(
      `INSERT INTO admin_sessions
       (token_hash, expires_at, admin_id)
       VALUES (?, datetime('now', ?), ?)`
    )
      .bind(tokenHash, `+${SESSION_DAYS} days`, admin.id)
      .run();

    return reply(request, env, {
      success: true,
      token,
      expiresInDays: SESSION_DAYS,
      admin: {
        id: admin.id,
        username: admin.username,
      },
    });
  }

  // طلب استعادة كلمة مرور الطالب
if (method === "POST" && path === "/api/password-reset/request") {
  await ensurePasswordResetRequestsTable(env);

  const body = await readBody(request);
  const username = clean(body?.username, 40).toLowerCase();
  const phone = clean(body?.phone, 30).replace(/[^\d]/g, "");

  if (!username || !phone) {
    return reply(request, env, {
      success: false,
      error: "اكتب اسم المستخدم ورقم الهاتف.",
    }, 400);
  }

  const resetIpAllowed = await consumeApiRateLimit(env, request, "password-reset-ip", "*", 10, 3600);
  const resetUserAllowed = await consumeApiRateLimit(env, request, "password-reset-user", username, 3, 3600);
  if (!resetIpAllowed || !resetUserAllowed) {
    return reply(request, env, {
      success: true,
      message: "إذا كانت البيانات صحيحة، سيصل طلبك للإدارة للمراجعة.",
    });
  }

  const account = await env.DB.prepare(`
    SELECT a.student_id, a.username, s.phone
    FROM student_accounts a
    JOIN students s ON s.id = a.student_id
    WHERE LOWER(a.username) = ?
  `).bind(username).first();

  const savedPhone = String(account?.phone || "").replace(/[^\d]/g, "");

  if (!account || savedPhone !== phone) {
    return reply(request, env, {
      success: true,
      message: "إذا كانت البيانات صحيحة، سيصل طلبك للإدارة للمراجعة.",
    });
  }

  const existing = await env.DB.prepare(`
    SELECT id FROM password_reset_requests
    WHERE student_id = ? AND status = 'pending'
    LIMIT 1
  `).bind(account.student_id).first();

  if (!existing) {
    await env.DB.prepare(`
      INSERT INTO password_reset_requests
        (student_id, username, phone, status)
      VALUES (?, ?, ?, 'pending')
    `).bind(account.student_id, username, phone).run();
  }

  return reply(request, env, {
    success: true,
    message: "إذا كانت البيانات صحيحة، سيصل طلبك للإدارة للمراجعة.",
  });
}

  // تسجيل خروج الإدارة
  if (method === "POST" && path === "/api/admin/logout") {
    const session = await adminSession(request, env);

    if (session) {
      await env.DB.prepare(
        "DELETE FROM admin_sessions WHERE token_hash = ?"
      )
        .bind(session.tokenHash)
        .run();
    }

    return reply(request, env, { success: true });
  }

  // جميع مسارات الإدارة محمية
  if (
    path.startsWith("/api/admin/") ||
    (path === "/api/subjects" && ["POST", "PUT", "DELETE"].includes(method))
  ) {
    const session = await requireAdmin(request, env);

    if (!session) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "Unauthorized.",
        },
        401
      );
    }

    const requiredPermission = adminPermissionForPath(path);
    if (requiredPermission && !(await requireAdminPermission(env, session, requiredPermission))) {
      return reply(request, env, { success: false, error: "ليست لديك صلاحية لتنفيذ هذه العملية." }, 403);
    }

    // Analytics: counts are calculated from existing academy tables; no legacy data is copied or rewritten.
    if (method === "GET" && path === "/api/admin/analytics") {
      if (!(await requireAdminPermission(env, session, "analytics"))) return reply(request, env, { success: false, error: "ليست لديك صلاحية عرض التقارير." }, 403);
      const [students, newStudents, activeSessions, pendingOrders, completedOrders, materials, pendingDevices, activeAds] = await Promise.all([
        env.DB.prepare("SELECT COUNT(*) AS total FROM students").first(),
        env.DB.prepare("SELECT COUNT(*) AS total FROM students WHERE created_at >= datetime('now','-30 days')").first(),
        env.DB.prepare("SELECT COUNT(*) AS total FROM student_sessions WHERE expires_at > datetime('now')").first(),
        env.DB.prepare("SELECT COUNT(*) AS total FROM orders WHERE status = 'pending'").first(),
        env.DB.prepare(`SELECT COUNT(*) AS total, COALESCE(SUM(m.price),0) AS revenue FROM orders o JOIN materials m ON m.id = o.material_id WHERE o.status = 'completed'`).first(),
        env.DB.prepare("SELECT COUNT(*) AS total FROM materials").first(),
        env.DB.prepare("SELECT COUNT(*) AS total FROM student_devices WHERE status = 'pending'").first(),
        env.DB.prepare("SELECT COUNT(*) AS total FROM ads WHERE is_active = 1 AND (starts_at IS NULL OR datetime(starts_at) <= datetime('now')) AND (ends_at IS NULL OR datetime(ends_at) >= datetime('now'))").first(),
      ]);
      return reply(request, env, { success: true, generated_at: new Date().toISOString(), stats: {
        students: Number(students?.total || 0), new_students_30d: Number(newStudents?.total || 0), active_sessions: Number(activeSessions?.total || 0),
        pending_orders: Number(pendingOrders?.total || 0), completed_orders: Number(completedOrders?.total || 0), revenue_egp: Number(completedOrders?.revenue || 0),
        materials: Number(materials?.total || 0), pending_devices: Number(pendingDevices?.total || 0), active_ads: Number(activeAds?.total || 0),
      } });
    }

    // Safe Visual Page Builder (schema-constrained JSON; never accepts HTML or JavaScript).
    const pageMatch = path.match(/^\/api\/admin\/pages\/([a-z0-9][a-z0-9-]{1,59})$/);
    if (pageMatch && ["GET", "PUT"].includes(method)) {
      if (!(await requireAdminPermission(env, session, "pages"))) return reply(request, env, { success: false, error: "ليست لديك صلاحية محرر الصفحات." }, 403);
      const slug = pageMatch[1];
      if (method === "GET") {
        const row = await env.DB.prepare("SELECT slug, title, draft_json, published_json, status, updated_at FROM platform_pages WHERE slug = ?").bind(slug).first();
        const revisions = await env.DB.prepare("SELECT id, revision_type, created_at FROM platform_page_revisions WHERE slug = ? ORDER BY id DESC LIMIT 30").bind(slug).all();
        return reply(request, env, { success: true, page: row ? { slug: row.slug, title: row.title, draft: parseHomepageJson(row.draft_json), published: parseHomepageJson(row.published_json), status: row.status, updated_at: row.updated_at } : { slug, title: "صفحة جديدة", draft: { version: 1, blocks: [] }, published: { version: 1, blocks: [] }, status: "draft", updated_at: null }, revisions: revisions.results || [] });
      }
      const body = await readBody(request);
      const title = clean(body?.title, 120);
      const validated = validatePageDocument(body?.document);
      if (!title || !validated.ok) return reply(request, env, { success: false, error: validated.error || "عنوان الصفحة مطلوب." }, 400);
      const snapshot = JSON.stringify(validated.value);
      await env.DB.prepare(`
        INSERT INTO platform_pages (slug, title, draft_json, published_json, status, updated_by)
        VALUES (?, ?, ?, '{"version":1,"blocks":[]}', 'draft', ?)
        ON CONFLICT(slug) DO UPDATE SET title = excluded.title, draft_json = excluded.draft_json, status = 'draft', updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP
      `).bind(slug, title, snapshot, session.admin_id).run();
      await env.DB.prepare("INSERT INTO platform_page_revisions (slug, snapshot_json, revision_type, created_by) VALUES (?, ?, 'save', ?)").bind(slug, snapshot, session.admin_id).run();
      await writeAuditLog(request, env, "admin", session.admin_id, "page.save_draft", "page", slug, { block_count: validated.value.blocks.length });
      return reply(request, env, { success: true, message: "تم حفظ مسودة الصفحة." });
    }
    const pagePublish = path.match(/^\/api\/admin\/pages\/([a-z0-9][a-z0-9-]{1,59})\/publish$/);
    if (method === "POST" && pagePublish) {
      if (!(await requireAdminPermission(env, session, "pages"))) return reply(request, env, { success: false, error: "ليست لديك صلاحية نشر الصفحات." }, 403);
      const slug = pagePublish[1];
      const page = await env.DB.prepare("SELECT draft_json FROM platform_pages WHERE slug = ?").bind(slug).first();
      if (!page) return reply(request, env, { success: false, error: "الصفحة غير موجودة." }, 404);
      const validated = validatePageDocument(parseHomepageJson(page.draft_json));
      if (!validated.ok) return reply(request, env, { success: false, error: "المسودة غير صالحة ولا يمكن نشرها." }, 409);
      const snapshot = JSON.stringify(validated.value);
      await env.DB.prepare("UPDATE platform_pages SET published_json = ?, status = 'published', updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE slug = ?")
        .bind(snapshot, session.admin_id, slug).run();
      await env.DB.prepare("INSERT INTO platform_page_revisions (slug, snapshot_json, revision_type, created_by) VALUES (?, ?, 'publish', ?)").bind(slug, snapshot, session.admin_id).run();
      await writeAuditLog(request, env, "admin", session.admin_id, "page.publish", "page", slug, {});
      return reply(request, env, { success: true, message: "تم نشر الصفحة." });
    }
    const pageRestore = path.match(/^\/api\/admin\/pages\/([a-z0-9][a-z0-9-]{1,59})\/restore\/(\d+)$/);
    if (method === "POST" && pageRestore) {
      if (!(await requireAdminPermission(env, session, "pages"))) return reply(request, env, { success: false, error: "ليست لديك صلاحية استعادة الإصدارات." }, 403);
      const [, slug, revisionId] = pageRestore;
      const revision = await env.DB.prepare("SELECT snapshot_json FROM platform_page_revisions WHERE id = ? AND slug = ?").bind(Number(revisionId), slug).first();
      if (!revision) return reply(request, env, { success: false, error: "الإصدار غير موجود." }, 404);
      const validated = validatePageDocument(parseHomepageJson(revision.snapshot_json));
      if (!validated.ok) return reply(request, env, { success: false, error: "الإصدار المخزن غير صالح." }, 409);
      const snapshot = JSON.stringify(validated.value);
      await env.DB.prepare("UPDATE platform_pages SET draft_json = ?, status = 'draft', updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE slug = ?").bind(snapshot, session.admin_id, slug).run();
      await env.DB.prepare("INSERT INTO platform_page_revisions (slug, snapshot_json, revision_type, created_by) VALUES (?, ?, 'restore', ?)").bind(slug, snapshot, session.admin_id).run();
      await writeAuditLog(request, env, "admin", session.admin_id, "page.restore", "page", slug, { revision_id: Number(revisionId) });
      return reply(request, env, { success: true, message: "تمت استعادة الإصدار كمسودة. انشره بعد المعاينة." });
    }

    if (method === "GET" && path === "/api/admin/parent-link-requests") {
      if (!(await requireAdminPermission(env, session, "parent_links"))) return reply(request, env, { success: false, error: "ليست لديك صلاحية مراجعة طلبات الربط." }, 403);
      const rows = await env.DB.prepare(`
        SELECT r.id, r.parent_id, r.student_id, r.created_at, p.name AS parent_name, p.phone AS parent_phone,
               s.name AS student_name, s.phone AS student_phone, s.parent_phone AS registered_parent_phone, s.grade
        FROM parent_link_requests r JOIN parent_accounts p ON p.id = r.parent_id JOIN students s ON s.id = r.student_id
        WHERE r.status = 'pending' ORDER BY r.created_at DESC, r.id DESC LIMIT 300
      `).all();
      return reply(request, env, { success: true, requests: rows.results || [] });
    }
    const parentRequestAction = path.match(/^\/api\/admin\/parent-link-requests\/(\d+)\/(approve|reject)$/);
    if (method === "POST" && parentRequestAction) {
      if (!(await requireAdminPermission(env, session, "parent_links"))) return reply(request, env, { success: false, error: "ليست لديك صلاحية مراجعة طلبات الربط." }, 403);
      const requestId = Number(parentRequestAction[1]);
      const action = parentRequestAction[2];
      const row = await env.DB.prepare(`SELECT r.id, r.parent_id, r.student_id, p.phone AS parent_phone, s.parent_phone AS student_parent_phone
        FROM parent_link_requests r JOIN parent_accounts p ON p.id = r.parent_id JOIN students s ON s.id = r.student_id
        WHERE r.id = ? AND r.status = 'pending'`).bind(requestId).first();
      if (!row) return reply(request, env, { success: false, error: "طلب الربط غير موجود أو تمت مراجعته." }, 404);
      if (action === "approve" && normalizePhone(row.parent_phone) !== normalizePhone(row.student_parent_phone)) {
        await env.DB.prepare("UPDATE parent_link_requests SET status = 'rejected', reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ? WHERE id = ? AND status = 'pending'").bind(session.admin_id, requestId).run();
        return reply(request, env, { success: false, error: "رقم ولي الأمر لا يطابق الرقم المسجل لدى الطالب؛ تم رفض الطلب احترازيًا." }, 409);
      }
      if (action === "approve") {
        await env.DB.batch([
          env.DB.prepare("INSERT OR IGNORE INTO parent_student_links (parent_id, student_id, created_by) VALUES (?, ?, ?)").bind(row.parent_id, row.student_id, session.admin_id),
          env.DB.prepare("UPDATE parent_link_requests SET status = 'approved', reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ? WHERE id = ? AND status = 'pending'").bind(session.admin_id, requestId),
        ]);
      } else {
        await env.DB.prepare("UPDATE parent_link_requests SET status = 'rejected', reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ? WHERE id = ? AND status = 'pending'").bind(session.admin_id, requestId).run();
      }
      await writeAuditLog(request, env, "admin", session.admin_id, `parent_link.${action}`, "parent_link_request", requestId, { student_id: row.student_id, parent_id: row.parent_id });
      return reply(request, env, { success: true, message: action === "approve" ? "تم اعتماد ربط ولي الأمر بالطالب." : "تم رفض طلب الربط." });
    }

    if (method === "GET" && path === "/api/admin/ads") {
      if (!(await requireAdminPermission(env, session, "ads"))) return reply(request, env, { success: false, error: "ليست لديك صلاحية إدارة الإعلانات." }, 403);
      const rows = await env.DB.prepare("SELECT * FROM ads ORDER BY priority DESC, id DESC LIMIT 300").all();
      return reply(request, env, { success: true, ads: rows.results || [] });
    }
    if (method === "POST" && path === "/api/admin/ads") {
      if (!(await requireAdminPermission(env, session, "ads"))) return reply(request, env, { success: false, error: "ليست لديك صلاحية إدارة الإعلانات." }, 403);
      const body = await readBody(request);
      const title = clean(body?.title, 140), bodyText = clean(body?.body, 1000), placement = clean(body?.placement, 30), audience = clean(body?.audience || "all", 20);
      const imageUrl = clean(body?.image_url, 1000), targetUrl = clean(body?.target_url, 1000), buttonText = clean(body?.button_text, 80);
      const allowedPlacements = ["home", "login", "register", "student", "parent", "content"];
      const safeLink = (v) => {
        if (!v) return true;
        if (typeof v !== "string" || v.includes("\\")) return false;
        if (/^https:\/\//i.test(v)) {
          try { const parsed = new URL(v); return parsed.protocol === "https:" && !parsed.username && !parsed.password; }
          catch { return false; }
        }
        if (!/^\/(?!\/)[a-z0-9_./#-]*$/i.test(v)) return false;
        return !v.split("/").some((segment) => segment === "." || segment === "..");
      };
      if (!title || !allowedPlacements.includes(placement) || !["all", "students", "parents"].includes(audience) || !safeLink(imageUrl) || !safeLink(targetUrl)) return reply(request, env, { success: false, error: "بيانات الإعلان غير صحيحة. استخدم مواضع وجمهورًا مسموحًا وروابط HTTPS." }, 400);
      const priority = Math.max(-100, Math.min(1000, Number(body?.priority) || 0));
      const isActive = body?.is_active === false ? 0 : 1;
      const result = await env.DB.prepare(`INSERT INTO ads (title, body, image_url, target_url, button_text, placement, audience, starts_at, ends_at, priority, is_active, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(title, bodyText, imageUrl || null, targetUrl || null, buttonText, placement, audience, body?.starts_at || null, body?.ends_at || null, priority, isActive, session.admin_id).run();
      await writeAuditLog(request, env, "admin", session.admin_id, "ad.create", "ad", result.meta?.last_row_id, { placement, audience });
      return reply(request, env, { success: true, id: result.meta?.last_row_id }, 201);
    }
    const adUpdate = path.match(/^\/api\/admin\/ads\/(\d+)$/);
    if (method === "PATCH" && adUpdate) {
      if (!(await requireAdminPermission(env, session, "ads"))) return reply(request, env, { success: false, error: "ليست لديك صلاحية إدارة الإعلانات." }, 403);
      const body = await readBody(request);
      const fields = [], values = [];
      if (typeof body?.is_active === "boolean") { fields.push("is_active = ?"); values.push(body.is_active ? 1 : 0); }
      if (body?.title !== undefined) { const v = clean(body.title, 140); if (!v) return reply(request, env, { success: false, error: "العنوان مطلوب." }, 400); fields.push("title = ?"); values.push(v); }
      if (body?.starts_at !== undefined) { fields.push("starts_at = ?"); values.push(body.starts_at || null); }
      if (body?.ends_at !== undefined) { fields.push("ends_at = ?"); values.push(body.ends_at || null); }
      if (!fields.length) return reply(request, env, { success: false, error: "لا توجد تغييرات صالحة." }, 400);
      fields.push("updated_at = CURRENT_TIMESTAMP");
      const result = await env.DB.prepare(`UPDATE ads SET ${fields.join(", ")} WHERE id = ?`).bind(...values, Number(adUpdate[1])).run();
      if (!(result.meta?.changes || 0)) return reply(request, env, { success: false, error: "الإعلان غير موجود." }, 404);
      await writeAuditLog(request, env, "admin", session.admin_id, "ad.update", "ad", adUpdate[1], {});
      return reply(request, env, { success: true });
    }

    if (method === "GET" && path === "/api/admin/notifications") {
      if (!(await requireAdminPermission(env, session, "notifications"))) return reply(request, env, { success: false, error: "ليست لديك صلاحية الإشعارات." }, 403);
      const rows = await env.DB.prepare(`SELECT n.*, (SELECT COUNT(*) FROM notification_recipients r WHERE r.notification_id = n.id) AS recipient_count FROM notifications n ORDER BY n.id DESC LIMIT 200`).all();
      return reply(request, env, { success: true, notifications: rows.results || [] });
    }
    if (method === "POST" && path === "/api/admin/notifications") {
      if (!(await requireAdminPermission(env, session, "notifications"))) return reply(request, env, { success: false, error: "ليست لديك صلاحية الإشعارات." }, 403);
      const body = await readBody(request);
      const title = clean(body?.title, 160), bodyText = clean(body?.body, 1800), targetType = clean(body?.target_type, 30), targetValue = clean(body?.target_value, 100);
      const allowedTargets = ["all_students", "grade", "student", "all_parents", "parent"];
      if (!title || !bodyText || !allowedTargets.includes(targetType)) return reply(request, env, { success: false, error: "بيانات الإشعار غير مكتملة." }, 400);
      let recipients = [];
      if (targetType === "all_students") recipients = (await env.DB.prepare("SELECT id FROM students ORDER BY id LIMIT 1500").all()).results || [];
      if (targetType === "grade") recipients = (await env.DB.prepare("SELECT id FROM students WHERE grade = ? ORDER BY id LIMIT 1500").bind(targetValue).all()).results || [];
      if (targetType === "student") recipients = (await env.DB.prepare("SELECT id FROM students WHERE id = ?").bind(Number(targetValue)).all()).results || [];
      if (targetType === "all_parents") recipients = (await env.DB.prepare("SELECT id FROM parent_accounts WHERE is_active = 1 ORDER BY id LIMIT 1500").all()).results || [];
      if (targetType === "parent") recipients = (await env.DB.prepare("SELECT id FROM parent_accounts WHERE id = ? AND is_active = 1").bind(Number(targetValue)).all()).results || [];
      if ((targetType === "student" || targetType === "parent") && !recipients.length) return reply(request, env, { success: false, error: "المستلم غير موجود." }, 404);
      const scheduledAt = body?.scheduled_at ? new Date(body.scheduled_at) : new Date();
      if (Number.isNaN(scheduledAt.getTime())) return reply(request, env, { success: false, error: "موعد الإرسال غير صالح." }, 400);
      const inserted = await env.DB.prepare(`INSERT INTO notifications (title, body, target_type, target_value, is_important, scheduled_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)`)
        .bind(title, bodyText, targetType, targetValue || null, body?.is_important ? 1 : 0, scheduledAt.toISOString().replace("T", " ").replace("Z", ""), session.admin_id).run();
      const id = inserted.meta?.last_row_id;
      const recipientType = targetType.endsWith("parents") || targetType === "parent" ? "parent" : "student";
      if (recipients.length) await env.DB.batch(recipients.map((item) => env.DB.prepare("INSERT OR IGNORE INTO notification_recipients (notification_id, recipient_type, recipient_id) VALUES (?, ?, ?)").bind(id, recipientType, item.id)));
      await writeAuditLog(request, env, "admin", session.admin_id, "notification.create", "notification", id, { target_type: targetType, recipients: recipients.length });
      return reply(request, env, { success: true, id, recipient_count: recipients.length }, 201);
    }

    if (method === "GET" && path === "/api/admin/audit-logs") {
      if (!(await requireAdminPermission(env, session, "analytics"))) return reply(request, env, { success: false, error: "ليست لديك صلاحية عرض سجل التدقيق." }, 403);
      const rows = await env.DB.prepare("SELECT id, actor_type, actor_id, action, entity_type, entity_id, details_json, ip_address, created_at FROM audit_logs ORDER BY id DESC LIMIT 300").all();
      return reply(request, env, { success: true, logs: rows.results || [] });
    }

    if (method === "GET" && path === "/api/admin/roles") {
      if (!(await requireAdminPermission(env, session, "roles"))) return reply(request, env, { success: false, error: "إدارة الأدوار متاحة للمسؤول الأعلى فقط." }, 403);
      const rows = await env.DB.prepare("SELECT a.id, a.username, COALESCE(r.role, 'super_admin') AS role FROM admin_users a LEFT JOIN admin_role_assignments r ON r.admin_id = a.id ORDER BY a.id").all();
      return reply(request, env, { success: true, admins: rows.results || [], available_roles: Object.keys(ADMIN_ROLE_PERMISSIONS) });
    }
    const roleUpdate = path.match(/^\/api\/admin\/roles\/(\d+)$/);
    if (method === "PUT" && roleUpdate) {
      if (!(await requireAdminPermission(env, session, "roles"))) return reply(request, env, { success: false, error: "إدارة الأدوار متاحة للمسؤول الأعلى فقط." }, 403);
      const body = await readBody(request), role = clean(body?.role, 30), adminId = Number(roleUpdate[1]);
      if (!Object.prototype.hasOwnProperty.call(ADMIN_ROLE_PERMISSIONS, role)) return reply(request, env, { success: false, error: "الدور المحدد غير صالح." }, 400);
      if (adminId === session.admin_id && role !== "super_admin") return reply(request, env, { success: false, error: "لا يمكنك خفض صلاحيات حسابك الحالي." }, 409);
      const exists = await env.DB.prepare("SELECT id FROM admin_users WHERE id = ?").bind(adminId).first();
      if (!exists) return reply(request, env, { success: false, error: "المستخدم الإداري غير موجود." }, 404);
      await env.DB.prepare(`INSERT INTO admin_role_assignments (admin_id, role, updated_by) VALUES (?, ?, ?) ON CONFLICT(admin_id) DO UPDATE SET role = excluded.role, updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP`).bind(adminId, role, session.admin_id).run();
      await writeAuditLog(request, env, "admin", session.admin_id, "admin.role.update", "admin", adminId, { role });
      return reply(request, env, { success: true });
    }

    if (method === "GET" && path === "/api/admin/quizzes") {
      const rows = await env.DB.prepare(`SELECT q.*, (SELECT COUNT(*) FROM quiz_questions x WHERE x.quiz_id = q.id) AS question_count, (SELECT COUNT(*) FROM quiz_attempts a WHERE a.quiz_id = q.id) AS attempt_count FROM quizzes q ORDER BY q.id DESC LIMIT 200`).all();
      return reply(request, env, { success: true, quizzes: rows.results || [] });
    }
    if (method === "POST" && path === "/api/admin/quizzes") {
      const body = await readBody(request), validated = sanitizeQuizDefinition(body);
      if (!validated.ok) return reply(request, env, { success: false, error: validated.error }, 400);
      const qz = validated.value;
      if (qz.subject_id) {
        const subject = await env.DB.prepare("SELECT id, grade FROM subjects WHERE id = ?").bind(qz.subject_id).first();
        if (!subject || subject.grade !== qz.grade) return reply(request, env, { success: false, error: "المادة غير موجودة أو لا تنتمي إلى الصف المحدد." }, 400);
      }
      const created = await env.DB.prepare(`INSERT INTO quizzes (title, description, grade, subject_id, duration_minutes, max_attempts, starts_at, ends_at, status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?)`)
        .bind(qz.title, qz.description, qz.grade, qz.subject_id, qz.duration_minutes, qz.max_attempts, qz.starts_at, qz.ends_at, session.admin_id).run();
      const quizId = created.meta?.last_row_id;
      const inserts = qz.questions.map((item) => env.DB.prepare(`INSERT INTO quiz_questions (quiz_id, question_type, prompt, options_json, answer_json, points, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(quizId, item.type, item.prompt, JSON.stringify(item.options), item.answer === null ? null : JSON.stringify(item.answer), item.points, item.sort_order));
      await env.DB.batch(inserts);
      await writeAuditLog(request, env, "admin", session.admin_id, "quiz.create", "quiz", quizId, { questions: qz.questions.length, grade: qz.grade });
      return reply(request, env, { success: true, id: quizId, message: "تم إنشاء الاختبار كمسودة. راجعه قبل النشر." }, 201);
    }
    const quizPublish = path.match(/^\/api\/admin\/quizzes\/(\d+)\/publish$/);
    if (method === "POST" && quizPublish) {
      const id = Number(quizPublish[1]);
      const quiz = await env.DB.prepare("SELECT id FROM quizzes WHERE id = ?").bind(id).first();
      const count = await env.DB.prepare("SELECT COUNT(*) AS total FROM quiz_questions WHERE quiz_id = ?").bind(id).first();
      if (!quiz) return reply(request, env, { success: false, error: "الاختبار غير موجود." }, 404);
      if (Number(count?.total || 0) < 1) return reply(request, env, { success: false, error: "لا يمكن نشر اختبار بلا أسئلة." }, 409);
      await env.DB.prepare("UPDATE quizzes SET status = 'published', updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(id).run();
      await writeAuditLog(request, env, "admin", session.admin_id, "quiz.publish", "quiz", id, {});
      return reply(request, env, { success: true });
    }
    const quizArchive = path.match(/^\/api\/admin\/quizzes\/(\d+)\/archive$/);
    if (method === "POST" && quizArchive) {
      await env.DB.prepare("UPDATE quizzes SET status = 'archived', updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(Number(quizArchive[1])).run();
      await writeAuditLog(request, env, "admin", session.admin_id, "quiz.archive", "quiz", quizArchive[1], {});
      return reply(request, env, { success: true });
    }
    if (method === "GET" && path === "/api/admin/quiz-attempts") {
      const status = clean(new URL(request.url).searchParams.get("status"), 20);
      const rows = await env.DB.prepare(`SELECT a.id, a.quiz_id, a.student_id, a.status, a.score, a.max_score, a.started_at, a.submitted_at, q.title AS quiz_title, s.name AS student_name FROM quiz_attempts a JOIN quizzes q ON q.id = a.quiz_id JOIN students s ON s.id = a.student_id WHERE (? = '' OR a.status = ?) ORDER BY a.id DESC LIMIT 300`).bind(status, status).all();
      return reply(request, env, { success: true, attempts: rows.results || [] });
    }
    const essayReview = path.match(/^\/api\/admin\/quiz-attempts\/(\d+)\/review$/);
    if (method === "GET" && essayReview) {
      const attempt = await env.DB.prepare("SELECT id, quiz_id, answers_json, status FROM quiz_attempts WHERE id = ?").bind(Number(essayReview[1])).first();
      if (!attempt) return reply(request, env, { success: false, error: "المحاولة غير موجودة." }, 404);
      const questions = (await env.DB.prepare("SELECT id, prompt, points FROM quiz_questions WHERE quiz_id = ? AND question_type = 'essay' ORDER BY sort_order, id").bind(attempt.quiz_id).all()).results || [];
      const answers = parseHomepageJson(attempt.answers_json) || {};
      return reply(request, env, { success: true, essays: questions.map((q) => ({ id: q.id, prompt: q.prompt, points: q.points, response: answers[String(q.id)]?.response || "" })) });
    }
    const essayGrade = path.match(/^\/api\/admin\/quiz-attempts\/(\d+)\/grade$/);
    if (method === "POST" && essayGrade) {
      const attemptId = Number(essayGrade[1]), body = await readBody(request);
      const attempt = await env.DB.prepare("SELECT id, quiz_id, answers_json, status FROM quiz_attempts WHERE id = ?").bind(attemptId).first();
      if (!attempt) return reply(request, env, { success: false, error: "المحاولة غير موجودة." }, 404);
      if (attempt.status !== "submitted") return reply(request, env, { success: false, error: "المحاولة ليست بانتظار التصحيح." }, 409);
      const questions = (await env.DB.prepare("SELECT id, question_type, points FROM quiz_questions WHERE quiz_id = ? ORDER BY sort_order, id").bind(attempt.quiz_id).all()).results || [];
      const answers = parseHomepageJson(attempt.answers_json) || {};
      const essayScores = body?.essay_scores && typeof body.essay_scores === "object" && !Array.isArray(body.essay_scores) ? body.essay_scores : {};
      let total = 0; const normalized = {};
      for (const q of questions) {
        if (q.question_type === "essay") {
          const score = Number(essayScores[q.id]);
          if (!Number.isFinite(score) || score < 0 || score > Number(q.points)) return reply(request, env, { success: false, error: `درجة السؤال المقالي ${q.id} غير صالحة.` }, 400);
          normalized[q.id] = score; total += score;
        } else {
          const key = String(q.id), answer = answers[key];
          const savedScore = answer && typeof answer === "object" ? Number(answer.awarded || 0) : 0;
          total += Number.isFinite(savedScore) ? savedScore : 0;
        }
      }
      const feedback = clean(body?.teacher_feedback, 2000);
      await env.DB.prepare("UPDATE quiz_attempts SET essay_scores_json = ?, teacher_feedback = ?, score = ?, status = 'graded', graded_by = ?, graded_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(JSON.stringify(normalized), feedback, total, session.admin_id, attemptId).run();
      await writeAuditLog(request, env, "admin", session.admin_id, "quiz_attempt.grade", "quiz_attempt", attemptId, { score: total });
      return reply(request, env, { success: true, score: total });
    }

    if (method === "GET" && path === "/api/admin/ai/content") {
      const rows = await env.DB.prepare("SELECT id, content_type, title, prompt, content, status, created_by, reviewed_by, created_at, reviewed_at FROM ai_content_drafts ORDER BY id DESC LIMIT 100").all();
      return reply(request, env, { success: true, drafts: rows.results || [] });
    }
    if (method === "POST" && path === "/api/admin/ai/content") {
      const allowed = await consumeApiRateLimit(env, request, "admin-ai-content", session.admin_id, 15, 3600);
      if (!allowed) return reply(request, env, { success: false, error: "تم الوصول إلى حد إنشاء المحتوى الذكي لهذا الوقت." }, 429);
      const body = await readBody(request), prompt = clean(body?.prompt, 3000), type = clean(body?.content_type, 30), title = clean(body?.title, 180);
      const supported = new Set(["summary", "lesson", "mcq", "essay", "flashcards", "study_plan"]);
      if (!supported.has(type) || prompt.length < 10 || !title) return reply(request, env, { success: false, error: "أدخل عنوانًا ونوع محتوى صحيحًا ووصفًا لا يقل عن 10 أحرف." }, 400);
      const instructions = {
        summary: "أنشئ ملخصًا تعليميًا منظمًا بالعناوين والنقاط.",
        lesson: "أنشئ شرح درس عربيًا تدريجيًا مع أهداف ومفاهيم وأمثلة.",
        mcq: "أنشئ أسئلة اختيار من متعدد مع 4 اختيارات ومفتاح إجابة منفصل في نهاية المسودة.",
        essay: "أنشئ أسئلة مقالية متنوعة مع عناصر نموذج إجابة في نهاية المسودة.",
        flashcards: "أنشئ بطاقات مراجعة بصيغة سؤال ثم إجابة.",
        study_plan: "أنشئ خطة مذاكرة قابلة للتنفيذ ومقسمة إلى أيام وجلسات.",
      };
      try {
        const generated = await requestAI(env, [
          { role: "system", content: `أنت محرر محتوى تعليمي في ZM Academy. اكتب باللغة العربية الفصحى المبسطة، لا تخترع حقائق علمية متخصصة عند نقص المصدر، واذكر الافتراضات. نوع المحتوى: ${instructions[type]} هذه مسودة للمراجعة فقط وليست منشورة للطلاب.` },
          { role: "user", content: prompt },
        ], { maxTokens: 2400, temperature: 0.5 });
        const result = await env.DB.prepare("INSERT INTO ai_content_drafts (content_type, title, prompt, content, status, created_by) VALUES (?, ?, ?, ?, 'pending_review', ?)").bind(type, title, prompt, generated, session.admin_id).run();
        await env.DB.prepare("INSERT INTO ai_usage (actor_type, actor_id, feature, input_chars, output_chars) VALUES ('admin', ?, 'content_studio', ?, ?)").bind(session.admin_id, prompt.length, generated.length).run();
        await writeAuditLog(request, env, "admin", session.admin_id, "ai.content.generate", "ai_content_draft", result.meta?.last_row_id, { content_type: type });
        return reply(request, env, { success: true, id: result.meta?.last_row_id, status: "pending_review", content: generated, message: "تم إنشاء مسودة للمراجعة ولم يتم نشرها." }, 201);
      } catch (error) {
        const missing = error?.message === "AI_NOT_CONFIGURED" || error?.message === "AI_MODEL_NOT_CONFIGURED";
        return reply(request, env, { success: false, error: missing ? "استوديو المحتوى غير مفعّل. أضف AI_API_KEY وAI_MODEL إلى Worker Secrets." : "تعذر إنشاء المسودة من مزود الذكاء الاصطناعي." }, missing ? 503 : 502);
      }
    }
    const aiDraftReview = path.match(/^\/api\/admin\/ai\/content\/(\d+)\/review$/);
    if (method === "POST" && aiDraftReview) {
      const body = await readBody(request), action = clean(body?.action, 20), draftId = Number(aiDraftReview[1]);
      if (!["approve", "reject"].includes(action)) return reply(request, env, { success: false, error: "إجراء المراجعة غير صالح." }, 400);
      const updated = await env.DB.prepare("UPDATE ai_content_drafts SET status = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending_review'").bind(action === "approve" ? "approved" : "rejected", session.admin_id, draftId).run();
      if (!(updated.meta?.changes || 0)) return reply(request, env, { success: false, error: "المسودة غير موجودة أو تمت مراجعتها بالفعل." }, 404);
      await writeAuditLog(request, env, "admin", session.admin_id, `ai.content.${action}`, "ai_content_draft", draftId, {});
      return reply(request, env, { success: true, status: action === "approve" ? "approved" : "rejected", message: action === "approve" ? "تم اعتماد المسودة داخليًا. لم تُنشر تلقائيًا." : "تم رفض المسودة." });
    }

    if (method === "POST" && path === "/api/admin/ai/command") {
      if (!(await requireAdminPermission(env, session, "ai"))) return reply(request, env, { success: false, error: "ليست لديك صلاحية مساعد الإدارة." }, 403);
      const allowed = await consumeApiRateLimit(env, request, "admin-ai", session.admin_id, 20, 3600);
      if (!allowed) return reply(request, env, { success: false, error: "تم الوصول إلى حد استخدام المساعد لهذا الوقت." }, 429);
      const body = await readBody(request), prompt = clean(body?.prompt, 2400), mode = clean(body?.mode || "assistant", 30);
      if (prompt.length < 3) return reply(request, env, { success: false, error: "اكتب أمرًا أو سؤالًا واضحًا." }, 400);
      try {
        const system = mode === "builder"
          ? "أنت مساعد تصميم لمنصة تعليمية. اقترح عناصر واجهة منظمة فقط. لا تنفذ أي تعديل ولا تدّع النشر. أخرج JSON صالحًا فقط بالشكل {\"title\":string,\"blocks\":[{\"type\":\"heading|text|button|card|image|alert|section|spacer|video\",\"content\":{\"title\":string,\"text\":string,\"buttonText\":string,\"href\":string,\"src\":string}}]}. لا تقترح HTML أو JavaScript أو CSS حرًا."
          : "أنت مساعد إداري لأكاديمية ZM. قدم اقتراحات وتقارير بناءً على المعلومات التي يقدمها المسؤول في رسالته فقط. لا تدّع الوصول إلى قاعدة البيانات أو تنفيذ تغييرات أو نشرها. اطلب تأكيدًا ومراجعة عند العمليات المؤثرة.";
        const answer = await requestAI(env, [{ role: "system", content: system }, { role: "user", content: prompt }], { maxTokens: 1100 });
        await env.DB.prepare("INSERT INTO ai_usage (actor_type, actor_id, feature, input_chars, output_chars) VALUES ('admin', ?, ?, ?, ?)").bind(session.admin_id, mode, prompt.length, answer.length).run();
        await writeAuditLog(request, env, "admin", session.admin_id, "ai.admin_request", "ai", "", { mode, prompt_chars: prompt.length });
        return reply(request, env, { success: true, answer, requires_review: true, executable: false });
      } catch (error) {
        const message = error?.message === "AI_NOT_CONFIGURED" || error?.message === "AI_MODEL_NOT_CONFIGURED" ? "تكامل الذكاء الاصطناعي غير مكتمل. أضف AI_API_KEY وAI_MODEL إلى أسرار Worker." : "تعذر الاتصال بخدمة الذكاء الاصطناعي. تحقق من إعدادات المزود وحاول مرة أخرى.";
        return reply(request, env, { success: false, error: message }, error?.message === "AI_NOT_CONFIGURED" || error?.message === "AI_MODEL_NOT_CONFIGURED" ? 503 : 502);
      }
    }

    
    // إدارة إعدادات الصفحة الرئيسية
    if (
      path === "/api/admin/homepage" &&
      method === "GET"
    ) {
      await ensureHomepageSettingsTable(env);

      const row = await env.DB.prepare(`
        SELECT draft_json, published_json, status, updated_at
        FROM homepage_settings
        WHERE id = 1
      `).first();

      return reply(request, env, {
        success: true,
        draft: parseHomepageJson(row?.draft_json),
        published: parseHomepageJson(row?.published_json),
        status: row?.status || "published",
        updated_at: row?.updated_at || null
      });
    }

    // حفظ مسودة الصفحة الرئيسية
    if (
      path === "/api/admin/homepage" &&
      method === "PUT"
    ) {
      await ensureHomepageSettingsTable(env);

      const body = await readBody(request);
      const settings = body?.settings;

      if (
        !settings ||
        typeof settings !== "object" ||
        Array.isArray(settings)
      ) {
        return reply(request, env, {
          success: false,
          error: "إعدادات الصفحة غير صحيحة."
        }, 400);
      }

      const json = JSON.stringify(settings);

      if (json.length > 50000) {
        return reply(request, env, {
          success: false,
          error: "حجم إعدادات الصفحة كبير جدًا."
        }, 413);
      }

      await env.DB.prepare(`
        UPDATE homepage_settings
        SET draft_json = ?,
            status = 'draft',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
      `).bind(json).run();

      return reply(request, env, {
        success: true,
        message: "تم حفظ المسودة."
      });
    }

    // نشر المسودة للزوار
    if (
      path === "/api/admin/homepage/publish" &&
      method === "POST"
    ) {
      await ensureHomepageSettingsTable(env);

      await env.DB.prepare(`
        UPDATE homepage_settings
        SET published_json = draft_json,
            status = 'published',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
      `).run();

      return reply(request, env, {
        success: true,
        message: "تم نشر الصفحة الرئيسية."
      });
    }

    // عرض طلبات استعادة كلمات المرور
if (method === "GET" && path === "/api/admin/password-reset-requests") {
  await ensurePasswordResetRequestsTable(env);

  const result = await env.DB.prepare(`
    SELECT
      r.id,
      r.username,
      r.phone,
      r.created_at,
      s.name AS student_name,
      s.grade
    FROM password_reset_requests r
    LEFT JOIN students s ON s.id = r.student_id
    WHERE r.status = 'pending'
    ORDER BY r.id DESC
  `).all();

  return reply(request, env, {
    success: true,
    requests: result.results || [],
  });
}

// تعيين كلمة مرور جديدة للطالب
const resetPasswordMatch = path.match(
  /^\/api\/admin\/password-reset-requests\/(\d+)\/reset$/
);

if (method === "POST" && resetPasswordMatch) {
  await ensurePasswordResetRequestsTable(env);

  const requestId = Number(resetPasswordMatch[1]);
  const body = await readBody(request);
  const newPassword = String(body?.password || "");

  if (newPassword.length < 8 || newPassword.length > 100) {
    return reply(request, env, {
      success: false,
      error: "كلمة المرور يجب أن تكون من 8 إلى 100 حرف.",
    }, 400);
  }

  const resetRequest = await env.DB.prepare(`
    SELECT id, student_id
    FROM password_reset_requests
    WHERE id = ? AND status = 'pending'
    LIMIT 1
  `).bind(requestId).first();

  if (!resetRequest) {
    return reply(request, env, {
      success: false,
      error: "الطلب غير موجود أو تمت مراجعته بالفعل.",
    }, 404);
  }

  const newHash = await passwordHash(newPassword);

  await env.DB.prepare(`
    UPDATE student_accounts
    SET password_hash = ?
    WHERE student_id = ?
  `).bind(newHash, resetRequest.student_id).run();

  // إنهاء جلسات الطالب القديمة
  await env.DB.prepare(`
    DELETE FROM student_sessions
    WHERE student_id = ?
  `).bind(resetRequest.student_id).run();

  // تسجيل مراجعة الطلب
  await env.DB.prepare(`
    UPDATE password_reset_requests
    SET status = 'completed',
        reviewed_at = CURRENT_TIMESTAMP,
        reviewed_by = ?
    WHERE id = ? AND status = 'pending'
  `).bind(session.admin_id, requestId).run();

  return reply(request, env, {
    success: true,
    message: "تم تغيير كلمة مرور الطالب وإنهاء جلساته القديمة.",
  });
}

// رفض طلب استعادة كلمة المرور
const rejectPasswordMatch = path.match(
  /^\/api\/admin\/password-reset-requests\/(\d+)\/reject$/
);

if (method === "POST" && rejectPasswordMatch) {
  await ensurePasswordResetRequestsTable(env);

  const requestId = Number(rejectPasswordMatch[1]);

  const result = await env.DB.prepare(`
    UPDATE password_reset_requests
    SET status = 'rejected',
        reviewed_at = CURRENT_TIMESTAMP,
        reviewed_by = ?
    WHERE id = ? AND status = 'pending'
  `).bind(session.admin_id, requestId).run();

  if (!result.meta || result.meta.changes === 0) {
    return reply(request, env, {
      success: false,
      error: "الطلب غير موجود أو تمت مراجعته بالفعل.",
    }, 404);
  }

  return reply(request, env, {
    success: true,
    message: "تم رفض طلب استعادة كلمة المرور.",
  });
}

        // عرض طلبات اعتماد الأجهزة المعلقة
    if (method === "GET" && path === "/api/admin/device-requests") {
      const rows = await env.DB.prepare(`
        SELECT d.id, d.student_id, d.device_name, d.created_at,
               s.name AS student_name, s.phone,
               a.username
        FROM student_devices d
        JOIN students s ON s.id = d.student_id
        LEFT JOIN student_accounts a ON a.student_id = d.student_id
        WHERE d.status = 'pending'
        ORDER BY d.created_at DESC, d.id DESC
        LIMIT 500
      `).all();

      return reply(request, env, {
        success: true,
        requests: rows.results || [],
      });
    }

    const deviceDecision = path.match(
      /^\/api\/admin\/device-requests\/(\d+)\/(approve|reject)$/
    );

    if (method === "POST" && deviceDecision) {
      const deviceId = Number(deviceDecision[1]);
      const decision = deviceDecision[2];

      const device = await env.DB.prepare(
        `SELECT id, student_id
         FROM student_devices
         WHERE id = ? AND status = 'pending'`
      )
        .bind(deviceId)
        .first();

      if (!device) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "طلب الجهاز غير موجود أو تمت مراجعته.",
          },
          404
        );
      }

      if (decision === "approve") {
        // اعتماد الجهاز المطلوب فقط: لا نرفض الأجهزة السابقة ولا ننهي جلساتها.
        const approved = await env.DB.prepare(
          `UPDATE student_devices
           SET status = 'approved',
               reviewed_at = CURRENT_TIMESTAMP,
               reviewed_by = ?
           WHERE id = ? AND student_id = ? AND status = 'pending'`
        ).bind(session.admin_id, deviceId, device.student_id).run();

        if (!(approved.meta?.changes || 0)) {
          return reply(request, env, { success: false, error: "تعذر اعتماد الجهاز؛ ربما تمت مراجعة الطلب بالفعل." }, 409);
        }
        await writeAuditLog(request, env, "admin", session.admin_id, "device.approve", "student_device", deviceId, { student_id: device.student_id });
        return reply(request, env, {
          success: true,
          message: "تم اعتماد الجهاز مع الإبقاء على الأجهزة والجلسات السابقة.",
        });
      }

      await env.DB.prepare(
        `UPDATE student_devices
         SET status = 'rejected',
             reviewed_at = CURRENT_TIMESTAMP,
             reviewed_by = ?
         WHERE id = ? AND status = 'pending'`
      )
        .bind(session.admin_id, deviceId)
        .run();

      return reply(request, env, {
        success: true,
        message: "Device rejected.",
      });
    }

    if (method === "GET" && path === "/api/admin/me") {
      return reply(request, env, {
        success: true,
        admin: {
          id: session.admin_id,
          username: session.username,
        },
      });
    }

    // الطلبات
    if (method === "GET" && path === "/api/admin/orders") {
      const rows = await env.DB.prepare(`
        SELECT o.id, o.status, o.created_at,
               s.name AS student_name, s.phone,
               m.title AS material_title, m.price
        FROM orders o
        JOIN students s ON s.id = o.student_id
        JOIN materials m ON m.id = o.material_id
        WHERE o.status = 'pending'
        ORDER BY o.id DESC
        LIMIT 500
      `).all();

      return reply(request, env, {
        success: true,
        orders: rows.results || [],
      });
    }

    // تحديث حالة الطلب
    const orderStatus = path.match(/^\/api\/admin\/orders\/(\d+)$/);

    if (method === "PATCH" && orderStatus) {
      const body = await readBody(request);
      const status = clean(body?.status, 30);

      if (!["pending", "approved", "rejected", "completed"].includes(status)) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "Invalid order status.",
          },
          400
        );
      }

      const result = await env.DB.prepare(
        "UPDATE orders SET status = ? WHERE id = ?"
      )
        .bind(status, Number(orderStatus[1]))
        .run();

      if (!(result.meta?.changes || 0)) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "Order not found.",
          },
          404
        );
      }

      return reply(request, env, {
        success: true,
        changed: result.meta?.changes || 0,
      });
    }

    // قائمة الطلاب بالتفاصيل الصحيحة
    if (method === "GET" && path === "/api/admin/students") {
      const rows = await env.DB.prepare(`
        SELECT id, name, phone, parent_phone,
               grade, school, governorate, created_at
        FROM students
        ORDER BY id DESC
        LIMIT 500
      `).all();

      return reply(request, env, {
        success: true,
        students: rows.results || [],
      });
    }

    // حذف طالب مع الحفاظ على سجل الطلبات
    if (method === "DELETE" && /^\/api\/admin\/students\/\d+$/.test(path)) {
      const studentId = Number(path.split("/").pop());

      const student = await env.DB.prepare(
        "SELECT id FROM students WHERE id = ?"
      )
        .bind(studentId)
        .first();

      if (!student) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "الطالب غير موجود.",
          },
          404
        );
      }

      const linkedOrders = await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM orders WHERE student_id = ?"
      )
        .bind(studentId)
        .first();

      if ((linkedOrders?.n || 0) > 0) {
        return reply(
          request,
          env,
          {
            success: false,
            error:
              "لا يمكن حذف الطالب لوجود طلبات مرتبطة به. احتفظ بسجل الطلبات.",
          },
          409
        );
      }

      await ensurePasswordResetRequestsTable(env);
      await ensureStudentPhotosTable(env);
      await ensureStudentLearningTables(env);

      const oldPhoto = await env.DB.prepare(
        "SELECT file_key FROM student_photos WHERE student_id = ?"
      ).bind(studentId).first();

      await env.DB.batch([
        env.DB.prepare("DELETE FROM student_sessions WHERE student_id = ?").bind(studentId),
        env.DB.prepare("DELETE FROM student_devices WHERE student_id = ?").bind(studentId),
        env.DB.prepare("DELETE FROM student_subjects WHERE student_id = ?").bind(studentId),
        env.DB.prepare("DELETE FROM student_accounts WHERE student_id = ?").bind(studentId),
        env.DB.prepare("DELETE FROM password_reset_requests WHERE student_id = ?").bind(studentId),
        env.DB.prepare("DELETE FROM student_photos WHERE student_id = ?").bind(studentId),
        env.DB.prepare("DELETE FROM student_material_progress WHERE student_id = ?").bind(studentId),
        env.DB.prepare("DELETE FROM student_favorites WHERE student_id = ?").bind(studentId),
        env.DB.prepare("DELETE FROM student_activity_days WHERE student_id = ?").bind(studentId),
        env.DB.prepare("DELETE FROM student_hidden_purchases WHERE student_id = ?").bind(studentId),
        env.DB.prepare("DELETE FROM students WHERE id = ?").bind(studentId),
      ]);

      if (oldPhoto?.file_key) {
        try {
          await deleteStudentPhotoFromGitHub(env, oldPhoto.file_key, studentId);
        } catch (error) {
          console.error("Student photo cleanup failed:", error?.message || error);
        }
      }

      return reply(request, env, {
        success: true,
        deleted: studentId,
      });
    }

    // عرض المواد للإدارة بما فيها المؤرشفة
    if (method === "GET" && path === "/api/admin/subjects") {
      await ensureArchivedSubjectsTable(env);

      const rows = await env.DB.prepare(`
        SELECT s.id, s.name, s.grade,
               CASE WHEN a.subject_id IS NULL THEN 0 ELSE 1 END AS is_archived
        FROM subjects s
        LEFT JOIN archived_subjects a ON a.subject_id = s.id
        ORDER BY is_archived ASC, s.grade, s.name
      `).all();

      return reply(request, env, {
        success: true,
        subjects: rows.results || [],
      });
    }

    // أرشفة مادة أو استعادتها
    const subjectArchiveMatch = path.match(
      /^\/api\/admin\/subjects\/(\d+)\/(archive|restore)$/
    );

    if (method === "POST" && subjectArchiveMatch) {
      await ensureArchivedSubjectsTable(env);

      const subjectId = Number(subjectArchiveMatch[1]);
      const action = subjectArchiveMatch[2];

      const subject = await env.DB.prepare(
        "SELECT id FROM subjects WHERE id = ?"
      ).bind(subjectId).first();

      if (!subject) {
        return reply(request, env, {
          success: false,
          error: "المادة غير موجودة.",
        }, 404);
      }

      if (action === "archive") {
        await env.DB.prepare(`
          INSERT OR IGNORE INTO archived_subjects (subject_id)
          VALUES (?)
        `).bind(subjectId).run();
      } else {
        await env.DB.prepare(
          "DELETE FROM archived_subjects WHERE subject_id = ?"
        ).bind(subjectId).run();
      }

      return reply(request, env, {
        success: true,
        message: action === "archive"
          ? "تمت أرشفة المادة بنجاح."
          : "تمت استعادة المادة بنجاح.",
      });
    }

    // إضافة مادة دراسية
    if (

    method === "POST" &&
      (path === "/api/admin/subjects" || path === "/api/subjects")
    ) {
      const body = await readBody(request);
      const name = clean(body?.name, 120);
      const grade = clean(body?.grade, 80);

      if (!name || !grade) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "Subject name and grade are required.",
          },
          400
        );
      }

      const result = await env.DB.prepare(
        "INSERT INTO subjects (name, grade) VALUES (?, ?)"
      )
        .bind(name, grade)
        .run();

      return reply(
        request,
        env,
        {
          success: true,
          id: result.meta.last_row_id,
        },
        201
      );
    }

    // تعديل مادة دراسية
    if (method === "PUT" && path === "/api/subjects") {
      const body = await readBody(request);
      const id = Number(body?.id);
      const name = clean(body?.name, 120);
      const grade = clean(body?.grade, 80);

      if (!Number.isInteger(id) || id < 1 || !name || !grade) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "بيانات المادة غير صحيحة.",
          },
          400
        );
      }

      const result = await env.DB.prepare(
        "UPDATE subjects SET name = ?, grade = ? WHERE id = ?"
      )
        .bind(name, grade, id)
        .run();

      if (!(result.meta?.changes || 0)) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "المادة غير موجودة.",
          },
          404
        );
      }

      return reply(request, env, {
        success: true,
        message: "تم تعديل المادة بنجاح.",
      });
    }

    // حذف مادة دراسية دون حذف سجلات الطلاب أو المحتوى المرتبط بها
    if (method === "DELETE" && path === "/api/subjects") {
      const body = await readBody(request);
      const id = Number(body?.id);

      if (!Number.isInteger(id) || id < 1) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "رقم المادة غير صحيح.",
          },
          400
        );
      }

      const subject = await env.DB.prepare(
        "SELECT id FROM subjects WHERE id = ?"
      )
        .bind(id)
        .first();

      if (!subject) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "المادة غير موجودة.",
          },
          404
        );
      }

      const [studentLinks, materials] = await Promise.all([
        env.DB.prepare(
          "SELECT COUNT(*) AS n FROM student_subjects WHERE subject_id = ?"
        )
          .bind(id)
          .first(),
        env.DB.prepare(
          "SELECT COUNT(*) AS n FROM materials WHERE subject_id = ?"
        )
          .bind(id)
          .first(),
      ]);

      if ((studentLinks?.n || 0) > 0 || (materials?.n || 0) > 0) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "لا يمكن حذف المادة لارتباطها بطلاب أو محتوى دراسي.",
          },
          409
        );
      }

      await env.DB.prepare("DELETE FROM subjects WHERE id = ?").bind(id).run();

      return reply(request, env, {
        success: true,
        message: "تم حذف المادة بنجاح.",
      });
    }

    // عرض جميع المحتويات للإدارة بما فيها المؤرشفة
    if (method === "GET" && path === "/api/admin/materials") {
      await ensureArchivedMaterialsTable(env);

      const rows = await env.DB.prepare(`
        SELECT m.id, m.subject_id, m.title, m.type, m.price, m.is_free,
               m.file_key, sub.name AS subject_name, sub.grade,
               CASE
                 WHEN a.material_id IS NULL THEN 0
                 ELSE 1
               END AS is_archived
        FROM materials m
        LEFT JOIN subjects sub ON sub.id = m.subject_id
        LEFT JOIN archived_materials a ON a.material_id = m.id
        ORDER BY is_archived ASC, m.id DESC
      `).all();

      return reply(request, env, {
        success: true,
        materials: rows.results || [],
      });
    }

    // أرشفة درس أو استعادته
    const materialArchiveMatch = path.match(
      /^\/api\/admin\/materials\/(\d+)\/(archive|restore)$/
    );

    if (method === "POST" && materialArchiveMatch) {
      await ensureArchivedMaterialsTable(env);

      const materialId = Number(materialArchiveMatch[1]);
      const action = materialArchiveMatch[2];

      const material = await env.DB.prepare(
        "SELECT id FROM materials WHERE id = ?"
      ).bind(materialId).first();

      if (!material) {
        return reply(request, env, {
          success: false,
          error: "الدرس غير موجود.",
        }, 404);
      }

      if (action === "archive") {
        await env.DB.prepare(`
          INSERT OR IGNORE INTO archived_materials (material_id)
          VALUES (?)
        `).bind(materialId).run();
      } else {
        await env.DB.prepare(
          "DELETE FROM archived_materials WHERE material_id = ?"
        ).bind(materialId).run();
      }

      return reply(request, env, {
        success: true,
        message: action === "archive"
          ? "تمت أرشفة الدرس بنجاح."
          : "تمت استعادة الدرس بنجاح.",
      });
    }

    // حذف محتوى دراسي
    if (method === "DELETE" && path === "/api/admin/materials") {
      const body = await readBody(request);
      const id = Number(body?.id);

      if (!Number.isInteger(id) || id < 1) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "Invalid material ID.",
          },
          400
        );
      }

      const existing = await env.DB.prepare(
        "SELECT file_key FROM materials WHERE id = ?"
      )
        .bind(id)
        .first();

      if (!existing) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "Material not found.",
          },
          404
        );
      }

      const linkedOrders = await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM orders WHERE material_id = ?"
      )
        .bind(id)
        .first();

      if ((linkedOrders?.n || 0) > 0) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "لا يمكن حذف المحتوى لوجود طلبات مرتبطة به.",
          },
          409
        );
      }

      await ensureStudentLearningTables(env);
      await ensureArchivedMaterialsTable(env);

      const deletion = await env.DB.batch([
        env.DB.prepare("DELETE FROM student_material_progress WHERE material_id = ?").bind(id),
        env.DB.prepare("DELETE FROM student_favorites WHERE material_id = ?").bind(id),
        env.DB.prepare("DELETE FROM archived_materials WHERE material_id = ?").bind(id),
        env.DB.prepare("DELETE FROM materials WHERE id = ?").bind(id),
      ]);
      const result = deletion[deletion.length - 1];

      if (!(result?.meta?.changes || 0)) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "Material not found.",
          },
          404
        );
      }

      if (existing.file_key) {
        try {
          await deleteFromGitHub(env, existing.file_key);
        } catch (error) {
          console.error("GITHUB_DELETE_ERROR:", error?.message || error);
        }
      }

      return reply(request, env, {
        success: true,
        message: "Material deleted.",
      });
    }
        // Managed Media Library: metadata in D1, bytes in the existing private GitHub repository.
    if (method === "GET" && path === "/api/admin/media") {
      const rows = await env.DB.prepare("SELECT id, file_name, content_type, size_bytes, folder, alt_text, is_public, uploaded_by, created_at FROM media_assets ORDER BY folder, id DESC LIMIT 500").all();
      return reply(request, env, { success: true, media: rows.results || [] });
    }
    if (method === "POST" && path === "/api/admin/media/upload") {
      let form;
      try { form = await request.formData(); }
      catch { return reply(request, env, { success: false, error: "تعذر قراءة بيانات الملف." }, 400); }
      const file = form.get("file");
      if (!file || typeof file.arrayBuffer !== "function") return reply(request, env, { success: false, error: "اختر ملفًا أولًا." }, 400);
      if (file.size < 1 || file.size > MAX_FILE_SIZE) return reply(request, env, { success: false, error: "حجم الملف يجب ألا يتجاوز 8 ميجابايت." }, 400);
      const contentType = clean(file.type, 80);
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (!isValidMediaBytes(bytes, contentType)) return reply(request, env, { success: false, error: "نوع الملف أو محتواه غير صالح. الصيغ المدعومة PDF وJPG وPNG وWEBP." }, 400);
      const safeName = clean(file.name, 180).replace(/[^\p{L}\p{N}._ -]/gu, "_").slice(0, 150) || "media-file";
      const folder = clean(form.get("folder"), 80).replace(/[\\/]/g, "-") || "general";
      const altText = clean(form.get("alt_text"), 240);
      const isPublic = contentType.startsWith("image/") && form.get("is_public") === "true" ? 1 : 0;
      let uploadedFileKey = "";
      try {
        uploadedFileKey = await uploadToGitHub(env, bytes, safeName, contentType);
        const inserted = await env.DB.prepare("INSERT INTO media_assets (file_key, file_name, content_type, size_bytes, folder, alt_text, is_public, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
          .bind(uploadedFileKey, safeName, contentType, bytes.length, folder, altText, isPublic, session.admin_id).run();
        await writeAuditLog(request, env, "admin", session.admin_id, "media.upload", "media_asset", inserted.meta?.last_row_id, { content_type: contentType, size_bytes: bytes.length, folder, is_public: Boolean(isPublic) });
        return reply(request, env, { success: true, id: inserted.meta?.last_row_id, file_name: safeName, content_type: contentType, size_bytes: bytes.length, is_public: Boolean(isPublic), url: isPublic ? `${new URL(request.url).origin}/api/media/${inserted.meta?.last_row_id}` : null }, 201);
      } catch (error) {
        if (uploadedFileKey) { try { await deleteFromGitHub(env, uploadedFileKey); } catch {} }
        console.error("MEDIA_UPLOAD_FAILED:", error?.message || error);
        return reply(request, env, { success: false, error: "تعذر رفع الوسيط إلى التخزين. تحقق من إعداد GitHub Storage." }, 502);
      }
    }
    const mediaMatch = path.match(/^\/api\/admin\/media\/(\d+)$/);
    if (method === "PATCH" && mediaMatch) {
      const body = await readBody(request), id = Number(mediaMatch[1]);
      const current = await env.DB.prepare("SELECT id, content_type FROM media_assets WHERE id = ?").bind(id).first();
      if (!current) return reply(request, env, { success: false, error: "الوسيط غير موجود." }, 404);
      const fields = [], values = [];
      if (body?.alt_text !== undefined) { fields.push("alt_text = ?"); values.push(clean(body.alt_text, 240)); }
      if (body?.folder !== undefined) { fields.push("folder = ?"); values.push(clean(body.folder, 80).replace(/[\\/]/g, "-") || "general"); }
      if (body?.is_public !== undefined) {
        if (typeof body.is_public !== "boolean") return reply(request, env, { success: false, error: "قيمة النشر غير صالحة." }, 400);
        if (body.is_public && !current.content_type.startsWith("image/")) return reply(request, env, { success: false, error: "لا يمكن نشر ملفات PDF كصور عامة." }, 400);
        if (!body.is_public) {
          const pageRefs = await env.DB.prepare("SELECT COUNT(*) AS n FROM platform_pages WHERE instr(draft_json, ?) > 0 OR instr(published_json, ?) > 0").bind(`/api/media/${id}`, `/api/media/${id}`).first();
          if (Number(pageRefs?.n || 0) > 0) return reply(request, env, { success: false, error: "الصورة مستخدمة داخل صفحة. أزلها من المسودة والنسخة المنشورة أولًا." }, 409);
        }
        fields.push("is_public = ?"); values.push(body.is_public ? 1 : 0);
      }
      if (!fields.length) return reply(request, env, { success: false, error: "لا توجد تغييرات." }, 400);
      const changed = await env.DB.prepare(`UPDATE media_assets SET ${fields.join(", ")} WHERE id = ?`).bind(...values, id).run();
      await writeAuditLog(request, env, "admin", session.admin_id, "media.update", "media_asset", id, {});
      return reply(request, env, { success: Boolean(changed.meta?.changes), url: current.content_type.startsWith("image/") ? `/api/media/${id}` : null });
    }
    if (method === "DELETE" && mediaMatch) {
      const id = Number(mediaMatch[1]);
      const asset = await env.DB.prepare("SELECT id, file_key FROM media_assets WHERE id = ?").bind(id).first();
      if (!asset) return reply(request, env, { success: false, error: "الوسيط غير موجود." }, 404);
      const reference = await env.DB.prepare(`SELECT
        (SELECT COUNT(*) FROM materials WHERE file_key = ?) AS material_refs,
        (SELECT COUNT(*) FROM platform_pages WHERE instr(draft_json, ?) > 0 OR instr(published_json, ?) > 0) AS page_refs`).bind(asset.file_key, `/api/media/${id}`, `/api/media/${id}`).first();
      if (Number(reference?.material_refs || 0) > 0 || Number(reference?.page_refs || 0) > 0) return reply(request, env, { success: false, error: "لا يمكن حذف الملف لأنه مرتبط بمحتوى أو صفحة. افصل الارتباط أولًا." }, 409);
      if (!env.GITHUB_STORAGE_TOKEN) return reply(request, env, { success: false, error: "خدمة التخزين غير مهيأة." }, 503);
      const fileUrl = githubContentsUrl(asset.file_key);
      const currentFile = await fetch(fileUrl, { headers: githubHeaders(env) });
      if (currentFile.ok) {
        const metadata = await currentFile.json();
        if (!metadata?.sha) return reply(request, env, { success: false, error: "تعذر التحقق من الملف في التخزين." }, 502);
        const removed = await fetch(fileUrl, { method: "DELETE", headers: { ...githubHeaders(env), "Content-Type": "application/json" }, body: JSON.stringify({ message: `Delete media asset ${id}`, sha: metadata.sha }) });
        if (!removed.ok) return reply(request, env, { success: false, error: "تعذر حذف الملف من مستودع التخزين." }, 502);
      } else if (currentFile.status !== 404) return reply(request, env, { success: false, error: "تعذر التحقق من الملف في التخزين." }, 502);
      await env.DB.prepare("DELETE FROM media_assets WHERE id = ?").bind(id).run();
      await writeAuditLog(request, env, "admin", session.admin_id, "media.delete", "media_asset", id, {});
      return reply(request, env, { success: true });
    }

    // رفع ملف PDF إلى التخزين الخاص
    if (method === "POST" && path === "/api/admin/upload") {
      try {
        const form = await request.formData();
        const file = form.get("file");

        if (!file || typeof file.arrayBuffer !== "function") {
          return reply(
            request,
            env,
            {
              success: false,
              error: "Please select a file.",
            },
            400
          );
        }

        if (file.size < 1 || file.size > MAX_FILE_SIZE) {
          return reply(
            request,
            env,
            {
              success: false,
              error: "Maximum file size is 8 MB.",
            },
            400
          );
        }

        const contentType = file.type;
        const bytes = new Uint8Array(await file.arrayBuffer());

        const isPDF =
          contentType === "application/pdf" &&
          bytes.length >= 5 &&
          new TextDecoder().decode(bytes.slice(0, 5)) === "%PDF-";

        if (!isPDF) {
          return reply(
            request,
            env,
            {
              success: false,
              error: "يجب اختيار ملف PDF صحيح.",
            },
            400
          );
        }

        const fileKey = await uploadToGitHub(env, bytes, file.name, contentType);

        return reply(
          request,
          env,
          {
            success: true,
            file_key: fileKey,
            message: "File uploaded successfully.",
          },
          201
        );
      } catch (error) {
        console.error("File upload error:", error);

        return reply(
          request,
          env,
          {
            success: false,
            error:
              "تعذر رفع الملف إلى التخزين. تحقق من إعدادات التخزين وحاول مرة أخرى.",
          },
          500
        );
      }
    }

    // تعديل محتوى دراسي
    if (method === "PUT" && path === "/api/admin/materials") {
      const body = await readBody(request);
      const id = Number(body?.id);
      const subjectId = Number(body?.subject_id);
      const title = clean(body?.title, 180);
      const type = clean(body?.type, 40);
      const price = Number(body?.price ?? 0);
      const isFree =
        body?.is_free === false || Number(body?.is_free) === 0 ? 0 : 1;

      if (
        !Number.isInteger(id) ||
        id < 1 ||
        !Number.isInteger(subjectId) ||
        subjectId < 1 ||
        !title ||
        !type ||
        !Number.isFinite(price) ||
        price < 0 ||
        price > MAX_PRICE
      ) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "Invalid material data.",
          },
          400
        );
      }

      const [existing, subject] = await Promise.all([
        env.DB.prepare("SELECT file_key, subject_id FROM materials WHERE id = ?")
          .bind(id)
          .first(),
        env.DB.prepare("SELECT id FROM subjects WHERE id = ?")
          .bind(subjectId)
          .first(),
      ]);

      if (!existing) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "Material not found.",
          },
          404
        );
      }

      if (!subject) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "Subject not found.",
          },
          404
        );
      }

      if (Number(existing.subject_id) !== subjectId) {
        const linkedOrders = await env.DB.prepare(
          "SELECT COUNT(*) AS n FROM orders WHERE material_id = ?"
        ).bind(id).first();

        if (Number(linkedOrders?.n || 0) > 0) {
          return reply(request, env, {
            success: false,
            error: "لا يمكن نقل محتوى مرتبط بطلبات شراء إلى مادة أخرى.",
          }, 409);
        }
      }

      const newFileKey = clean(body?.file_key, 500);
      const fileKey = newFileKey || existing.file_key || null;

      await env.DB.prepare(
        `UPDATE materials
         SET subject_id = ?, title = ?, type = ?, price = ?,
             is_free = ?, file_key = ?
         WHERE id = ?`
      )
        .bind(subjectId, title, type, price, isFree, fileKey, id)
        .run();

      return reply(request, env, {
        success: true,
        message: "Material updated.",
      });
    }

    // إضافة محتوى دراسي
    if (method === "POST" && path === "/api/admin/materials") {
      const body = await readBody(request);
      const subjectId = Number(body?.subject_id);
      const title = clean(body?.title, 180);
      const type = clean(body?.type, 40);
      const price = Number(body?.price ?? 0);
      const isFree =
        body?.is_free === false || Number(body?.is_free) === 0 ? 0 : 1;

      if (
        !Number.isInteger(subjectId) ||
        subjectId < 1 ||
        !title ||
        !type ||
        !Number.isFinite(price) ||
        price < 0 ||
        price > MAX_PRICE
      ) {
        return reply(
          request,
          env,
          {
            success: false,
            error:
              "Valid subject_id, title, type and non-negative price are required.",
          },
          400
        );
      }

      const subject = await env.DB.prepare(
        "SELECT id FROM subjects WHERE id = ?"
      )
        .bind(subjectId)
        .first();

      if (!subject) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "Subject not found.",
          },
          404
        );
      }

      const result = await env.DB.prepare(
        `INSERT INTO materials
         (subject_id, title, type, price, is_free, file_key)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
        .bind(
          subjectId,
          title,
          type,
          price,
          isFree,
          clean(body?.file_key, 500) || null
        )
        .run();

      return reply(
        request,
        env,
        {
          success: true,
          id: result.meta.last_row_id,
        },
        201
      );
    }

    return reply(
      request,
      env,
      {
        success: false,
        error: "Admin endpoint not found.",
      },
      404
    );
  }

  // المواد والصفوف المتاحة للتسجيل
  if (method === "GET" && path === "/api/subjects") {
    await ensureArchivedSubjectsTable(env);

    const rows = await env.DB.prepare(`
      SELECT id, name, grade
      FROM subjects
      WHERE id NOT IN (
        SELECT subject_id FROM archived_subjects
      )
      ORDER BY grade, name
    `).all();

    return reply(request, env, {
      success: true,
      subjects: rows.results || [],
    });
  }

  // المحتوى الدراسي المتاح للطالب المسجل
  if (method === "GET" && path === "/api/materials") {
    const session = await studentSession(request, env);

    if (!session) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "يجب تسجيل الدخول لعرض المحتوى الدراسي.",
        },
        401
      );
    }

    await ensureArchivedSubjectsTable(env);
    await ensureArchivedMaterialsTable(env);

    const subjectId = Number(url.searchParams.get("subject_id") || 0);

    const rows = subjectId
      ? await env.DB.prepare(
          `SELECT m.id, m.subject_id, m.title, m.type, m.price, m.is_free
           FROM materials m
           JOIN student_subjects ss ON ss.subject_id = m.subject_id
           WHERE ss.student_id = ?
             AND m.subject_id = ?
             AND m.subject_id NOT IN (
               SELECT subject_id FROM archived_subjects
             )
             AND m.id NOT IN (
               SELECT material_id FROM archived_materials
             )
           ORDER BY m.id DESC`
        )
          .bind(session.student_id, subjectId)
          .all()
      : await env.DB.prepare(
          `SELECT m.id, m.subject_id, m.title, m.type, m.price, m.is_free
           FROM materials m
           JOIN student_subjects ss ON ss.subject_id = m.subject_id
           WHERE ss.student_id = ?
             AND m.subject_id NOT IN (
               SELECT subject_id FROM archived_subjects
             )
             AND m.id NOT IN (
               SELECT material_id FROM archived_materials
             )
           ORDER BY m.id DESC`
        )
          .bind(session.student_id)
          .all();

    return reply(request, env, {
      success: true,
      materials: rows.results || [],
    });
  }

  // تسجيل طالب جديد وإنشاء حسابه
  if (method === "POST" && path === "/api/students/register") {
    const body = await readBody(request);

    const name = clean(body?.name, 120);
    const phone = clean(body?.phone, 30).replace(/\s+/g, "");
    const parentPhone = clean(body?.parent_phone, 30).replace(/\s+/g, "");
    const grade = clean(body?.grade, 80);
    const school = clean(body?.school, 160);
    const governorate = clean(body?.governorate, 80);
    const username = clean(body?.username, 40).toLowerCase();

    const password = typeof body?.password === "string" ? body.password : "";

    const subjectIds = Array.isArray(body?.subjects)
      ? [
          ...new Set(
            body.subjects
              .map(Number)
              .filter((x) => Number.isInteger(x) && x > 0)
          ),
        ]
      : [];

    if (
      name.length < 2 ||
      !/^[+0-9()-]{8,20}$/.test(phone) ||
      !/^[+0-9()-]{8,20}$/.test(parentPhone) ||
      !grade ||
      !school ||
      !governorate ||
      !/^[a-z0-9_.-]{3,40}$/.test(username) ||
      password.length < 8 ||
      password.length > 200 ||
      subjectIds.length < 1
    ) {
      return reply(
        request,
        env,
        {
          success: false,
          error:
            "تأكد من إدخال جميع البيانات بشكل صحيح، واختر مادة واحدة على الأقل. اسم المستخدم من 3 إلى 40 حرفًا إنجليزيًا أو رقمًا، وكلمة المرور 8 أحرف على الأقل.",
        },
        400
      );
    }

    const existingPhone = await env.DB.prepare(
      "SELECT id FROM students WHERE phone = ?"
    )
      .bind(phone)
      .first();

    if (existingPhone) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "رقم الطالب مسجل بالفعل. تواصل مع الإدارة للمساعدة.",
        },
        409
      );
    }

    const existingUsername = await env.DB.prepare(
      "SELECT id FROM student_accounts WHERE username = ?"
    )
      .bind(username)
      .first();

    if (existingUsername) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "اسم المستخدم مستخدم بالفعل، اختر اسمًا آخر.",
        },
        409
      );
    }

    const placeholders = subjectIds.map(() => "?").join(",");

    await ensureArchivedSubjectsTable(env);

    const validSubjects = await env.DB.prepare(
      `SELECT id FROM subjects
       WHERE grade = ?
         AND id IN (${placeholders})
         AND id NOT IN (
           SELECT subject_id FROM archived_subjects
         )`
    )
      .bind(grade, ...subjectIds)
      .all();

    if ((validSubjects.results || []).length !== subjectIds.length) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "يوجد اختيار مادة غير تابع للصف الدراسي المحدد.",
        },
        400
      );
    }

    let studentId = null;

    try {
      const studentResult = await env.DB.prepare(
        `INSERT INTO students
         (name, phone, parent_phone, grade, school, governorate)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
        .bind(name, phone, parentPhone, grade, school, governorate)
        .run();

      studentId = studentResult.meta.last_row_id;

      const hash = await passwordHash(password);

      const statements = [
        env.DB.prepare(
          `INSERT INTO student_accounts
           (student_id, username, password_hash)
           VALUES (?, ?, ?)`
        ).bind(studentId, username, hash),

        ...subjectIds.map((subjectId) =>
          env.DB.prepare(
            `INSERT INTO student_subjects
             (student_id, subject_id)
             VALUES (?, ?)`
          ).bind(studentId, subjectId)
        ),
      ];

      await env.DB.batch(statements);

      return reply(
        request,
        env,
        {
          success: true,
          student_id: studentId,
          username,
          message: "تم إنشاء حسابك بنجاح.",
        },
        201
      );
    } catch (error) {
      console.error("STUDENT_REGISTER_ERROR:", error?.message || error);

      if (studentId) {
        try {
          await env.DB.batch([
            env.DB.prepare(
              "DELETE FROM student_subjects WHERE student_id = ?"
            ).bind(studentId),
            env.DB.prepare(
              "DELETE FROM student_accounts WHERE student_id = ?"
            ).bind(studentId),
            env.DB.prepare("DELETE FROM students WHERE id = ?").bind(
              studentId
            ),
          ]);
        } catch (cleanupError) {
          console.error(
            "STUDENT_CLEANUP_ERROR:",
            cleanupError?.message || cleanupError
          );
        }
      }

      return reply(
        request,
        env,
        {
          success: false,
          error:
            "تعذر إتمام التسجيل بسبب خطأ داخلي. حاول مرة أخرى أو تواصل مع الإدارة.",
        },
        500
      );
    }
  }

  // تسجيل دخول الطالب
  if (method === "POST" && path === "/api/students/login") {
    await purgeExpiredSessions(env);

    const body = await readBody(request);

    const username = clean(body?.username, 40).toLowerCase();
    const password = typeof body?.password === "string" ? body.password : "";
    const deviceToken =
      typeof body?.deviceToken === "string" ? body.deviceToken.trim() : "";
    const deviceName = clean(body?.deviceName, 100) || "جهاز غير معروف";

    if (!username || !password) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "أدخل اسم المستخدم وكلمة المرور.",
        },
        400
      );
    }

    if (deviceToken.length < 32 || deviceToken.length > 200) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "تعذر التعرف على الجهاز. حدّث الصفحة وحاول مرة أخرى.",
        },
        400
      );
    }

    const studentIpAllowed = await consumeApiRateLimit(env, request, "student-login-ip", "*", 100, 900);
    const studentUserAllowed = await consumeApiRateLimit(env, request, "student-login-user", username, 8, 900);
    if (!studentIpAllowed || !studentUserAllowed) {
      return reply(request, env, {
        success: false,
        error: "محاولات تسجيل الدخول كثيرة. انتظر 15 دقيقة ثم حاول مرة أخرى.",
      }, 429);
    }

    const account = await env.DB.prepare(
      `SELECT id, student_id, password_hash
       FROM student_accounts
       WHERE username = ?`
    )
      .bind(username)
      .first();

    if (!account || !(await verifyPassword(password, account.password_hash))) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "اسم المستخدم أو كلمة المرور غير صحيحة.",
        },
        401
      );
    }

    const deviceTokenHash = await sha256(deviceToken);

    const existingDevice = await env.DB.prepare(
      `SELECT id, status
       FROM student_devices
       WHERE student_id = ?
         AND device_token_hash = ?`
    )
      .bind(account.student_id, deviceTokenHash)
      .first();

    if (existingDevice?.status !== "approved") {
      if (existingDevice?.status === "rejected") {
        await env.DB.prepare(
          `UPDATE student_devices
           SET status = 'pending',
               device_name = ?,
               created_at = CURRENT_TIMESTAMP,
               reviewed_at = NULL,
               reviewed_by = NULL
           WHERE id = ?`
        )
          .bind(deviceName, existingDevice.id)
          .run();
      } else if (!existingDevice) {
        await env.DB.prepare(
          `INSERT INTO student_devices
           (student_id, device_token_hash, device_name, status)
           SELECT ?, ?, ?, 'pending'
           WHERE NOT EXISTS (
             SELECT 1 FROM student_devices
             WHERE student_id = ? AND device_token_hash = ?
           )`
        )
          .bind(
            account.student_id,
            deviceTokenHash,
            deviceName,
            account.student_id,
            deviceTokenHash
          )
          .run();
      }

      return reply(
        request,
        env,
        {
          success: false,
          code: "DEVICE_APPROVAL_REQUIRED",
          error: "هذا الجهاز يحتاج إلى موافقة المدرس قبل تسجيل الدخول.",
        },
        403
      );
    }

    const token = randomToken();
    const tokenHash = await sha256(token);

    await env.DB.prepare(
      `INSERT INTO student_sessions
       (student_id, token_hash, device_token_hash, expires_at)
       VALUES (?, ?, ?, datetime('now', ?))`
    )
      .bind(
        account.student_id,
        tokenHash,
        deviceTokenHash,
        `+${SESSION_DAYS} days`
      )
      .run();

    return reply(request, env, {
      success: true,
      token,
      expiresInDays: SESSION_DAYS,
    });
          }
    // مسارات الطالب المحمية بتسجيل الدخول
  if (path.startsWith("/api/student/")) {
    const session = await studentSession(request, env);

    if (!session) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "يلزم تسجيل الدخول.",
        },
        401
      );
    }

    // Personal student preferences: stored per student and strictly allow-listed.
    if (path === "/api/student/ads" && method === "GET") {
      const rows = await env.DB.prepare(`SELECT id, title, body, image_url, target_url, button_text, placement FROM ads WHERE is_active = 1 AND audience IN ('all','students') AND placement = 'student' AND (starts_at IS NULL OR datetime(starts_at) <= datetime('now')) AND (ends_at IS NULL OR datetime(ends_at) >= datetime('now')) ORDER BY priority DESC, id DESC LIMIT 20`).all();
      if (rows.results?.length) await env.DB.batch(rows.results.map((ad) => env.DB.prepare("UPDATE ads SET impressions = impressions + 1 WHERE id = ?").bind(ad.id)));
      return reply(request, env, { success: true, ads: rows.results || [] });
    }
    if (path === "/api/student/preferences" && method === "GET") {
      const row = await env.DB.prepare("SELECT settings_json, updated_at FROM student_preferences WHERE student_id = ?").bind(session.student_id).first();
      return reply(request, env, { success: true, preferences: parseHomepageJson(row?.settings_json), updated_at: row?.updated_at || null });
    }
    if (path === "/api/student/preferences" && method === "PUT") {
      const body = await readBody(request);
      const preferences = sanitizeStudentPreferences(body?.preferences);
      if (!preferences) return reply(request, env, { success: false, error: "إعدادات التخصيص غير صالحة." }, 400);
      await env.DB.prepare(`INSERT INTO student_preferences (student_id, settings_json) VALUES (?, ?) ON CONFLICT(student_id) DO UPDATE SET settings_json = excluded.settings_json, updated_at = CURRENT_TIMESTAMP`)
        .bind(session.student_id, JSON.stringify(preferences)).run();
      return reply(request, env, { success: true, preferences });
    }
    if (path === "/api/student/notifications" && method === "GET") {
      const rows = await env.DB.prepare(`
        SELECT n.id, n.title, n.body, n.is_important, n.scheduled_at, r.read_at
        FROM notification_recipients r JOIN notifications n ON n.id = r.notification_id
        WHERE r.recipient_type = 'student' AND r.recipient_id = ? AND n.scheduled_at <= datetime('now')
        ORDER BY n.is_important DESC, n.id DESC LIMIT 100
      `).bind(session.student_id).all();
      return reply(request, env, { success: true, notifications: rows.results || [] });
    }
    const studentReadMatch = path.match(/^\/api\/student\/notifications\/(\d+)\/read$/);
    if (method === "POST" && studentReadMatch) {
      const result = await env.DB.prepare(`UPDATE notification_recipients SET read_at = CURRENT_TIMESTAMP WHERE notification_id = ? AND recipient_type = 'student' AND recipient_id = ?`)
        .bind(Number(studentReadMatch[1]), session.student_id).run();
      if (!(result.meta?.changes || 0)) return reply(request, env, { success: false, error: "الإشعار غير موجود." }, 404);
      return reply(request, env, { success: true });
    }
    if (path === "/api/student/quizzes" && method === "GET") {
      const rows = await env.DB.prepare(`SELECT q.id, q.title, q.description, q.grade, q.subject_id, q.duration_minutes, q.max_attempts, q.starts_at, q.ends_at, sub.name AS subject_name, (SELECT COUNT(*) FROM quiz_questions x WHERE x.quiz_id = q.id) AS question_count, (SELECT COUNT(*) FROM quiz_attempts a WHERE a.quiz_id = q.id AND a.student_id = ?) AS attempts_used, (SELECT a.status FROM quiz_attempts a WHERE a.quiz_id = q.id AND a.student_id = ? ORDER BY a.id DESC LIMIT 1) AS last_status FROM quizzes q LEFT JOIN subjects sub ON sub.id = q.subject_id WHERE q.status = 'published' AND q.grade = ? AND (q.subject_id IS NULL OR EXISTS (SELECT 1 FROM student_subjects ss WHERE ss.student_id = ? AND ss.subject_id = q.subject_id)) AND (q.starts_at IS NULL OR datetime(q.starts_at) <= datetime('now')) AND (q.ends_at IS NULL OR datetime(q.ends_at) >= datetime('now')) ORDER BY q.id DESC LIMIT 100`).bind(session.student_id, session.student_id, session.grade || "", session.student_id).all();
      return reply(request, env, { success: true, quizzes: rows.results || [] });
    }
    const quizStart = path.match(/^\/api\/student\/quizzes\/(\d+)\/attempt$/);
    if (method === "POST" && quizStart) {
      const quizId = Number(quizStart[1]);
      const quiz = await env.DB.prepare("SELECT * FROM quizzes WHERE id = ? AND status = 'published'").bind(quizId).first();
      if (!quiz || quiz.grade !== session.grade) return reply(request, env, { success: false, error: "الاختبار غير متاح لحسابك." }, 404);
      if (quiz.subject_id) {
        const membership = await env.DB.prepare("SELECT 1 AS ok FROM student_subjects WHERE student_id = ? AND subject_id = ?").bind(session.student_id, quiz.subject_id).first();
        if (!membership) return reply(request, env, { success: false, error: "لا تملك صلاحية الوصول إلى اختبار هذه المادة." }, 403);
      }
      const now = Date.now();
      if ((quiz.starts_at && new Date(quiz.starts_at).getTime() > now) || (quiz.ends_at && new Date(quiz.ends_at).getTime() < now)) return reply(request, env, { success: false, error: "الاختبار خارج موعد الإتاحة." }, 409);
      const previous = await env.DB.prepare("SELECT COUNT(*) AS total FROM quiz_attempts WHERE quiz_id = ? AND student_id = ?").bind(quizId, session.student_id).first();
      if (Number(previous?.total || 0) >= Number(quiz.max_attempts)) return reply(request, env, { success: false, error: "استهلكت عدد المحاولات المسموح به." }, 409);
      const questions = (await env.DB.prepare("SELECT id, question_type, prompt, options_json, points FROM quiz_questions WHERE quiz_id = ? ORDER BY sort_order, id").bind(quizId).all()).results || [];
      if (!questions.length) return reply(request, env, { success: false, error: "لا توجد أسئلة متاحة في هذا الاختبار." }, 409);
      const maxScore = questions.reduce((sum, q) => sum + Number(q.points || 0), 0);
      const created = await env.DB.prepare("INSERT INTO quiz_attempts (quiz_id, student_id, max_score, status) VALUES (?, ?, ?, 'in_progress')").bind(quizId, session.student_id, maxScore).run();
      const safeQuestions = questions.map((q) => ({ id: q.id, type: q.question_type, prompt: q.prompt, options: parseJsonValue(q.options_json, []) || [], points: Number(q.points) }));
      return reply(request, env, { success: true, attempt_id: created.meta?.last_row_id, quiz: { title: quiz.title, duration_minutes: quiz.duration_minutes }, questions: safeQuestions }, 201);
    }
    const quizSubmit = path.match(/^\/api\/student\/quiz-attempts\/(\d+)\/submit$/);
    if (method === "POST" && quizSubmit) {
      const attemptId = Number(quizSubmit[1]), body = await readBody(request);
      const attempt = await env.DB.prepare("SELECT a.*, q.duration_minutes FROM quiz_attempts a JOIN quizzes q ON q.id = a.quiz_id WHERE a.id = ? AND a.student_id = ?").bind(attemptId, session.student_id).first();
      if (!attempt) return reply(request, env, { success: false, error: "المحاولة غير موجودة." }, 404);
      if (attempt.status !== "in_progress") return reply(request, env, { success: false, error: "تم تسليم هذه المحاولة بالفعل." }, 409);
      const elapsed = Date.now() - new Date(`${attempt.started_at.replace(" ", "T")}Z`).getTime();
      if (Number.isFinite(elapsed) && elapsed > (Number(attempt.duration_minutes) + 3) * 60000) return reply(request, env, { success: false, error: "انتهى الوقت المسموح للاختبار." }, 409);
      const submitted = body?.answers && typeof body.answers === "object" && !Array.isArray(body.answers) ? body.answers : {};
      const questions = (await env.DB.prepare("SELECT id, question_type, answer_json, options_json, points FROM quiz_questions WHERE quiz_id = ? ORDER BY sort_order, id").bind(attempt.quiz_id).all()).results || [];
      const answers = {}; let score = 0; let hasEssay = false;
      for (const q of questions) {
        const key = String(q.id), raw = submitted[key];
        if (q.question_type === "essay") {
          hasEssay = true;
          answers[key] = { response: typeof raw === "string" ? raw.trim().slice(0, 5000) : "", awarded: 0 };
          continue;
        }
        let normalized = null;
        if (q.question_type === "mcq") { const n = Number(raw); if (Number.isInteger(n) && n >= 0 && n < (parseJsonValue(q.options_json, []) || []).length) normalized = n; }
        if (q.question_type === "true_false" && typeof raw === "boolean") normalized = raw;
        const correct = parseJsonValue(q.answer_json, null);
        const awarded = normalized !== null && normalized === correct ? Number(q.points) : 0;
        answers[key] = { response: normalized, awarded }; score += awarded;
      }
      await env.DB.prepare("UPDATE quiz_attempts SET answers_json = ?, score = ?, status = ?, submitted_at = CURRENT_TIMESTAMP, graded_at = CASE WHEN ? = 0 THEN CURRENT_TIMESTAMP ELSE NULL END WHERE id = ? AND student_id = ?")
        .bind(JSON.stringify(answers), hasEssay ? null : score, hasEssay ? "submitted" : "graded", hasEssay ? 1 : 0, attemptId, session.student_id).run();
      return reply(request, env, { success: true, status: hasEssay ? "submitted" : "graded", score: hasEssay ? null : score, max_score: Number(attempt.max_score), message: hasEssay ? "تم تسليم الاختبار، والإجابات المقالية بانتظار مراجعة المدرس." : "تم التصحيح التلقائي وحفظ نتيجتك." });
    }
    const attemptView = path.match(/^\/api\/student\/quiz-attempts\/(\d+)$/);
    if (method === "GET" && attemptView) {
      const attempt = await env.DB.prepare("SELECT id, quiz_id, answers_json, score, max_score, status, submitted_at, teacher_feedback FROM quiz_attempts WHERE id = ? AND student_id = ?").bind(Number(attemptView[1]), session.student_id).first();
      if (!attempt) return reply(request, env, { success: false, error: "المحاولة غير موجودة." }, 404);
      if (attempt.status !== "graded") return reply(request, env, { success: true, attempt: { id: attempt.id, status: attempt.status, submitted_at: attempt.submitted_at } });
      const answers = parseHomepageJson(attempt.answers_json) || {};
      const essayScores = parseHomepageJson((await env.DB.prepare("SELECT essay_scores_json FROM quiz_attempts WHERE id = ?").bind(attempt.id).first())?.essay_scores_json) || {};
      return reply(request, env, { success: true, attempt: { id: attempt.id, status: attempt.status, score: attempt.score, max_score: attempt.max_score, answers, essay_scores: essayScores, teacher_feedback: attempt.teacher_feedback, submitted_at: attempt.submitted_at } });
    }

    if (path === "/api/student/ai/chat" && method === "POST") {
      const allowed = await consumeApiRateLimit(env, request, "student-ai", session.student_id, 25, 3600);
      if (!allowed) return reply(request, env, { success: false, error: "وصلت إلى حد الاستخدام المسموح للمساعد اليوم. حاول لاحقًا." }, 429);
      const body = await readBody(request);
      const rawMessages = Array.isArray(body?.messages) ? body.messages.slice(-8) : [];
      const messages = [];
      for (const item of rawMessages) {
        if (!item || !["user", "assistant"].includes(item.role) || typeof item.content !== "string") continue;
        const content = item.content.trim().slice(0, 2200);
        if (content) messages.push({ role: item.role, content });
      }
      if (!messages.length || messages[messages.length - 1].role !== "user") return reply(request, env, { success: false, error: "أرسل سؤالك أولًا." }, 400);
      const materials = await env.DB.prepare(`
        SELECT m.title, m.type, sub.name AS subject_name
        FROM materials m JOIN subjects sub ON sub.id = m.subject_id
        JOIN student_subjects ss ON ss.subject_id = m.subject_id
        WHERE ss.student_id = ? AND m.subject_id NOT IN (SELECT subject_id FROM archived_subjects)
          AND m.id NOT IN (SELECT material_id FROM archived_materials)
        ORDER BY m.id DESC LIMIT 80
      `).bind(session.student_id).all();
      const courseContext = (materials.results || []).map((m) => `${m.subject_name}: ${m.title} (${m.type})`).join("\n").slice(0, 5000);
      const system = `أنت مساعد تعليمي لطالب في ZM Academy. أجب بالعربية المبسطة، واشرح خطوة بخطوة عند الحاجة. لا تكشف بيانات أي طالب آخر ولا معلومات إدارية أو أسرارًا. لا تدّع أنك قرأت ملفًا أو درسًا لم يتم توفير محتواه. قائمة المحتوى المتاح للطالب (عناوين فقط وليست نصوص الدروس):\n${courseContext || "لم تتوفر قائمة محتوى."}\nإذا لم تتوفر معلومة من المنهج، وضح ذلك وقدّم شرحًا عامًا مع تمييزه عن محتوى الأكاديمية.`;
      try {
        const answer = await requestAI(env, [{ role: "system", content: system }, ...messages], { maxTokens: 900 });
        await env.DB.prepare("INSERT INTO ai_usage (actor_type, actor_id, feature, input_chars, output_chars) VALUES ('student', ?, 'student_assistant', ?, ?)")
          .bind(session.student_id, messages.reduce((sum, m) => sum + m.content.length, 0), answer.length).run();
        return reply(request, env, { success: true, answer });
      } catch (error) {
        const missing = error?.message === "AI_NOT_CONFIGURED" || error?.message === "AI_MODEL_NOT_CONFIGURED";
        return reply(request, env, { success: false, error: missing ? "المساعد الذكي غير مفعّل بعد. يحتاج إعداد AI_API_KEY وAI_MODEL في Cloudflare Worker." : "تعذر الاتصال بالمساعد الذكي حاليًا. حاول مرة أخرى لاحقًا." }, missing ? 503 : 502);
      }
    }

    // متابعة تقدم الطالب والمفضلة وأيام النشاط
    if (
      path === "/api/student/progress" ||
      path === "/api/student/favorites" ||
      /^\/api\/student\/favorites\/\d+$/.test(path)
    ) {
      await ensureStudentLearningTables(env);
      await ensureArchivedSubjectsTable(env);
      await ensureArchivedMaterialsTable(env);

      if (method === "GET" && path === "/api/student/progress") {
        const rows = await env.DB.prepare(`
          SELECT p.material_id, p.last_page, p.updated_at,
                 m.title, m.type, sub.name AS subject_name
          FROM student_material_progress p
          JOIN materials m ON m.id = p.material_id
          JOIN subjects sub ON sub.id = m.subject_id
          JOIN student_subjects ss
            ON ss.student_id = p.student_id
           AND ss.subject_id = m.subject_id
          WHERE p.student_id = ?
            AND m.subject_id NOT IN (
              SELECT subject_id FROM archived_subjects
            )
            AND m.id NOT IN (
              SELECT material_id FROM archived_materials
            )
          ORDER BY p.updated_at DESC
          LIMIT 100
        `).bind(session.student_id).all();

        return reply(request, env, {
          success: true,
          progress: rows.results || [],
        });
      }

      if (method === "GET" && path === "/api/student/favorites") {
        const rows = await env.DB.prepare(`
          SELECT f.material_id, f.created_at,
                 m.title, m.type, m.price, m.is_free,
                 sub.name AS subject_name
          FROM student_favorites f
          JOIN materials m ON m.id = f.material_id
          JOIN subjects sub ON sub.id = m.subject_id
          JOIN student_subjects ss
            ON ss.student_id = f.student_id
           AND ss.subject_id = m.subject_id
          WHERE f.student_id = ?
            AND m.subject_id NOT IN (
              SELECT subject_id FROM archived_subjects
            )
            AND m.id NOT IN (
              SELECT material_id FROM archived_materials
            )
          ORDER BY f.created_at DESC
          LIMIT 200
        `).bind(session.student_id).all();

        return reply(request, env, {
          success: true,
          favorites: rows.results || [],
        });
      }

      const favoriteMatch = path.match(
        /^\/api\/student\/favorites\/(\d+)$/
      );

      if (favoriteMatch && ["POST", "DELETE"].includes(method)) {
        const materialId = Number(favoriteMatch[1]);

        const material = await env.DB.prepare(`
          SELECT m.id
          FROM materials m
          JOIN student_subjects ss ON ss.subject_id = m.subject_id
          WHERE m.id = ?
            AND ss.student_id = ?
            AND m.subject_id NOT IN (
              SELECT subject_id FROM archived_subjects
            )
            AND m.id NOT IN (
              SELECT material_id FROM archived_materials
            )
          LIMIT 1
        `).bind(materialId, session.student_id).first();

        if (!material) {
          return reply(request, env, {
            success: false,
            error: "المحتوى غير متاح لحسابك.",
          }, 404);
        }

        if (method === "POST") {
          await env.DB.prepare(`
            INSERT OR IGNORE INTO student_favorites
              (student_id, material_id)
            VALUES (?, ?)
          `).bind(session.student_id, materialId).run();

          return reply(request, env, {
            success: true,
            message: "تمت إضافة المحتوى إلى المفضلة.",
          }, 201);
        }

        await env.DB.prepare(`
          DELETE FROM student_favorites
          WHERE student_id = ? AND material_id = ?
        `).bind(session.student_id, materialId).run();

        return reply(request, env, {
          success: true,
          message: "تمت إزالة المحتوى من المفضلة.",
        });
      }

      if (method === "POST" && path === "/api/student/progress") {
        const body = await readBody(request);
        const materialId = Number(body?.material_id);
        const lastPage = Number(body?.last_page);

        if (
          !Number.isInteger(materialId) || materialId < 1 ||
          !Number.isInteger(lastPage) || lastPage < 1 || lastPage > 10000
        ) {
          return reply(request, env, {
            success: false,
            error: "بيانات تقدم المذاكرة غير صحيحة.",
          }, 400);
        }

        const material = await env.DB.prepare(`
          SELECT m.id, m.is_free
          FROM materials m
          JOIN student_subjects ss ON ss.subject_id = m.subject_id
          WHERE m.id = ?
            AND ss.student_id = ?
            AND m.subject_id NOT IN (
              SELECT subject_id FROM archived_subjects
            )
            AND m.id NOT IN (
              SELECT material_id FROM archived_materials
            )
          LIMIT 1
        `).bind(materialId, session.student_id).first();

        if (!material) {
          return reply(request, env, {
            success: false,
            error: "المحتوى غير متاح لحسابك.",
          }, 404);
        }

        if (Number(material.is_free) !== 1) {
          const purchase = await env.DB.prepare(`
            SELECT id FROM orders
            WHERE student_id = ?
              AND material_id = ?
              AND status IN ('approved', 'completed')
            LIMIT 1
          `).bind(session.student_id, materialId).first();

          if (!purchase) {
            return reply(request, env, {
              success: false,
              error: "يجب اعتماد شراء المحتوى أولًا.",
            }, 403);
          }
        }

        await env.DB.batch([
          env.DB.prepare(`
            INSERT INTO student_material_progress
              (student_id, material_id, last_page, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(student_id, material_id) DO UPDATE SET
              last_page = excluded.last_page,
              updated_at = CURRENT_TIMESTAMP
          `).bind(session.student_id, materialId, lastPage),
          env.DB.prepare(`
            INSERT OR IGNORE INTO student_activity_days
              (student_id, activity_date)
            VALUES (?, date('now'))
          `).bind(session.student_id),
        ]);

        return reply(request, env, {
          success: true,
          material_id: materialId,
          last_page: lastPage,
          message: "تم حفظ تقدمك الدراسي.",
        });
      }
    }

    // عرض صورة الطالب المحفوظة على حسابه
    if (method === "GET" && path === "/api/student/photo") {
      await ensureStudentPhotosTable(env);

      const photo = await env.DB.prepare(
        `SELECT file_key, content_type
         FROM student_photos
         WHERE student_id = ?`
      ).bind(session.student_id).first();

      if (!photo) {
        return reply(request, env, {
          success: true,
          photo_url: null,
        });
      }

      const expectedPrefix = `student-photos/${session.student_id}/`;

            if (
        !photo.file_key ||
        !photo.file_key.startsWith(expectedPrefix) ||
        photo.file_key.includes("..")
      ) {
        return reply(request, env, {
          success: false,
          error: "بيانات الصورة غير صالحة.",
        }, 400);
      }

      const imageResponse = await fetch(
        githubContentsUrl(photo.file_key),
        {
          headers: githubHeaders(env, "application/vnd.github.raw"),
        }
      );

      if (!imageResponse.ok) {
        console.error("Student photo fetch failed:", imageResponse.status);

        return reply(request, env, {
          success: false,
          error: "تعذر تحميل صورة الطالب.",
        }, 502);
      }

      const imageBytes = new Uint8Array(await imageResponse.arrayBuffer());

      return reply(request, env, {
        success: true,
        photo_url:
          `data:${photo.content_type};base64,${bytesToBase64(imageBytes)}`,
      });
    }

    // رفع صورة جديدة وحفظها على حساب الطالب
    if (method === "POST" && path === "/api/student/photo") {
      await ensureStudentPhotosTable(env);

      let form;

      try {
        form = await request.formData();
      } catch {
        return reply(request, env, {
          success: false,
          error: "تعذر قراءة ملف الصورة.",
        }, 400);
      }

      const file = form.get("photo");

      if (!file || typeof file.arrayBuffer !== "function") {
        return reply(request, env, {
          success: false,
          error: "لم يتم اختيار صورة.",
        }, 400);
      }

      if (file.size < 1 || file.size > 5 * 1024 * 1024) {
        return reply(request, env, {
          success: false,
          error: "حجم الصورة يجب ألا يتجاوز 5 ميجابايت.",
        }, 400);
      }

      const contentType = file.type;

      if (!["image/jpeg", "image/png", "image/webp"].includes(contentType)) {
        return reply(request, env, {
          success: false,
          error: "الصيغ المسموحة: JPG وPNG وWEBP فقط.",
        }, 400);
      }

      const fileBytes = new Uint8Array(await file.arrayBuffer());

      if (!validStudentPhoto(fileBytes, contentType)) {
        return reply(request, env, {
          success: false,
          error: "ملف الصورة غير صالح.",
        }, 400);
      }

      const oldPhoto = await env.DB.prepare(
        `SELECT file_key
         FROM student_photos
         WHERE student_id = ?`
      ).bind(session.student_id).first();

      let newFileKey;

      try {
        newFileKey = await uploadStudentPhotoToGitHub(
          env,
          fileBytes,
          contentType,
          session.student_id
        );

        await env.DB.prepare(`
          INSERT INTO student_photos
            (student_id, file_key, content_type, updated_at)
          VALUES (?, ?, ?, CURRENT_TIMESTAMP)
          ON CONFLICT(student_id) DO UPDATE SET
            file_key = excluded.file_key,
            content_type = excluded.content_type,
            updated_at = CURRENT_TIMESTAMP
        `).bind(
          session.student_id,
          newFileKey,
          contentType
        ).run();

      } catch (error) {
        if (newFileKey) {
          try {
            await deleteStudentPhotoFromGitHub(
              env,
              newFileKey,
              session.student_id
            );
          } catch (cleanupError) {
            console.error("New photo cleanup failed:", cleanupError);
          }
        }

        console.error("Student photo save failed:", error);

        return reply(request, env, {
          success: false,
          error: "تعذر حفظ الصورة. حاول مرة أخرى.",
        }, 500);
      }

      if (oldPhoto?.file_key && oldPhoto.file_key !== newFileKey) {
        try {
          await deleteStudentPhotoFromGitHub(
            env,
            oldPhoto.file_key,
            session.student_id
          );
        } catch (error) {
          console.error("Old photo cleanup failed:", error);
        }
      }

      return reply(request, env, {
        success: true,
        photo_url:
          `data:${contentType};base64,${bytesToBase64(fileBytes)}`,
        message: "تم حفظ الصورة على حسابك.",
      });
    }

    // عرض ملف PDF بعد التحقق من صلاحية الطالب وعدم أرشفة المحتوى
    const materialViewMatch = path.match(
      /^\/api\/student\/materials\/(\d+)\/view$/
    );

    if (method === "GET" && materialViewMatch) {
      const materialId = Number(materialViewMatch[1]);

      await ensureArchivedSubjectsTable(env);
      await ensureArchivedMaterialsTable(env);

      const material = await env.DB.prepare(
        `SELECT m.id, m.title, m.is_free, m.file_key
         FROM materials m
         JOIN student_subjects ss ON ss.subject_id = m.subject_id
         WHERE m.id = ?
           AND ss.student_id = ?
           AND m.subject_id NOT IN (
             SELECT subject_id FROM archived_subjects
           )
           AND m.id NOT IN (
             SELECT material_id FROM archived_materials
           )`
      )
        .bind(materialId, session.student_id)
        .first();

      if (!material) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "المحتوى غير موجود.",
          },
          404
        );
      }

      const isFree = Number(material.is_free) === 1;
      let hasPurchase = false;

      if (!isFree) {
        const purchase = await env.DB.prepare(
          `SELECT id
           FROM orders
           WHERE student_id = ?
             AND material_id = ?
             AND status IN ('approved', 'completed')
           LIMIT 1`
        )
          .bind(session.student_id, materialId)
          .first();

        hasPurchase = Boolean(purchase);
      }

      if (!isFree && !hasPurchase) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "هذا المحتوى غير متاح. يجب اعتماد طلب الشراء أولاً.",
          },
          403
        );
      }

      const fileKey = clean(material.file_key, 500);

      if (
        !fileKey ||
        !fileKey.startsWith("materials/") ||
        fileKey.includes("..")
      ) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "لم يتم ربط ملف PDF بهذا المحتوى بعد.",
          },
          404
        );
      }

      if (!env.GITHUB_STORAGE_TOKEN) {
        return reply(
          request,
          env,
          {
            success: false,
            error: "خدمة عرض الملفات غير مهيأة.",
          },
          503
        );
      }

      const githubResponse = await fetch(githubContentsUrl(fileKey), {
        method: "GET",
        headers: githubHeaders(env, "application/vnd.github.raw"),
      });

      if (!githubResponse.ok) {
        const details = await githubResponse.text();
        console.error(
          "GitHub PDF view error:",
          githubResponse.status,
          details.slice(0, 300)
        );
        return reply(
          request,
          env,
          {
            success: false,
            error: "تعذر جلب ملف المذكرة من التخزين الخاص.",
          },
          502
        );
      }

      return new Response(githubResponse.body, {
        status: 200,
        headers: {
          ...corsHeaders(request, env),
          "Content-Type": "application/pdf",
          "Content-Disposition": 'inline; filename="zm-academy-material.pdf"',
          "Cache-Control": "private, no-store, no-cache, must-revalidate",
          Pragma: "no-cache",
          "X-Content-Type-Options": "nosniff",
          "Cross-Origin-Resource-Policy": "cross-origin",
        },
      });
    }

    // بيانات الطالب ومواده
    if (method === "GET" && path === "/api/student/me") {
      await ensureArchivedSubjectsTable(env);

      const student = await env.DB.prepare(
        `SELECT id, name, phone, parent_phone,
                grade, school, governorate, created_at
         FROM students
         WHERE id = ?`
      )
        .bind(session.student_id)
        .first();

      const subjects = await env.DB.prepare(
        `SELECT sub.id, sub.name, sub.grade
         FROM student_subjects ss
         JOIN subjects sub ON sub.id = ss.subject_id
         WHERE ss.student_id = ?
           AND sub.id NOT IN (
             SELECT subject_id FROM archived_subjects
           )
         ORDER BY sub.name`
      )
        .bind(session.student_id)
        .all();

      return reply(request, env, {
        success: true,
        student,
        subjects: subjects.results || [],
      });
    }

    // طلبات الطالب ومشترياته مع تحديد العناصر المخفية
    if (method === "GET" && path === "/api/student/purchases") {
      await ensureStudentHiddenPurchasesTable(env);
      const rows = await env.DB.prepare(
        `SELECT o.id AS order_id, o.status, o.created_at,
                m.id AS material_id, m.title, m.type,
                m.price,
                sub.name AS subject_name,
                CASE WHEN h.order_id IS NULL THEN 0 ELSE 1 END AS is_hidden
         FROM orders o
         JOIN materials m ON m.id = o.material_id
         JOIN subjects sub ON sub.id = m.subject_id
         LEFT JOIN student_hidden_purchases h
           ON h.order_id = o.id
          AND h.student_id = o.student_id
         WHERE o.student_id = ?
         ORDER BY o.id DESC`
      )
        .bind(session.student_id)
        .all();

      return reply(request, env, {
        success: true,
        purchases: rows.results || [],
      });
    }

    // حذف الطلب المرفوض أو إخفاء عملية الشراء
    const studentPurchaseDelete = path.match(
      /^\/api\/student\/purchases\/(\d+)$/
    );

    if (method === "DELETE" && studentPurchaseDelete) {
      await ensureStudentHiddenPurchasesTable(env);
      const orderId = Number(studentPurchaseDelete[1]);

      const order = await env.DB.prepare(
        `SELECT id, status
         FROM orders
         WHERE id = ? AND student_id = ?`
      )
        .bind(orderId, session.student_id)
        .first();

      if (!order) {
        return reply(request, env, {
          success: false,
          error: "الطلب غير موجود.",
        }, 404);
      }

      if (order.status === "rejected") {
        await env.DB.prepare(
          `INSERT OR IGNORE INTO student_hidden_purchases (student_id, order_id) VALUES (?, ?)`
        ).bind(session.student_id, orderId).run();
        return reply(request, env, {
          success: true,
          action: "hidden",
          message: "تم إخفاء الطلب المرفوض من قائمتك مع الاحتفاظ بسجله التاريخي.",
        });
      }

      if (order.status === "approved" || order.status === "completed") {
        await env.DB.prepare(
          `INSERT OR IGNORE INTO student_hidden_purchases
           (student_id, order_id)
           VALUES (?, ?)`
        )
          .bind(session.student_id, orderId)
          .run();

        return reply(request, env, {
          success: true,
          action: "hidden",
          message: "تمت إزالة المشتراة من القائمة.",
        });
      }

      return reply(request, env, {
        success: false,
        error: "لا يمكن حذف طلب قيد المراجعة.",
      }, 409);
    }

    // تسجيل خروج الطالب
    if (method === "POST" && path === "/api/student/logout") {
      await env.DB.prepare(
        "DELETE FROM student_sessions WHERE token_hash = ?"
      )
        .bind(session.tokenHash)
        .run();

      return reply(request, env, {
        success: true,
      });
    }

    return reply(
      request,
      env,
      {
        success: false,
        error: "Student endpoint not found.",
      },
      404
    );
  }

  // إنشاء طلب شراء - للطالب المسجل فقط
  if (method === "POST" && path === "/api/orders") {
    const session = await studentSession(request, env);

    if (!session) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "يجب تسجيل الدخول لإنشاء طلب شراء.",
        },
        401
      );
    }

    const body = await readBody(request);
    const materialId = Number(body?.material_id);

    if (!Number.isInteger(materialId) || materialId < 1) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "رقم المحتوى غير صحيح.",
        },
        400
      );
    }

    await ensureArchivedSubjectsTable(env);
    await ensureArchivedMaterialsTable(env);

    const material = await env.DB.prepare(
      `SELECT m.id, m.is_free
       FROM materials m
       JOIN student_subjects ss ON ss.subject_id = m.subject_id
       WHERE m.id = ?
         AND ss.student_id = ?
         AND m.subject_id NOT IN (
           SELECT subject_id FROM archived_subjects
         )
         AND m.id NOT IN (
           SELECT material_id FROM archived_materials
         )`
    )
      .bind(materialId, session.student_id)
      .first();

    if (!material) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "المحتوى غير موجود.",
        },
        404
      );
    }

    if (Number(material.is_free) === 1) {
      return reply(
        request,
        env,
        {
          success: false,
          error: "هذا المحتوى مجاني ولا يحتاج إلى طلب شراء.",
        },
        400
      );
    }

    const duplicate = await env.DB.prepare(
      `SELECT id, status
       FROM orders
       WHERE student_id = ?
         AND material_id = ?
         AND status IN ('pending', 'approved', 'completed')
       LIMIT 1`
    )
      .bind(session.student_id, materialId)
      .first();

    if (duplicate) {
      return reply(
        request,
        env,
        {
          success: false,
          code: "ORDER_ALREADY_EXISTS",
          status: duplicate.status,
          error:
            duplicate.status === "pending"
              ? "لديك طلب شراء قيد المراجعة بالفعل."
              : "هذا المحتوى موجود بالفعل ضمن مشترياتك.",
        },
        409
      );
    }

    const result = await env.DB.prepare(
      `INSERT INTO orders (student_id, material_id, status)
       SELECT ?, ?, 'pending'
       WHERE NOT EXISTS (
         SELECT 1 FROM orders
         WHERE student_id = ?
           AND material_id = ?
           AND status IN ('pending', 'approved', 'completed')
       )`
    )
      .bind(session.student_id, materialId, session.student_id, materialId)
      .run();

    if (!(result.meta?.changes || 0)) {
      return reply(
        request,
        env,
        {
          success: false,
          code: "ORDER_ALREADY_EXISTS",
          error: "لديك طلب شراء قيد المراجعة بالفعل.",
        },
        409
      );
    }

    return reply(
      request,
      env,
      {
        success: true,
        order_id: result.meta.last_row_id,
        status: "pending",
      },
      201
    );
  }

  return reply(
    request,
    env,
    {
      success: false,
      error: "Not found.",
    },
    404
  );
}

export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (error) {
      console.error("Worker Error:", error);

      return reply(
        request,
        env,
        {
          success: false,
          error: "Internal server error.",
        },
        500
      );
    }
  },
};
