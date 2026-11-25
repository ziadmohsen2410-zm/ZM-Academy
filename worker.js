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
    `SELECT ss.id, ss.student_id, s.name, s.phone
     FROM student_sessions ss
     JOIN students s ON s.id = ss.student_id
     JOIN student_devices d
       ON d.student_id = ss.student_id
      AND d.device_token_hash = ss.device_token_hash
      AND d.status = 'approved'
     WHERE ss.token_hash = ?
       AND ss.expires_at > datetime('now')
       AND NOT EXISTS (
         SELECT 1
         FROM student_devices pending
         WHERE pending.student_id = ss.student_id
           AND pending.status = 'pending'
       )`
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


// إنشاء جدول أرشيف الدروس
async function ensureArchivedMaterialsTable(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS archived_materials (
      material_id INTEGER PRIMARY KEY,
      archived_at TEXT DEFAULT CURRENT_TIMESTAMP
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
        await env.DB.batch([
          env.DB.prepare(
            `UPDATE student_devices
             SET status = 'rejected',
                 reviewed_at = CURRENT_TIMESTAMP,
                 reviewed_by = ?
             WHERE student_id = ?
               AND id != ?
               AND status IN ('approved', 'pending')`
          ).bind(session.admin_id, device.student_id, deviceId),

          env.DB.prepare(
            `UPDATE student_devices
             SET status = 'approved',
                 reviewed_at = CURRENT_TIMESTAMP,
                 reviewed_by = ?
             WHERE id = ? AND status = 'pending'`
          ).bind(session.admin_id, deviceId),

          env.DB.prepare(
            "DELETE FROM student_sessions WHERE student_id = ?"
          ).bind(device.student_id),
        ]);

        return reply(request, env, {
          success: true,
          message: "Device approved.",
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

    const pending = await env.DB.prepare(
      `SELECT COUNT(*) AS total
       FROM student_devices
       WHERE student_id = ?
         AND status = 'pending'`
    )
      .bind(account.student_id)
      .first();

    if ((pending?.total || 0) > 0) {
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
      }

      return reply(
        request,
        env,
        {
          success: false,
          code: "DEVICE_APPROVAL_REQUIRED",
          error:
            "الحساب متوقف مؤقتًا لحين مراجعة طلب اعتماد الجهاز. برجاء التواصل مع المدرس.",
        },
        403
      );
    }

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
|
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
          `DELETE FROM orders
           WHERE id = ? AND student_id = ? AND status = 'rejected'`
        )
          .bind(orderId, session.student_id)
          .run();

        return reply(request, env, {
          success: true,
          action: "deleted",
          message: "تم حذف الطلب المرفوض.",
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
