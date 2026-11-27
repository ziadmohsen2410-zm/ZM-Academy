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

  const folder = contentType.startsWith('image/') ? 'media' : 'materials';
  const path = `${folder}/${crypto.randomUUID()}-${safeName}`;

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
    !/^(materials|media)\//.test(fileKey) ||
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

function sanitizeHomepageSettings(value) {
  const source=value&&typeof value==='object'&&!Array.isArray(value)?value:{};
  const text=(v,max=2000)=>String(v??'').trim().slice(0,max);
  const safeLink=(v)=>{
    const raw=text(v,1000);
    if(!raw||raw.startsWith('//'))return '';
    if(/^https:\/\/[^\s]+$/i.test(raw)||raw.startsWith('/')||raw.startsWith('./')||raw.startsWith('#'))return raw;
    return '';
  };
  const safeImage=(v)=>{
    const raw=text(v,1000);
    if(!raw||raw.startsWith('//'))return '';
    if(/^\/assets\/[a-z0-9_./-]+$/i.test(raw)||/^\/api\/media\/\d+$/.test(raw))return raw;
    try {
      const url=new URL(raw);
      const forbidden=['"',"'",'(',')',';','\\','<','>'];
      if(url.protocol==='https:'&&url.hostname&&!url.username&&!url.password&&!forbidden.some(ch=>raw.includes(ch)))return url.href;
    } catch {}
    return '';
  };
  const out={...source};
  out.brandName=text(source.brandName,80);
  out.tagline=text(source.tagline,180);
  const theme=source.theme&&typeof source.theme==='object'?source.theme:{};
  const color=(v,fallback)=>/^#[0-9a-f]{6}$/i.test(String(v||''))?String(v):fallback;
  out.theme={...theme,mode:['dark','light','system'].includes(theme.mode)?theme.mode:'dark',template:['future','glass','minimal','luxury','editorial'].includes(theme.template)?theme.template:'future',primary:color(theme.primary,'#2F80FF'),secondary:color(theme.secondary,'#7B61FF'),background:color(theme.background,'#071226'),surface:color(theme.surface,'#0D1B35'),text:color(theme.text,'#FFFFFF'),muted:color(theme.muted,'#9AA9C4'),font:['cairo','tajawal','system','georgia'].includes(theme.font)?theme.font:'cairo',corners:['round','normal','sharp'].includes(theme.corners)?theme.corners:'normal',buttons:['gradient','solid','outline'].includes(theme.buttons)?theme.buttons:'gradient',cards:['solid','glass','outline'].includes(theme.cards)?theme.cards:'solid',motion:theme.motion==='off'?'off':'on'};
  const hero=source.hero&&typeof source.hero==='object'?source.hero:{};
  out.hero={...hero,eyebrow:text(hero.eyebrow,100),title:text(hero.title,180),highlight:text(hero.highlight,100),description:text(hero.description,1000),primaryText:text(hero.primaryText,80),primaryUrl:safeLink(hero.primaryUrl),secondaryText:text(hero.secondaryText,80),secondaryUrl:safeLink(hero.secondaryUrl)};
  const about=source.about&&typeof source.about==='object'?source.about:{};
  out.about={...about,title:text(about.title,120),description:text(about.description,1500)};
  const branding=source.branding&&typeof source.branding==='object'?source.branding:{};
  out.branding={...branding,logoUrl:safeImage(branding.logoUrl),heroImageUrl:safeImage(branding.heroImageUrl),whatsapp:text(branding.whatsapp,20).replace(/\D/g,'').slice(0,15),facebook:safeLink(branding.facebook),youtube:safeLink(branding.youtube),telegram:safeLink(branding.telegram)};
  const announcement=source.announcement&&typeof source.announcement==='object'?source.announcement:{};
  out.announcement={...announcement,enabled:!!announcement.enabled,text:text(announcement.text,300),buttonText:text(announcement.buttonText,80),url:safeLink(announcement.url)};
  const sections=source.sections&&typeof source.sections==='object'?source.sections:{};
  out.sections={...sections,subjects:sections.subjects!==false,curriculum:sections.curriculum!==false,library:sections.library!==false,about:sections.about!==false,join:sections.join!==false};
  return out;
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
  await ensureColumn(env, 'student_material_progress', 'completed_at', 'TEXT');
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

  // Public image delivery for academy media stored in the private GitHub storage repo.
  if (method === "GET" && path.startsWith("/api/media/")) {
    try {
      const fileKey = decodeURIComponent(path.slice("/api/media/".length));
      if (!fileKey.startsWith("media/") || fileKey.includes("..") || fileKey.includes("\\")) {
        return reply(request, env, { success: false, error: "Invalid media path." }, 400);
      }
      if (!env.GITHUB_STORAGE_TOKEN) {
        return reply(request, env, { success: false, error: "Storage is not configured." }, 503);
      }
      const stored = await fetch(githubContentsUrl(fileKey), { headers: githubHeaders(env) });
      if (!stored.ok) return reply(request, env, { success: false, error: "Media not found." }, 404);
      const item = await stored.json();
      if (!item?.content || item.encoding !== "base64") {
        return reply(request, env, { success: false, error: "Invalid stored media." }, 502);
      }
      const binary = atob(String(item.content).replace(/\s/g, ""));
      const bytes = Uint8Array.from(binary, ch => ch.charCodeAt(0));
      const ext = fileKey.toLowerCase().split(".").pop();
      const type = ext === "png" ? "image/png" : ext === "webp" ? "image/webp" : "image/jpeg";
      return new Response(bytes, { status: 200, headers: {
        ...corsHeaders(request, env), "Content-Type": type,
        "Cache-Control": "public, max-age=86400, stale-while-revalidate=604800",
        "X-Content-Type-Options": "nosniff"
      }});
    } catch (error) {
      console.error("MEDIA_DELIVERY_ERROR:", error?.message || error);
      return reply(request, env, { success: false, error: "Unable to load media." }, 500);
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
        settings: sanitizeHomepageSettings(parseHomepageJson(row?.published_json))
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

  // جميع مسارات الإدارة محمية (platform routes have their own auth/roles)
  if (
    (path.startsWith("/api/admin/") && !path.startsWith("/api/admin/platform/")) ||
    (path === "/api/subjects" && ["POST", "PUT", "DELETE"].includes(method))
  ) {
    const legacyPermission =
      path === "/api/admin/me" ? "dashboard" :
      path === "/api/admin/students" && method === "GET" ? "students.view" :
      path.startsWith("/api/admin/students") || path.startsWith("/api/admin/password-reset-requests") ? "students" :
      path.startsWith("/api/admin/orders") ? "orders" :
      path.startsWith("/api/admin/device-requests") ? "devices" :
      path.startsWith("/api/admin/subjects") || path.startsWith("/api/admin/materials") || path === "/api/subjects" ? "content" :
      path.startsWith("/api/admin/homepage") ? "page_builder" :
      path.startsWith("/api/admin/upload") ? null : "settings";
    const auth = await requireAdminRole(request, env, legacyPermission);
    if (auth.error) return auth.error;
    const session = auth.session;
    if (path.startsWith("/api/admin/upload") &&
        !hasPerm(auth.admin.role, "media") &&
        !hasPerm(auth.admin.role, "content")) {
      return reply(request, env, { success: false, error: "Forbidden" }, 403);
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
        draft: sanitizeHomepageSettings(parseHomepageJson(row?.draft_json)),
        published: sanitizeHomepageSettings(parseHomepageJson(row?.published_json)),
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
      const settings = sanitizeHomepageSettings(body?.settings);

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
        await env.DB.prepare(
          `UPDATE student_devices
           SET status = 'approved',
               reviewed_at = CURRENT_TIMESTAMP,
               reviewed_by = ?
           WHERE id = ? AND status = 'pending'`
        ).bind(session.admin_id, deviceId).run();

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
        await ensureArchivedSubjectsTable(env);
        await env.DB.prepare(
          "INSERT OR IGNORE INTO archived_subjects (subject_id) VALUES (?)"
        ).bind(id).run();
        return reply(request, env, {
          success: true,
          archived: true,
          message: "المادة مرتبطة بطلاب أو دروس؛ تم إخفاؤها بأمان وأرشفتها مع الاحتفاظ بكل السجلات. يمكنك استعادتها لاحقًا.",
        });
      }

      await env.DB.prepare("DELETE FROM subjects WHERE id = ?").bind(id).run();
      return reply(request, env, { success: true, message: "تم حذف المادة بنجاح." });
    }

    // عرض جميع المحتويات للإدارة بما فيها المؤرشفة
    if (method === "GET" && path === "/api/admin/materials") {
      // Older D1 databases may predate file uploads and therefore lack materials.file_key.
      // Add the nullable column before selecting it so the admin content list remains readable.
      const materialsTableReady = await ensureColumn(env, "materials", "file_key", "TEXT");
      if (!materialsTableReady) throw new Error("The materials table is missing from the connected D1 database.");
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
        await ensureArchivedMaterialsTable(env);
        await env.DB.prepare(
          "INSERT OR IGNORE INTO archived_materials (material_id) VALUES (?)"
        ).bind(id).run();
        return reply(request, env, {
          success: true,
          archived: true,
          message: "الدرس مرتبط بطلبات أو مشتريات؛ تم إخفاؤه وأرشفته مع الاحتفاظ بسجلات الطلاب والطلبات. يمكنك استعادته لاحقًا.",
        });
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

        const bytes = new Uint8Array(await file.arrayBuffer());
        const signature = new TextDecoder().decode(bytes.slice(0, 12));
        const isPDF = bytes.length >= 5 && signature.startsWith("%PDF-");
        const isJpeg = bytes.length >= 3 && bytes[0]===0xff && bytes[1]===0xd8 && bytes[2]===0xff;
        const isPng = bytes.length >= 8 && bytes[0]===0x89 && signature.slice(1,4)==="PNG";
        const isWebp = bytes.length >= 12 && signature.slice(0,4)==="RIFF" && signature.slice(8,12)==="WEBP";
        const contentType = isPDF ? "application/pdf" : isJpeg ? "image/jpeg" : isPng ? "image/png" : isWebp ? "image/webp" : "";
        if (!contentType) {
          return reply(request, env, {
            success: false,
            error: "الملف غير مدعوم أو تالف. ارفع PDF أو صورة JPG أو PNG أو WEBP صحيحة.",
          }, 400);
        }

        const fileKey = await uploadToGitHub(env, bytes, file.name, contentType);
        const mediaUrl = contentType.startsWith("image/")
          ? `${new URL(request.url).origin}/api/media/${encodeURIComponent(fileKey)}`
          : null;

        return reply(
          request,
          env,
          {
            success: true,
            file_key: fileKey,
            url: mediaUrl,
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

    if ((pending?.total || 0) > 0 && existingDevice?.status !== "approved") {
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
          SELECT p.material_id, p.last_page, p.updated_at, p.completed_at,
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
        const completed = body?.completed === true || body?.completed === 1 || body?.completed === "1";

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
              (student_id, material_id, last_page, completed_at, updated_at)
            VALUES (?, ?, ?, CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE NULL END, CURRENT_TIMESTAMP)
            ON CONFLICT(student_id, material_id) DO UPDATE SET
              last_page = excluded.last_page,
              completed_at = CASE
                WHEN ? = 1 THEN COALESCE(student_material_progress.completed_at, CURRENT_TIMESTAMP)
                WHEN ? = 0 THEN NULL
                ELSE student_material_progress.completed_at
              END,
              updated_at = CURRENT_TIMESTAMP
          `).bind(session.student_id, materialId, lastPage, completed ? 1 : 0, completed ? 1 : 0, body?.completed === false ? 0 : 1),
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
          completed,
          message: completed ? "تم حفظ التقدم وتم تحديد الدرس كمكتمل." : "تم حفظ تقدمك الدراسي.",
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


  // ==================== PLATFORM EXTENSIONS ====================

  // --- helpers ---
  const nowIso = () => new Date().toISOString();
  const safeJsonParse = (v, fallback) => { try { return JSON.parse(v); } catch { return fallback; } };
  const asInt = (v, d=0) => { const n = Number(v); return Number.isFinite(n) ? Math.trunc(n) : d; };
  const validateExamInput = (b) => {
    const duration = b?.duration_minutes === '' || b?.duration_minutes == null ? null : Number(b.duration_minutes);
    const attempts = b?.attempts_allowed === '' || b?.attempts_allowed == null ? 1 : Number(b.attempts_allowed);
    const status = clean(b?.status || 'draft', 20);
    if (duration !== null && (!Number.isInteger(duration) || duration < 1 || duration > 600)) return 'مدة الاختبار يجب أن تكون من 1 إلى 600 دقيقة';
    if (!Number.isInteger(attempts) || attempts < 1 || attempts > 20) return 'عدد المحاولات يجب أن يكون من 1 إلى 20';
    if (!['draft','published','closed','archived'].includes(status)) return 'حالة الاختبار غير صالحة';
    const starts = b?.starts_at ? Date.parse(b.starts_at) : null;
    const ends = b?.ends_at ? Date.parse(b.ends_at) : null;
    if (b?.starts_at && !Number.isFinite(starts)) return 'تاريخ بداية الاختبار غير صالح';
    if (b?.ends_at && !Number.isFinite(ends)) return 'تاريخ نهاية الاختبار غير صالح';
    if (starts !== null && ends !== null && ends <= starts) return 'يجب أن يكون موعد النهاية بعد موعد البداية';
    return null;
  };
  const normalizeStudentPreferences = (value) => {
    const raw=value&&typeof value==='object'&&!Array.isArray(value)?value:{};
    const prefs={};
    if(['dark','light'].includes(raw.mode)) prefs.mode=raw.mode;
    if(typeof raw.primary==='string' && /^#[0-9a-fA-F]{6}$/.test(raw.primary)) prefs.primary=raw.primary;
    if(typeof raw.secondary==='string' && /^#[0-9a-fA-F]{6}$/.test(raw.secondary)) prefs.secondary=raw.secondary;
    if(['normal','large','xlarge'].includes(raw.fontSize)) prefs.fontSize=raw.fontSize;
    return prefs;
  };
  const validateExamQuestion = (b) => {
    const type = clean(b?.type, 20);
    const question = clean(b?.question_text, 4000);
    const points = b?.points == null || b?.points === '' ? 1 : Number(b.points);
    if (!['mcq','true_false','essay'].includes(type)) return 'نوع السؤال غير صالح';
    if (!question) return 'نص السؤال مطلوب';
    if (!Number.isFinite(points) || points <= 0 || points > 1000) return 'درجة السؤال يجب أن تكون أكبر من صفر وحتى 1000';
    if (type === 'mcq' && (!Array.isArray(b?.options) || b.options.length < 2)) return 'سؤال الاختيار من متعدد يحتاج إلى اختيارين على الأقل';
    return null;
  };
  const isAdminRole = (role) => ['super_admin','admin','content_manager','teacher','support'].includes(role);
  const ADMIN_PERMS = {
    super_admin: ['*'],
    admin: ['dashboard','settings','students','content','orders','devices','parents','exams','ads','notifications','analytics','page_builder','theme','ai','backups','roles','audit','media'],
    content_manager: ['dashboard','content','media','page_builder','theme','ads','notifications','exams'],
    teacher: ['dashboard','content','exams','analytics','notifications','students.view'],
    support: ['dashboard','students','orders','devices','parents','notifications','audit.view']
  };
  const hasPerm = (role, perm) => {
    const perms = ADMIN_PERMS[role] || [];
    return perms.includes('*') || perms.includes(perm) || perms.includes(perm.split('.')[0]);
  };
  async function ensureColumn(env, table, column, ddl) {
    // Verify live D1 schema before altering it. Swallowing every ALTER error
    // allowed later SELECT statements to fail with an opaque internal 500.
    const allowedTables = new Set(['admin_users','students','orders','materials','subjects','exam_attempts','student_material_progress']);
    if (!allowedTables.has(table) || !/^[a-z_]+$/.test(column)) throw new Error('Unsupported schema migration target.');
    const inspect = async () => {
      const result = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
      return result.results || [];
    };
    let columns = await inspect();
    if (!columns.length) return false;
    if (columns.some(item => item.name === column)) return true;
    try {
      await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${ddl}`).run();
    } catch (error) {
      columns = await inspect();
      if (!columns.some(item => item.name === column)) {
        console.error('SCHEMA_COLUMN_MIGRATION_ERROR:', {table,column,message:error?.message||String(error)});
        throw new Error(`Database schema is missing ${table}.${column}; migration failed.`);
      }
    }
    columns = await inspect();
    if (!columns.some(item => item.name === column)) throw new Error(`Database schema verification failed for ${table}.${column}.`);
    return true;
  }
  async function ensurePlatformSchema(env) {
    // core extensions on existing tables
    await ensureColumn(env, 'admin_users', 'display_name', 'TEXT');
    await ensureColumn(env, 'admin_users', 'email', 'TEXT');
    await ensureColumn(env, 'admin_users', 'role', "TEXT DEFAULT 'super_admin'");
    await ensureColumn(env, 'admin_users', 'is_active', 'INTEGER NOT NULL DEFAULT 1');
    await ensureColumn(env, 'admin_users', 'last_login_at', 'TEXT');
    await ensureColumn(env, 'admin_users', 'created_at', 'TEXT');
    await ensureColumn(env, 'students', 'is_active', 'INTEGER NOT NULL DEFAULT 1');
    await ensureColumn(env, 'students', 'created_at', 'TEXT');
    await ensureColumn(env, 'students', 'updated_at', 'TEXT');
    await ensureColumn(env, 'orders', 'review_note', 'TEXT');
    await ensureColumn(env, 'orders', 'reviewed_at', 'TEXT');
    await ensureColumn(env, 'orders', 'reviewed_by', 'TEXT');
    await ensureColumn(env, 'materials', 'is_archived', 'INTEGER NOT NULL DEFAULT 0');
    await ensureColumn(env, 'subjects', 'is_archived', 'INTEGER NOT NULL DEFAULT 0');
    await ensureColumn(env, 'exam_attempts', 'question_order_json', 'TEXT');

    const stmts = [
      `CREATE TABLE IF NOT EXISTS platform_settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL DEFAULT (datetime('now')), updated_by TEXT)`,
      `CREATE TABLE IF NOT EXISTS roles (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, label TEXT NOT NULL, description TEXT DEFAULT '', is_system INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
      `CREATE TABLE IF NOT EXISTS role_permissions (id INTEGER PRIMARY KEY AUTOINCREMENT, role_id INTEGER NOT NULL, permission TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(role_id, permission))`,
      `CREATE TABLE IF NOT EXISTS admin_user_roles (id INTEGER PRIMARY KEY AUTOINCREMENT, admin_user_id INTEGER NOT NULL, role_id INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(admin_user_id, role_id))`,
      `CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, actor_type TEXT NOT NULL, actor_id INTEGER, actor_label TEXT, action TEXT NOT NULL, entity_type TEXT, entity_id TEXT, details_json TEXT, ip TEXT, user_agent TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
      `CREATE TABLE IF NOT EXISTS page_drafts (id INTEGER PRIMARY KEY AUTOINCREMENT, page_key TEXT NOT NULL UNIQUE, title TEXT NOT NULL, content_json TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL DEFAULT (datetime('now')), updated_by TEXT)`,
      `CREATE TABLE IF NOT EXISTS page_published (id INTEGER PRIMARY KEY AUTOINCREMENT, page_key TEXT NOT NULL UNIQUE, title TEXT NOT NULL, content_json TEXT NOT NULL DEFAULT '{}', published_at TEXT NOT NULL DEFAULT (datetime('now')), published_by TEXT)`,
      `CREATE TABLE IF NOT EXISTS page_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, page_key TEXT NOT NULL, title TEXT NOT NULL, content_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'published', created_at TEXT NOT NULL DEFAULT (datetime('now')), created_by TEXT)`,
      `CREATE TABLE IF NOT EXISTS student_preferences (student_id INTEGER PRIMARY KEY, preferences_json TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL DEFAULT (datetime('now')))`,
      `CREATE TABLE IF NOT EXISTS parents (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT, phone TEXT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')))`,
      `CREATE TABLE IF NOT EXISTS parent_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, parent_id INTEGER NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
      `CREATE TABLE IF NOT EXISTS parent_student_links (id INTEGER PRIMARY KEY AUTOINCREMENT, parent_id INTEGER NOT NULL, student_id INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', requested_at TEXT NOT NULL DEFAULT (datetime('now')), reviewed_at TEXT, reviewed_by TEXT, note TEXT, UNIQUE(parent_id, student_id))`,
      `CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT NOT NULL, type TEXT NOT NULL DEFAULT 'general', audience_type TEXT NOT NULL DEFAULT 'all', audience_value TEXT, scheduled_at TEXT, sent_at TEXT, created_by TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), is_important INTEGER NOT NULL DEFAULT 0)`,
      `CREATE TABLE IF NOT EXISTS notification_reads (id INTEGER PRIMARY KEY AUTOINCREMENT, notification_id INTEGER NOT NULL, user_type TEXT NOT NULL, user_id INTEGER NOT NULL, read_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(notification_id, user_type, user_id))`,
      `CREATE TABLE IF NOT EXISTS ads (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT, image_url TEXT, link_url TEXT, cta_text TEXT, placement TEXT NOT NULL DEFAULT 'home', audience_type TEXT NOT NULL DEFAULT 'all', audience_value TEXT, priority INTEGER NOT NULL DEFAULT 0, starts_at TEXT, ends_at TEXT, is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')))`,
      `CREATE TABLE IF NOT EXISTS ad_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ad_id INTEGER NOT NULL, event_type TEXT NOT NULL, user_type TEXT, user_id INTEGER, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
      `CREATE TABLE IF NOT EXISTS exams (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT, subject_id INTEGER, grade TEXT, status TEXT NOT NULL DEFAULT 'draft', duration_minutes INTEGER, attempts_allowed INTEGER DEFAULT 1, starts_at TEXT, ends_at TEXT, shuffle_questions INTEGER NOT NULL DEFAULT 0, show_results INTEGER NOT NULL DEFAULT 1, created_by TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')))`,
      `CREATE TABLE IF NOT EXISTS exam_questions (id INTEGER PRIMARY KEY AUTOINCREMENT, exam_id INTEGER NOT NULL, type TEXT NOT NULL, question_text TEXT NOT NULL, options_json TEXT, correct_answer_json TEXT, points REAL NOT NULL DEFAULT 1, order_index INTEGER NOT NULL DEFAULT 0, explanation TEXT)`,
      `CREATE TABLE IF NOT EXISTS exam_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, exam_id INTEGER NOT NULL, student_id INTEGER NOT NULL, started_at TEXT NOT NULL DEFAULT (datetime('now')), submitted_at TEXT, score REAL, max_score REAL, status TEXT NOT NULL DEFAULT 'in_progress', answers_json TEXT, question_order_json TEXT, feedback_json TEXT, graded_by TEXT, graded_at TEXT)`,
      `CREATE TABLE IF NOT EXISTS ai_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, actor_type TEXT NOT NULL, actor_id INTEGER, tool TEXT NOT NULL, prompt_preview TEXT, response_status TEXT, tokens_estimate INTEGER, created_at TEXT NOT NULL DEFAULT (datetime('now')))`,
      `CREATE TABLE IF NOT EXISTS backup_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, status TEXT NOT NULL, details_json TEXT, created_by TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')))`
    ];
    for (const sql of stmts) { try { await env.DB.prepare(sql).run(); } catch(e) { console.error('schema', e.message); } }
    const idx = [
      `CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_page_versions_key ON page_versions(page_key, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_parent_sessions_parent ON parent_sessions(parent_id)`,
      `CREATE INDEX IF NOT EXISTS idx_parent_links_parent ON parent_student_links(parent_id)`,
      `CREATE INDEX IF NOT EXISTS idx_exam_questions_exam ON exam_questions(exam_id)`,
      `CREATE INDEX IF NOT EXISTS idx_exam_attempts_exam_student ON exam_attempts(exam_id, student_id)`,
      `CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC)`
    ];
    for (const sql of idx) { try { await env.DB.prepare(sql).run(); } catch(_) {} }
    try { await env.DB.prepare(`INSERT OR IGNORE INTO roles (id,name,label,description,is_system) VALUES (1,'super_admin','Super Admin','Full access',1),(2,'admin','Admin','Administrative access',1),(3,'content_manager','Content Manager','Manage content',1),(4,'teacher','Teacher','Manage exams/content',1),(5,'support','Support','Support and requests',1)`).run(); } catch(_) {}
  }
  async function logAudit(env, entry) {
    try {
      await ensurePlatformSchema(env);
      await env.DB.prepare(`INSERT INTO audit_logs (actor_type,actor_id,actor_label,action,entity_type,entity_id,details_json,ip,user_agent,created_at) VALUES (?,?,?,?,?,?,?,?,?,datetime('now'))`)
        .bind(entry.actor_type||'system', entry.actor_id||null, entry.actor_label||null, entry.action||'unknown', entry.entity_type||null, entry.entity_id!=null?String(entry.entity_id):null, entry.details_json?JSON.stringify(entry.details_json):null, entry.ip||null, entry.user_agent||null).run();
    } catch(e) { console.error('audit', e.message); }
  }
  async function requireAdminRole(request, env, perm=null) {
    const session = await adminSession(request, env);
    if (!session) return { error: reply(request, env, {success:false,error:'Unauthorized'}, 401) };
    await ensurePlatformSchema(env);
    const admin = await env.DB.prepare(`SELECT id, username, display_name, email, role, is_active FROM admin_users WHERE id=?`).bind(session.admin_id).first();
    if (!admin || Number(admin.is_active) === 0) return { error: reply(request, env, {success:false,error:'Account disabled'}, 403) };
    const role = admin.role || 'super_admin';
    if (perm && !hasPerm(role, perm)) return { error: reply(request, env, {success:false,error:'Forbidden'}, 403) };
    return { session, admin: {...admin, role} };
  }
  async function parentSession(request, env) {
    await ensurePlatformSchema(env);
    const token = bearer(request);
    if (!token) return null;
    const tokenHash = await sha256(token);
    const row = await env.DB.prepare(`SELECT ps.id as session_id, ps.parent_id, ps.expires_at, p.name, p.username, p.is_active FROM parent_sessions ps JOIN parents p ON p.id=ps.parent_id WHERE ps.token_hash=?`).bind(tokenHash).first();
    if (!row) return null;
    if (new Date(row.expires_at).getTime() < Date.now()) {
      await env.DB.prepare(`DELETE FROM parent_sessions WHERE id=?`).bind(row.session_id).run();
      return null;
    }
    if (Number(row.is_active) === 0) return null;
    return row;
  }
  function settingDefault(key) {
    const defaults = {
      general: { academyName:'ZM Academy', tagline:'التعلم بذكاء، والتفكير بلا حدود', logo:'', favicon:'', description:'', supportEmail:'', supportPhone:'', whatsapp:'', facebook:'', youtube:'', telegram:'', language:'ar', timezone:'Africa/Cairo', maintenance:false, maintenanceMessage:'الموقع في وضع الصيانة', registrationEnabled:true },
      theme: { mode:'dark', primary:'#2F80FF', secondary:'#7B61FF', background:'#071226', surface:'#0D1B35', text:'#FFFFFF', muted:'#9AA9C4', radius:'18px', font:'Cairo', template:'future', motion:true },
    };
    return defaults[key] || {};
  }
  async function getSetting(env, key) {
    await ensurePlatformSchema(env);
    const row = await env.DB.prepare(`SELECT value_json FROM platform_settings WHERE key=?`).bind(key).first();
    return row ? { ...settingDefault(key), ...safeJsonParse(row.value_json, {}) } : settingDefault(key);
  }
  async function setSetting(env, key, value, actor) {
    await ensurePlatformSchema(env);
    await env.DB.prepare(`INSERT INTO platform_settings(key,value_json,updated_at,updated_by) VALUES(?,?,datetime('now'),?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, updated_at=datetime('now'), updated_by=excluded.updated_by`)
      .bind(key, JSON.stringify(value||{}), actor||null).run();
  }

  // Ensure schema for platform endpoints
  if (path.startsWith('/api/admin/platform') || path.startsWith('/api/parent') || path.startsWith('/api/public/') || path.startsWith('/api/ai/')) {
    await ensurePlatformSchema(env);
  }

  // ---- Public settings/ads/pages ----
  if (method === 'GET' && path === '/api/public/settings') {
    const general = await getSetting(env,'general');
    const theme = await getSetting(env,'theme');
    return reply(request, env, {success:true, settings:{general, theme}});
  }
  if (method === 'GET' && path === '/api/public/ads') {
    await ensurePlatformSchema(env);
    const placement = clean(url.searchParams.get('placement')||'home', 40);
    const rows = await env.DB.prepare(`SELECT id,title,body,image_url,link_url,cta_text,placement,priority,starts_at,ends_at FROM ads WHERE is_active=1 AND (placement=? OR placement='all') AND (starts_at IS NULL OR starts_at <= datetime('now')) AND (ends_at IS NULL OR ends_at >= datetime('now')) ORDER BY priority DESC, id DESC LIMIT 20`).bind(placement).all();
    return reply(request, env, {success:true, ads: rows.results||[]});
  }
  if (method === 'POST' && /^\/api\/public\/ads\/\d+\/(view|click)$/.test(path)) {
    await ensurePlatformSchema(env);
    const m = path.match(/\/(\d+)\/(view|click)$/);
    await env.DB.prepare(`INSERT INTO ad_events(ad_id,event_type,user_type,user_id,created_at) VALUES(?,?,?,?,datetime('now'))`).bind(Number(m[1]), m[2], null, null).run();
    return reply(request, env, {success:true});
  }
  if (method === 'GET' && path.startsWith('/api/public/pages/')) {
    await ensurePlatformSchema(env);
    const key = clean(decodeURIComponent(path.split('/').pop()||''), 80);
    const row = await env.DB.prepare(`SELECT page_key,title,content_json,published_at FROM page_published WHERE page_key=?`).bind(key).first();
    return reply(request, env, {success:true, page: row ? {...row, content:safeJsonParse(row.content_json,{})} : null});
  }

  // ---- Parent auth ----
  if (method === 'POST' && path === '/api/parent/register') {
    await ensurePlatformSchema(env);
    const body = await readBody(request);
    const name = clean(body?.name, 100);
    const username = clean(body?.username, 60).toLowerCase();
    const password = String(body?.password||'');
    const phone = clean(body?.phone, 30);
    const email = clean(body?.email, 120).toLowerCase();
    if (!name || !/^[a-z0-9_.-]{3,60}$/.test(username) || password.length < 8) return reply(request, env, {success:false,error:'بيانات غير صالحة'}, 400);
    const regAllowed = await consumeApiRateLimit(env, request, "parent-register-ip", "*", 20, 3600);
    if (!regAllowed) return reply(request, env, {success:false,error:'محاولات كثيرة. حاول لاحقًا.'}, 429);
    const exists = await env.DB.prepare(`SELECT id FROM parents WHERE username=?`).bind(username).first();
    if (exists) return reply(request, env, {success:false,error:'اسم المستخدم مستخدم'}, 409);
    const hash = await passwordHash(password);
    await env.DB.prepare(`INSERT INTO parents(name,email,phone,username,password_hash) VALUES(?,?,?,?,?)`).bind(name,email,phone,username,hash).run();
    return reply(request, env, {success:true});
  }
  if (method === 'POST' && path === '/api/parent/login') {
    await ensurePlatformSchema(env);
    const body = await readBody(request);
    const username = clean(body?.username,60).toLowerCase();
    const password = String(body?.password||'');
    const ipAllowed = await consumeApiRateLimit(env, request, "parent-login-ip", "*", 60, 900);
    const userAllowed = await consumeApiRateLimit(env, request, "parent-login-user", username, 8, 900);
    if (!ipAllowed || !userAllowed) return reply(request, env, {success:false,error:'محاولات كثيرة. انتظر 15 دقيقة ثم حاول مرة أخرى.'}, 429);
    const parent = await env.DB.prepare(`SELECT * FROM parents WHERE username=?`).bind(username).first();
    if (!parent || !(await verifyPassword(password, parent.password_hash))) return reply(request, env, {success:false,error:'بيانات الدخول غير صحيحة'}, 401);
    if (Number(parent.is_active)===0) return reply(request, env, {success:false,error:'الحساب موقوف'}, 403);
    const token = randomToken(); const tokenHash = await sha256(token);
    await env.DB.prepare(`INSERT INTO parent_sessions(parent_id,token_hash,expires_at) VALUES(?,?,datetime('now', ?))`).bind(parent.id, tokenHash, `+${SESSION_DAYS} days`).run();
    return reply(request, env, {success:true, token, parent:{id:parent.id,name:parent.name,username:parent.username}});
  }
  if (path.startsWith('/api/parent/')) {
    const ps = await parentSession(request, env);
    if (!ps) return reply(request, env, {success:false,error:'Unauthorized'}, 401);
    if (method==='GET' && path==='/api/parent/me') return reply(request, env, {success:true, parent:{id:ps.parent_id,name:ps.name,username:ps.username}});
    if (method==='POST' && path==='/api/parent/logout') {
      const t=bearer(request); if(t){ const h=await sha256(t); await env.DB.prepare(`DELETE FROM parent_sessions WHERE token_hash=?`).bind(h).run(); }
      return reply(request, env, {success:true});
    }
    if (method==='GET' && path==='/api/parent/children') {
      const rows = await env.DB.prepare(`SELECT l.id as link_id,l.status,l.requested_at,l.reviewed_at,s.id,s.name,s.grade,s.school FROM parent_student_links l JOIN students s ON s.id=l.student_id WHERE l.parent_id=? ORDER BY l.id DESC`).bind(ps.parent_id).all();
      return reply(request, env, {success:true, children: rows.results||[]});
    }
    if (method==='GET' && path==='/api/parent/notifications') {
      const rows=await env.DB.prepare(`SELECT n.*,CASE WHEN r.id IS NULL THEN 0 ELSE 1 END AS is_read FROM notifications n LEFT JOIN notification_reads r ON r.notification_id=n.id AND r.user_type='parent' AND r.user_id=? WHERE n.audience_type='parents' AND (n.scheduled_at IS NULL OR datetime(n.scheduled_at)<=datetime('now')) ORDER BY n.id DESC LIMIT 100`).bind(ps.parent_id).all();
      return reply(request,env,{success:true,notifications:rows.results||[]});
    }
    if (method==='POST' && /^\/api\/parent\/notifications\/\d+\/read$/.test(path)) {
      const nid=Number(path.split('/')[4]);
      const notification=await env.DB.prepare(`SELECT id FROM notifications WHERE id=? AND audience_type='parents' AND (scheduled_at IS NULL OR datetime(scheduled_at)<=datetime('now'))`).bind(nid).first();
      if(!notification) return reply(request,env,{success:false,error:'الإشعار غير موجود'},404);
      await env.DB.prepare(`INSERT OR IGNORE INTO notification_reads(notification_id,user_type,user_id) VALUES(?, 'parent', ?)`).bind(nid,ps.parent_id).run();
      return reply(request,env,{success:true});
    }
    if (method==='POST' && path==='/api/parent/link-request') {
      const allowed=await consumeApiRateLimit(env,request,'parent-link-request',ps.parent_id,5,3600);
      if(!allowed) return reply(request,env,{success:false,error:'تجاوزت عدد طلبات ربط الطلاب المسموح بها. حاول بعد ساعة.'},429);
      const body = await readBody(request);
      const studentUsername = clean(body?.student_username,60).toLowerCase();
      const studentPhone = clean(body?.student_phone,30).replace(/[^\d]/g,'');
      const st = await env.DB.prepare(`SELECT sa.student_id, s.name FROM student_accounts sa JOIN students s ON s.id=sa.student_id WHERE sa.username=? AND s.phone=?`).bind(studentUsername, studentPhone).first();
      if (!st) return reply(request, env, {success:false,error:'لم يتم العثور على طالب مطابق'}, 404);
      await env.DB.prepare(`INSERT INTO parent_student_links(parent_id,student_id,status) VALUES(?,?, 'pending') ON CONFLICT(parent_id,student_id) DO UPDATE SET status='pending', requested_at=datetime('now')`).bind(ps.parent_id, st.student_id).run();
      await logAudit(env,{actor_type:'parent',actor_id:ps.parent_id,actor_label:ps.username,action:'parent.link.request',entity_type:'student',entity_id:st.student_id});
      return reply(request, env, {success:true});
    }
    if (method==='GET' && /^\/api\/parent\/children\/\d+\/overview$/.test(path)) {
      const studentId = Number(path.split('/')[4]);
      const link = await env.DB.prepare(`SELECT status FROM parent_student_links WHERE parent_id=? AND student_id=?`).bind(ps.parent_id, studentId).first();
      if (!link || link.status!=='approved') return reply(request, env, {success:false,error:'غير مصرح'}, 403);
      const student = await env.DB.prepare(`SELECT id,name,phone,grade,school,governorate FROM students WHERE id=?`).bind(studentId).first();
      const subjects = await env.DB.prepare(`SELECT s.id,s.name FROM student_subjects ss JOIN subjects s ON s.id=ss.subject_id WHERE ss.student_id=?`).bind(studentId).all();
      const orders = await env.DB.prepare(`SELECT o.id,o.status,o.created_at,m.title as material_title FROM orders o LEFT JOIN materials m ON m.id=o.material_id WHERE o.student_id=? ORDER BY o.id DESC LIMIT 50`).bind(studentId).all();
      const attempts = await env.DB.prepare(`SELECT a.id,a.exam_id,CASE WHEN a.status='graded' AND e.show_results<>0 THEN a.score ELSE NULL END AS score,CASE WHEN a.status='graded' AND e.show_results<>0 THEN a.max_score ELSE NULL END AS max_score,a.status,a.submitted_at,e.title as exam_title FROM exam_attempts a JOIN exams e ON e.id=a.exam_id WHERE a.student_id=? ORDER BY a.id DESC LIMIT 50`).bind(studentId).all();
      return reply(request, env, {success:true, student, subjects:subjects.results||[], orders:orders.results||[], attempts:attempts.results||[]});
    }
    return reply(request, env, {success:false,error:'Not found'}, 404);
  }

  // ---- Student preferences ----
  if (method === 'GET' && path === '/api/student/preferences') {
    const session = await studentSession(request, env);
    if (!session) return reply(request, env, {success:false,error:'Unauthorized'}, 401);
    await ensurePlatformSchema(env);
    const row = await env.DB.prepare(`SELECT preferences_json FROM student_preferences WHERE student_id=?`).bind(session.student_id).first();
    return reply(request, env, {success:true, preferences: normalizeStudentPreferences(safeJsonParse(row?.preferences_json, {}))});
  }
  if (method === 'PUT' && path === '/api/student/preferences') {
    const session = await studentSession(request, env);
    if (!session) return reply(request, env, {success:false,error:'Unauthorized'}, 401);
    await ensurePlatformSchema(env);
    const body = await readBody(request);
    const prefs = normalizeStudentPreferences(body?.preferences);
    await env.DB.prepare(`INSERT INTO student_preferences(student_id,preferences_json,updated_at) VALUES(?,?,datetime('now')) ON CONFLICT(student_id) DO UPDATE SET preferences_json=excluded.preferences_json, updated_at=datetime('now')`).bind(session.student_id, JSON.stringify(prefs)).run();
    return reply(request, env, {success:true});
  }

  // ---- Admin platform endpoints ----
  if (path.startsWith('/api/admin/platform/')) {
    const auth = await requireAdminRole(request, env, null);
    if (auth.error) return auth.error;
    const { admin } = auth;
    const ip = request.headers.get('CF-Connecting-IP') || '';
    const ua = clean(request.headers.get('User-Agent')||'', 200);

    if (method==='GET' && path==='/api/admin/platform/me') {
      return reply(request, env, {success:true, admin:{id:admin.id, username:admin.username, display_name:admin.display_name, role:admin.role, permissions: ADMIN_PERMS[admin.role]||[]}});
    }

    // Student directory (platform API alias for the legacy admin route).
    if (method==='GET' && path==='/api/admin/platform/students') {
      if (!hasPerm(admin.role,'students') && !hasPerm(admin.role,'students.view')) {
        return reply(request, env, {success:false,error:'Forbidden'},403);
      }
      const rows = await env.DB.prepare(`
        SELECT id, name, phone, parent_phone, grade, school, governorate, created_at
        FROM students
        ORDER BY id DESC
        LIMIT 500
      `).all();
      return reply(request, env, {success:true, students:rows.results||[]});
    }

    // Settings
    if (path==='/api/admin/platform/settings') {
      if (!hasPerm(admin.role,'settings')) return reply(request, env, {success:false,error:'Forbidden'},403);
      if (method==='GET') {
        const general = await getSetting(env,'general');
        const theme = await getSetting(env,'theme');
        return reply(request, env, {success:true, settings:{general,theme}});
      }
      if (method==='PUT') {
        const body = await readBody(request);
        if (body.general) await setSetting(env,'general', body.general, admin.username);
        if (body.theme) await setSetting(env,'theme', body.theme, admin.username);
        await logAudit(env,{actor_type:'admin',actor_id:admin.id,actor_label:admin.username,action:'settings.update',entity_type:'settings',entity_id:'platform',details_json:{keys:Object.keys(body||{})},ip,user_agent:ua});
        return reply(request, env, {success:true});
      }
    }

    // Dashboard stats
    if (method==='GET' && path==='/api/admin/platform/dashboard') {
      if (!hasPerm(admin.role,'dashboard')) return reply(request, env, {success:false,error:'Forbidden'},403);
      const q = async (sql, ...args) => { try { const r=await env.DB.prepare(sql).bind(...args).first(); return r; } catch { return {}; } };
      const [students, orders, pendingOrders, subjects, materials, parents, exams, ads, pendingDevices] = await Promise.all([
        q(`SELECT COUNT(*) as c FROM students`),
        q(`SELECT COUNT(*) as c FROM orders`),
        q(`SELECT COUNT(*) as c FROM orders WHERE status='pending'`),
        q(`SELECT COUNT(*) as c FROM subjects`),
        q(`SELECT COUNT(*) as c FROM materials`),
        q(`SELECT COUNT(*) as c FROM parents`),
        q(`SELECT COUNT(*) as c FROM exams`),
        q(`SELECT COUNT(*) as c FROM ads WHERE is_active=1`),
        q(`SELECT COUNT(*) as c FROM student_devices WHERE status='pending'`)
      ]);
      return reply(request, env, {success:true, stats:{
        students: students.c||0, orders: orders.c||0, pendingOrders: pendingOrders.c||0,
        subjects: subjects.c||0, materials: materials.c||0, parents: parents.c||0,
        exams: exams.c||0, activeAds: ads.c||0, pendingDevices: pendingDevices.c||0
      }});
    }

    // Audit logs
    if (method==='GET' && path==='/api/admin/platform/audit') {
      if (!hasPerm(admin.role,'audit') && !hasPerm(admin.role,'audit.view')) return reply(request, env, {success:false,error:'Forbidden'},403);
      const limit = Math.min(200, Math.max(1, asInt(url.searchParams.get('limit'), 50)));
      const rows = await env.DB.prepare(`SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?`).bind(limit).all();
      return reply(request, env, {success:true, logs: rows.results||[]});
    }

    // Page builder
    if (path==='/api/admin/platform/pages') {
      if (!hasPerm(admin.role,'page_builder')) return reply(request, env, {success:false,error:'Forbidden'},403);
      if (method==='GET') {
        const rows = await env.DB.prepare(`SELECT p.page_key,p.title,p.updated_at,pub.published_at FROM page_drafts p LEFT JOIN page_published pub ON pub.page_key=p.page_key ORDER BY p.updated_at DESC`).all();
        return reply(request, env, {success:true, pages: rows.results||[]});
      }
    }
    if (path.startsWith('/api/admin/platform/pages/')) {
      if (!hasPerm(admin.role,'page_builder')) return reply(request, env, {success:false,error:'Forbidden'},403);
      const parts = path.split('/').filter(Boolean); // api admin platform pages <key> [action]
      const key = clean(decodeURIComponent(parts[4]||''), 80);
      const action = parts[5] || '';
      if (!/^[a-z0-9][a-z0-9_-]{0,79}$/i.test(key)) return reply(request, env, {success:false,error:'مفتاح الصفحة يجب أن يبدأ بحرف أو رقم ويحتوي على حروف أو أرقام أو شرطة فقط.'},400);
      if (method==='GET' && !action) {
        const draft = await env.DB.prepare(`SELECT * FROM page_drafts WHERE page_key=?`).bind(key).first();
        const pub = await env.DB.prepare(`SELECT * FROM page_published WHERE page_key=?`).bind(key).first();
        const versions = await env.DB.prepare(`SELECT id,page_key,title,status,created_at,created_by FROM page_versions WHERE page_key=? ORDER BY id DESC LIMIT 20`).bind(key).all();
        return reply(request, env, {success:true, draft: draft?{...draft,content:safeJsonParse(draft.content_json,{})}:null, published: pub?{...pub,content:safeJsonParse(pub.content_json,{})}:null, versions: versions.results||[]});
      }
      if (method==='PUT' && !action) {
        const body = await readBody(request);
        const title = clean(body?.title || key, 120);
        const content = body?.content && typeof body.content==='object' ? body.content : {};
        await env.DB.prepare(`INSERT INTO page_drafts(page_key,title,content_json,updated_at,updated_by) VALUES(?,?,?,?,?) ON CONFLICT(page_key) DO UPDATE SET title=excluded.title,content_json=excluded.content_json,updated_at=datetime('now'),updated_by=excluded.updated_by`).bind(key,title,JSON.stringify(content),nowIso(),admin.username).run();
        await logAudit(env,{actor_type:'admin',actor_id:admin.id,actor_label:admin.username,action:'page.draft.save',entity_type:'page',entity_id:key,ip,user_agent:ua});
        return reply(request, env, {success:true});
      }
      if (method==='POST' && action==='publish') {
        const draft = await env.DB.prepare(`SELECT * FROM page_drafts WHERE page_key=?`).bind(key).first();
        if (!draft) return reply(request, env, {success:false,error:'No draft'},404);
        await env.DB.prepare(`INSERT INTO page_published(page_key,title,content_json,published_at,published_by) VALUES(?,?,?,?,?) ON CONFLICT(page_key) DO UPDATE SET title=excluded.title,content_json=excluded.content_json,published_at=datetime('now'),published_by=excluded.published_by`).bind(key,draft.title,draft.content_json,nowIso(),admin.username).run();
        await env.DB.prepare(`INSERT INTO page_versions(page_key,title,content_json,status,created_by) VALUES(?,?,?,'published',?)`).bind(key,draft.title,draft.content_json,admin.username).run();
        await logAudit(env,{actor_type:'admin',actor_id:admin.id,actor_label:admin.username,action:'page.publish',entity_type:'page',entity_id:key,ip,user_agent:ua});
        return reply(request, env, {success:true});
      }
      if (method==='POST' && action==='rollback') {
        const body = await readBody(request);
        const versionId = asInt(body?.version_id);
        const v = await env.DB.prepare(`SELECT * FROM page_versions WHERE id=? AND page_key=?`).bind(versionId,key).first();
        if (!v) return reply(request, env, {success:false,error:'Version not found'},404);
        await env.DB.prepare(`INSERT INTO page_drafts(page_key,title,content_json,updated_at,updated_by) VALUES(?,?,?,?,?) ON CONFLICT(page_key) DO UPDATE SET title=excluded.title,content_json=excluded.content_json,updated_at=datetime('now'),updated_by=excluded.updated_by`).bind(key,v.title,v.content_json,nowIso(),admin.username).run();
        await logAudit(env,{actor_type:'admin',actor_id:admin.id,actor_label:admin.username,action:'page.rollback',entity_type:'page',entity_id:key,details_json:{version_id:versionId},ip,user_agent:ua});
        return reply(request, env, {success:true});
      }
    }

    // Ads
    if (path==='/api/admin/platform/ads') {
      if (!hasPerm(admin.role,'ads')) return reply(request, env, {success:false,error:'Forbidden'},403);
      if (method==='GET') { const rows = await env.DB.prepare(`SELECT a.*, (SELECT COUNT(*) FROM ad_events e WHERE e.ad_id=a.id AND e.event_type='view') as views, (SELECT COUNT(*) FROM ad_events e WHERE e.ad_id=a.id AND e.event_type='click') as clicks FROM ads a ORDER BY id DESC LIMIT 200`).all(); return reply(request, env, {success:true, ads: rows.results||[]}); }
      if (method==='POST') {
        const b = await readBody(request);
        const title = clean(b?.title,120); if(!title) return reply(request, env,{success:false,error:'title required'},400);
        await env.DB.prepare(`INSERT INTO ads(title,body,image_url,link_url,cta_text,placement,audience_type,audience_value,priority,starts_at,ends_at,is_active) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
          .bind(title,clean(b?.body,2000),clean(b?.image_url,500),clean(b?.link_url,500),clean(b?.cta_text,60),clean(b?.placement||'home',40),clean(b?.audience_type||'all',40),clean(b?.audience_value,120),asInt(b?.priority,0),b?.starts_at||null,b?.ends_at||null,b?.is_active?1:0).run();
        await logAudit(env,{actor_type:'admin',actor_id:admin.id,actor_label:admin.username,action:'ad.create',entity_type:'ad',ip,user_agent:ua});
        return reply(request, env, {success:true});
      }
    }
    if (/^\/api\/admin\/platform\/ads\/\d+$/.test(path)) {
      if (!hasPerm(admin.role,'ads')) return reply(request, env, {success:false,error:'Forbidden'},403);
      const id = Number(path.split('/').pop());
      if (method==='PUT') {
        const b=await readBody(request);
        await env.DB.prepare(`UPDATE ads SET title=?,body=?,image_url=?,link_url=?,cta_text=?,placement=?,audience_type=?,audience_value=?,priority=?,starts_at=?,ends_at=?,is_active=?,updated_at=datetime('now') WHERE id=?`)
          .bind(clean(b?.title,120),clean(b?.body,2000),clean(b?.image_url,500),clean(b?.link_url,500),clean(b?.cta_text,60),clean(b?.placement||'home',40),clean(b?.audience_type||'all',40),clean(b?.audience_value,120),asInt(b?.priority,0),b?.starts_at||null,b?.ends_at||null,b?.is_active?1:0,id).run();
        await logAudit(env,{actor_type:'admin',actor_id:admin.id,actor_label:admin.username,action:'ad.update',entity_type:'ad',entity_id:id,ip,user_agent:ua});
        return reply(request, env, {success:true});
      }
      if (method==='DELETE') { await env.DB.prepare(`DELETE FROM ads WHERE id=?`).bind(id).run(); return reply(request, env, {success:true}); }
    }

    // Notifications
    if (path==='/api/admin/platform/notifications') {
      if (!hasPerm(admin.role,'notifications')) return reply(request, env, {success:false,error:'Forbidden'},403);
      if (method==='GET') { const rows = await env.DB.prepare(`SELECT * FROM notifications ORDER BY id DESC LIMIT 200`).all(); return reply(request, env, {success:true, notifications: rows.results||[]}); }
      if (method==='POST') {
        const b=await readBody(request); const title=clean(b?.title,150); const bodyText=clean(b?.body,4000);
        if(!title||!bodyText) return reply(request, env,{success:false,error:'title/body required'},400);
        const audienceType=clean(b?.audience_type||'all',30);
        const audienceValue=clean(b?.audience_value,120);
        if(!['all','parents','student','grade'].includes(audienceType)) return reply(request,env,{success:false,error:'نوع الجمهور غير صالح'},400);
        if(audienceType==='student'&&!/^\d+$/.test(audienceValue)) return reply(request,env,{success:false,error:'أدخل رقم الطالب الصحيح'},400);
        if(audienceType==='grade'&&!audienceValue) return reply(request,env,{success:false,error:'أدخل الصف المستهدف'},400);
        const scheduledAt=b?.scheduled_at?clean(b.scheduled_at,40):null;
        if(scheduledAt&&!Number.isFinite(Date.parse(scheduledAt.replace(' ','T')+'Z'))) return reply(request,env,{success:false,error:'موعد الإرسال غير صالح'},400);
        await env.DB.prepare(`INSERT INTO notifications(title,body,type,audience_type,audience_value,scheduled_at,sent_at,created_by,is_important) VALUES(?,?,?,?,?,?,?,?,?)`)
          .bind(title,bodyText,clean(b?.type||'general',30),audienceType,audienceValue||null,scheduledAt,scheduledAt?null:nowIso(),admin.username,b?.is_important?1:0).run();
        await logAudit(env,{actor_type:'admin',actor_id:admin.id,actor_label:admin.username,action:'notification.create',entity_type:'notification',ip,user_agent:ua});
        return reply(request, env, {success:true});
      }
    }

    // Parents management
    if (path==='/api/admin/platform/parents') {
      if (!hasPerm(admin.role,'parents')) return reply(request, env, {success:false,error:'Forbidden'},403);
      if (method==='GET') {
        const rows = await env.DB.prepare(`SELECT p.id,p.name,p.username,p.phone,p.email,p.is_active,p.created_at,(SELECT COUNT(*) FROM parent_student_links l WHERE l.parent_id=p.id AND l.status='approved') as approved_children,(SELECT COUNT(*) FROM parent_student_links l WHERE l.parent_id=p.id AND l.status='pending') as pending_children FROM parents p ORDER BY p.id DESC LIMIT 300`).all();
        return reply(request, env, {success:true, parents: rows.results||[]});
      }
    }
    if (path==='/api/admin/platform/parent-links') {
      if (!hasPerm(admin.role,'parents')) return reply(request, env, {success:false,error:'Forbidden'},403);
      if (method==='GET') {
        const rows = await env.DB.prepare(`SELECT l.*, p.name as parent_name,p.username as parent_username, s.name as student_name, s.grade FROM parent_student_links l JOIN parents p ON p.id=l.parent_id JOIN students s ON s.id=l.student_id ORDER BY l.id DESC LIMIT 300`).all();
        return reply(request, env, {success:true, links: rows.results||[]});
      }
    }
    if (/^\/api\/admin\/platform\/parent-links\/\d+$/.test(path)) {
      if (!hasPerm(admin.role,'parents')) return reply(request, env, {success:false,error:'Forbidden'},403);
      const id = Number(path.split('/').pop());
      if (method==='PUT') {
        const b = await readBody(request); const status = clean(b?.status,20);
        if(!['approved','rejected','pending'].includes(status)) return reply(request, env,{success:false,error:'bad status'},400);
        await env.DB.prepare(`UPDATE parent_student_links SET status=?, reviewed_at=datetime('now'), reviewed_by=?, note=? WHERE id=?`).bind(status, admin.username, clean(b?.note,500), id).run();
        await logAudit(env,{actor_type:'admin',actor_id:admin.id,actor_label:admin.username,action:'parent_link.review',entity_type:'parent_student_link',entity_id:id,details_json:{status},ip,user_agent:ua});
        return reply(request, env, {success:true});
      }
    }

    // Exams
    if (path==='/api/admin/platform/exams') {
      if (!hasPerm(admin.role,'exams')) return reply(request, env, {success:false,error:'Forbidden'},403);
      if (method==='GET') { const rows = await env.DB.prepare(`SELECT e.*, (SELECT COUNT(*) FROM exam_questions q WHERE q.exam_id=e.id) as questions_count, (SELECT COUNT(*) FROM exam_attempts a WHERE a.exam_id=e.id) as attempts_count FROM exams e ORDER BY e.id DESC LIMIT 200`).all(); return reply(request, env,{success:true, exams: rows.results||[]}); }
      if (method==='POST') {
        const b=await readBody(request); const title=clean(b?.title,160); if(!title) return reply(request, env,{success:false,error:'title required'},400);
        const validationError = validateExamInput(b); if (validationError) return reply(request, env,{success:false,error:validationError},400);
        const res = await env.DB.prepare(`INSERT INTO exams(title,description,subject_id,grade,status,duration_minutes,attempts_allowed,starts_at,ends_at,shuffle_questions,show_results,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
          .bind(title,clean(b?.description,2000),b?.subject_id?Number(b.subject_id):null,clean(b?.grade,40),clean(b?.status||'draft',20),b?.duration_minutes?Number(b.duration_minutes):null,b?.attempts_allowed?Number(b.attempts_allowed):1,b?.starts_at||null,b?.ends_at||null,b?.shuffle_questions?1:0,b?.show_results===false?0:1,admin.username).run();
        await logAudit(env,{actor_type:'admin',actor_id:admin.id,actor_label:admin.username,action:'exam.create',entity_type:'exam',entity_id:res.meta?.last_row_id,ip,user_agent:ua});
        return reply(request, env, {success:true, id: res.meta?.last_row_id});
      }
    }
    if (/^\/api\/admin\/platform\/exams\/\d+$/.test(path)) {
      if (!hasPerm(admin.role,'exams')) return reply(request, env, {success:false,error:'Forbidden'},403);
      const id = Number(path.split('/').pop());
      if (method==='GET') {
        const exam = await env.DB.prepare(`SELECT e.*,(SELECT COUNT(*) FROM exam_attempts a WHERE a.exam_id=e.id) AS attempts_count FROM exams e WHERE e.id=?`).bind(id).first();
        const qs = await env.DB.prepare(`SELECT * FROM exam_questions WHERE exam_id=? ORDER BY order_index ASC, id ASC`).bind(id).all();
        return reply(request, env, {success:true, exam, questions: (qs.results||[]).map(q=>({...q, options:safeJsonParse(q.options_json,[]), correct_answer:safeJsonParse(q.correct_answer_json,null)}))});
      }
      if (method==='PUT') {
        const b=await readBody(request);
        if (!clean(b?.title,160)) return reply(request, env,{success:false,error:'عنوان الاختبار مطلوب'},400);
        const validationError = validateExamInput(b); if (validationError) return reply(request, env,{success:false,error:validationError},400);
        const existingAttempts=await env.DB.prepare(`SELECT COUNT(*) AS c FROM exam_attempts WHERE exam_id=?`).bind(id).first();
        if(Number(existingAttempts?.c||0)>0) {
          await env.DB.prepare(`UPDATE exams SET title=?,description=?,status=?,updated_at=datetime('now') WHERE id=?`).bind(clean(b?.title,160),clean(b?.description,2000),clean(b?.status||'draft',20),id).run();
          return reply(request,env,{success:true,settings_locked:true,message:'تم تحديث بيانات الاختبار. إعدادات التقييم والأسئلة ثابتة بعد بدء الطلاب.'});
        }
        await env.DB.prepare(`UPDATE exams SET title=?,description=?,subject_id=?,grade=?,status=?,duration_minutes=?,attempts_allowed=?,starts_at=?,ends_at=?,shuffle_questions=?,show_results=?,updated_at=datetime('now') WHERE id=?`)
          .bind(clean(b?.title,160),clean(b?.description,2000),b?.subject_id?Number(b.subject_id):null,clean(b?.grade,40),clean(b?.status||'draft',20),b?.duration_minutes?Number(b.duration_minutes):null,b?.attempts_allowed?Number(b.attempts_allowed):1,b?.starts_at||null,b?.ends_at||null,b?.shuffle_questions?1:0,b?.show_results===false?0:1,id).run();
        return reply(request, env, {success:true});
      }
      if (method==='DELETE') {
        const attempts=await env.DB.prepare(`SELECT COUNT(*) AS c FROM exam_attempts WHERE exam_id=?`).bind(id).first();
        if(Number(attempts?.c||0)>0) return reply(request,env,{success:false,error:'لا يمكن حذف اختبار له محاولات طلاب. غيّر حالته إلى مؤرشف بدلًا من الحذف.'},409);
        await env.DB.prepare(`DELETE FROM exam_questions WHERE exam_id=?`).bind(id).run();
        await env.DB.prepare(`DELETE FROM exams WHERE id=?`).bind(id).run();
        return reply(request, env,{success:true});
      }
    }
    if (/^\/api\/admin\/platform\/exams\/\d+\/questions$/.test(path)) {
      if (!hasPerm(admin.role,'exams')) return reply(request, env, {success:false,error:'Forbidden'},403);
      const examId = Number(path.split('/')[5]);
      if (method==='POST') {
        const existingAttempts=await env.DB.prepare(`SELECT COUNT(*) AS c FROM exam_attempts WHERE exam_id=?`).bind(examId).first();
        if(Number(existingAttempts?.c||0)>0) return reply(request,env,{success:false,error:'لا يمكن تعديل أسئلة اختبار بدأه الطلاب. أنشئ نسخة جديدة للاختبار.'},409);
        const b=await readBody(request);
        const validationError = validateExamQuestion(b); if (validationError) return reply(request, env,{success:false,error:validationError},400);
        const type = clean(b?.type,20);
        await env.DB.prepare(`INSERT INTO exam_questions(exam_id,type,question_text,options_json,correct_answer_json,points,order_index,explanation) VALUES(?,?,?,?,?,?,?,?)`)
          .bind(examId,type,clean(b?.question_text,4000),JSON.stringify(b?.options||[]),JSON.stringify(b?.correct_answer??null),Number(b?.points||1),asInt(b?.order_index,0),clean(b?.explanation,2000)).run();
        return reply(request, env, {success:true});
      }
    }
    if (/^\/api\/admin\/platform\/exam-questions\/\d+$/.test(path)) {
      if (!hasPerm(admin.role,'exams')) return reply(request, env, {success:false,error:'Forbidden'},403);
      const qid = Number(path.split('/').pop());
      if (method==='PUT' || method==='DELETE') {
        const question=await env.DB.prepare(`SELECT exam_id FROM exam_questions WHERE id=?`).bind(qid).first();
        if(!question) return reply(request,env,{success:false,error:'السؤال غير موجود'},404);
        const existingAttempts=await env.DB.prepare(`SELECT COUNT(*) AS c FROM exam_attempts WHERE exam_id=?`).bind(question.exam_id).first();
        if(Number(existingAttempts?.c||0)>0) return reply(request,env,{success:false,error:'لا يمكن تعديل أو حذف سؤال بعد بدء الطلاب للاختبار. أنشئ نسخة جديدة.'},409);
      }
      if (method==='PUT') {
        const b=await readBody(request);
        const validationError = validateExamQuestion(b); if (validationError) return reply(request, env,{success:false,error:validationError},400);
        await env.DB.prepare(`UPDATE exam_questions SET type=?,question_text=?,options_json=?,correct_answer_json=?,points=?,order_index=?,explanation=? WHERE id=?`)
          .bind(clean(b?.type,20),clean(b?.question_text,4000),JSON.stringify(b?.options||[]),JSON.stringify(b?.correct_answer??null),Number(b?.points||1),asInt(b?.order_index,0),clean(b?.explanation,2000),qid).run();
        return reply(request, env, {success:true});
      }
      if (method==='DELETE') { await env.DB.prepare(`DELETE FROM exam_questions WHERE id=?`).bind(qid).run(); return reply(request, env,{success:true}); }
    }

    // Exam attempt review and manual essay grading
    if (method==='GET' && path==='/api/admin/platform/exam-attempts') {
      if (!hasPerm(admin.role,'exams')) return reply(request, env,{success:false,error:'Forbidden'},403);
      const examId = asInt(url.searchParams.get('exam_id'),0);
      if (!examId) return reply(request, env,{success:false,error:'exam_id required'},400);
      const rows = await env.DB.prepare(`SELECT a.id,a.exam_id,a.student_id,a.status,a.score,a.max_score,a.started_at,a.submitted_at,s.name AS student_name FROM exam_attempts a JOIN students s ON s.id=a.student_id WHERE a.exam_id=? ORDER BY a.id DESC LIMIT 300`).bind(examId).all();
      return reply(request, env,{success:true,attempts:rows.results||[]});
    }
    if (/^\/api\/admin\/platform\/exam-attempts\/\d+$/.test(path)) {
      if (!hasPerm(admin.role,'exams')) return reply(request, env,{success:false,error:'Forbidden'},403);
      const attemptId = Number(path.split('/').pop());
      if (method==='GET') {
        const attempt = await env.DB.prepare(`SELECT a.*,s.name AS student_name,e.title AS exam_title FROM exam_attempts a JOIN students s ON s.id=a.student_id JOIN exams e ON e.id=a.exam_id WHERE a.id=?`).bind(attemptId).first();
        if (!attempt) return reply(request, env,{success:false,error:'المحاولة غير موجودة'},404);
        const questions = await env.DB.prepare(`SELECT id,question_text,points,order_index FROM exam_questions WHERE exam_id=? AND type='essay' ORDER BY order_index ASC,id ASC`).bind(attempt.exam_id).all();
        return reply(request, env,{success:true,attempt:{...attempt,answers:safeJsonParse(attempt.answers_json,{})},essay_questions:questions.results||[]});
      }
    }
    if (/^\/api\/admin\/platform\/exam-attempts\/\d+\/grade$/.test(path)) {
      if (!hasPerm(admin.role,'exams')) return reply(request, env,{success:false,error:'Forbidden'},403);
      const attemptId = Number(path.split('/')[5]);
      if (method==='PUT') {
        const attempt = await env.DB.prepare(`SELECT id,exam_id,score,status FROM exam_attempts WHERE id=?`).bind(attemptId).first();
        if (!attempt) return reply(request, env,{success:false,error:'المحاولة غير موجودة'},404);
        if (attempt.status!=='submitted') return reply(request, env,{success:false,error:'هذه المحاولة ليست بانتظار التصحيح'},409);
        const questions = await env.DB.prepare(`SELECT id,points FROM exam_questions WHERE exam_id=? AND type='essay'`).bind(attempt.exam_id).all();
        const essayQuestions = questions.results||[];
        if (!essayQuestions.length) return reply(request, env,{success:false,error:'لا توجد أسئلة مقالية للتصحيح'},400);
        const b=await readBody(request); const scores=b?.essay_scores;
        if (!scores || typeof scores!=='object' || Array.isArray(scores)) return reply(request, env,{success:false,error:'درجات الأسئلة المقالية مطلوبة'},400);
        let essayScore=0; const feedback={};
        for (const q of essayQuestions) {
          const value=Number(scores[q.id]);
          const max=Number(q.points||1);
          if (!Object.prototype.hasOwnProperty.call(scores,String(q.id)) || !Number.isFinite(value) || value<0 || value>max) return reply(request, env,{success:false,error:'تأكد من إدخال درجة صحيحة لكل سؤال مقالي'},400);
          essayScore+=value;
          feedback[q.id]=clean(b?.feedback?.[q.id]||'',1000);
        }
        const total=Number(attempt.score||0)+essayScore;
        const gradeUpdate=await env.DB.prepare(`UPDATE exam_attempts SET score=?,status='graded',graded_by=?,graded_at=datetime('now'),feedback_json=? WHERE id=? AND status='submitted'`).bind(total,admin.username,JSON.stringify(feedback),attemptId).run();
        if (!(gradeUpdate.meta?.changes||0)) return reply(request,env,{success:false,error:'تم تصحيح هذه المحاولة بالفعل'},409);
        await logAudit(env,{actor_type:'admin',actor_id:admin.id,actor_label:admin.username,action:'exam.attempt.grade',entity_type:'exam_attempt',entity_id:attemptId,details_json:{essay_score:essayScore},ip,user_agent:ua});
        return reply(request, env,{success:true,score:total});
      }
    }

    // Analytics
    if (method==='GET' && path==='/api/admin/platform/analytics') {
      if (!hasPerm(admin.role,'analytics')) return reply(request, env, {success:false,error:'Forbidden'},403);
      const days = Math.min(90, Math.max(1, asInt(url.searchParams.get('days'), 30)));
      const since = `-${days} days`;
      const safeCount = async (sql, ...args) => { try { const r = await env.DB.prepare(sql).bind(...args).first(); return r?.c||0; } catch { return 0; } };
      const students = await safeCount(`SELECT COUNT(*) c FROM students`);
      const newStudents = await safeCount(`SELECT COUNT(*) c FROM students WHERE created_at >= datetime('now', ?)`, since);
      const orders = await safeCount(`SELECT COUNT(*) c FROM orders WHERE created_at >= datetime('now', ?)`, since);
      const pendingOrders = await safeCount(`SELECT COUNT(*) c FROM orders WHERE status='pending'`);
      const examAttempts = await safeCount(`SELECT COUNT(*) c FROM exam_attempts WHERE submitted_at >= datetime('now', ?)`, since);
      let topMaterials = [];
      try { const r = await env.DB.prepare(`SELECT m.id,m.title,COUNT(o.id) c FROM orders o JOIN materials m ON m.id=o.material_id GROUP BY m.id ORDER BY c DESC LIMIT 10`).all(); topMaterials=r.results||[]; } catch {}
      return reply(request, env, {success:true, analytics:{days, students, newStudents, orders, pendingOrders, examAttempts, topMaterials}});
    }

    // AI proxy (admin)
    if (method==='POST' && path==='/api/admin/platform/ai') {
      if (!hasPerm(admin.role,'ai')) return reply(request, env, {success:false,error:'Forbidden'},403);
      const b = await readBody(request);
      const prompt = clean(b?.prompt, 8000);
      const mode = clean(b?.mode||'admin_assistant', 40);
      if (!prompt) return reply(request, env, {success:false,error:'prompt required'},400);
      if (!(await consumeApiRateLimit(env,request,'admin_ai',admin.id,20,60))) return reply(request, env,{success:false,error:'تم تجاوز الحد المؤقت لطلبات المساعد. حاول بعد دقيقة.',code:'RATE_LIMITED'},429);
      const key = env.AI_API_KEY || env.OPENAI_API_KEY || '';
      if (!key) {
        await env.DB.prepare(`INSERT INTO ai_logs(actor_type,actor_id,tool,prompt_preview,response_status) VALUES(?,?,?,?,?)`).bind('admin',admin.id,mode,prompt.slice(0,200),'not_configured').run();
        return reply(request, env, {success:false,error:'AI service not configured. Set AI_API_KEY secret.', code:'AI_NOT_CONFIGURED'}, 503);
      }
      const endpoint = env.AI_API_URL || 'https://api.openai.com/v1/chat/completions';
      const model = env.AI_MODEL || 'gpt-4o-mini';
      const sys = mode==='content_studio' ? 'أنت مساعد محتوى تعليمي. أنشئ مسودات واضحة قابلة للمراجعة قبل النشر.' : mode==='builder' ? 'أنت مصمم واجهات لمنصة ZM Academy. أعد كائن JSON صالحًا فقط، دون Markdown أو HTML أو CSS أو JavaScript. استخدم المفاتيح الاختيارية: brandName, tagline, theme, hero, about, branding, announcement, sections. داخل theme استخدم mode dark/light/system وحقول الألوان بصيغة HEX من 6 خانات وtemplate future/glass/minimal/luxury/editorial وfont cairo/tajawal/system/georgia وbuttons gradient/solid/outline وcards solid/glass/outline وmotion on/off وcorners normal/round/sharp. داخل hero استخدم eyebrow,title,highlight,description,primaryText,primaryUrl,secondaryText,secondaryUrl. داخل about استخدم title,description. داخل branding استخدم logoUrl,heroImageUrl,whatsapp,facebook,youtube,telegram. داخل announcement استخدم enabled,text,buttonText,url. داخل sections استخدم قيمًا منطقية للحقول subjects,curriculum,library,about,join. لا تضف مفاتيح غير لازمة ولا تنشئ روابط وهمية.' : 'أنت مساعد إدارة لمنصة ZM Academy. اقترح خطوات واضحة ولا تنفذ عمليات مدمرة بدون تأكيد.';
      try {
        const resp = await fetch(endpoint, {method:'POST', headers:{'Content-Type':'application/json','Authorization':`Bearer ${key}`}, body: JSON.stringify({model, messages:[{role:'system',content:sys},{role:'user',content:prompt}], temperature:0.4})});
        const data = await resp.json();
        const text = data?.choices?.[0]?.message?.content || data?.output_text || '';
        await env.DB.prepare(`INSERT INTO ai_logs(actor_type,actor_id,tool,prompt_preview,response_status) VALUES(?,?,?,?,?)`).bind('admin',admin.id,mode,prompt.slice(0,200),resp.ok?'ok':'error').run();
        return reply(request, env, {success:resp.ok, text, raw: resp.ok?undefined:data}, resp.ok?200:502);
      } catch(e) {
        return reply(request, env, {success:false,error:'AI request failed'}, 502);
      }
    }

    // Roles & admin users
    if (path==='/api/admin/platform/roles') {
      if (!hasPerm(admin.role,'roles') && !hasPerm(admin.role,'settings')) return reply(request, env,{success:false,error:'Forbidden'},403);
      if (method==='GET') {
        const roles = await env.DB.prepare(`SELECT r.*, (SELECT COUNT(*) FROM role_permissions rp WHERE rp.role_id=r.id) as perm_count FROM roles r ORDER BY r.id ASC`).all();
        const admins = await env.DB.prepare(`SELECT id,username,display_name,email,role,is_active,created_at,last_login_at FROM admin_users ORDER BY id DESC LIMIT 200`).all();
        const permissionsMap={...ADMIN_PERMS};
        if(admin.role!=='super_admin') delete permissionsMap.super_admin;
        return reply(request, env,{success:true, roles: roles.results||[], admins: admins.results||[], permissions_map: permissionsMap,current_role:admin.role,current_admin_id:admin.id});
      }
    }
    if (path==='/api/admin/platform/admin-users') {
      if (!hasPerm(admin.role,'roles')) return reply(request, env,{success:false,error:'Forbidden'},403);
      if (method==='GET') {
        const admins = await env.DB.prepare(`SELECT id,username,display_name,email,role,is_active,created_at,last_login_at FROM admin_users ORDER BY id DESC LIMIT 200`).all();
        return reply(request, env,{success:true, admins: admins.results||[]});
      }
      if (method==='POST') {
        const b=await readBody(request);
        const username=clean(b?.username,60); const password=String(b?.password||''); const role=clean(b?.role||'admin',40);
        const display_name=clean(b?.display_name,120); const email=clean(b?.email,120).toLowerCase();
        if(!/^[A-Za-z0-9_.-]{3,60}$/.test(username) || password.length<12) return reply(request, env,{success:false,error:'اسم مستخدم/كلمة مرور غير صالحة (كلمة المرور 12+)'},400);
        if(!ADMIN_PERMS[role]) return reply(request, env,{success:false,error:'دور غير صالح'},400);
        if(role==='super_admin' && admin.role!=='super_admin') return reply(request,env,{success:false,error:'لا يمكن منح صلاحية المدير الأعلى إلا للمدير الأعلى'},403);
        const exists = await env.DB.prepare(`SELECT id FROM admin_users WHERE username=?`).bind(username).first();
        if (exists) return reply(request, env,{success:false,error:'اسم المستخدم موجود'},409);
        const hash = await passwordHash(password);
        await env.DB.prepare(`INSERT INTO admin_users (username,password_hash,display_name,email,role,is_active,created_at) VALUES (?,?,?,?,?,?,datetime('now'))`).bind(username,hash,display_name,email,role,1).run();
        await logAudit(env,{actor_type:'admin',actor_id:admin.id,actor_label:admin.username,action:'admin.create',entity_type:'admin_user',entity_id:username,details_json:{role},ip,user_agent:ua});
        return reply(request, env,{success:true});
      }
    }
    if (/^\/api\/admin\/platform\/admin-users\/\d+$/.test(path)) {
      if (!hasPerm(admin.role,'roles')) return reply(request, env,{success:false,error:'Forbidden'},403);
      const uid = Number(path.split('/').pop());
      if (method==='PUT') {
        const targetAdmin=await env.DB.prepare(`SELECT role FROM admin_users WHERE id=?`).bind(uid).first();
        if(!targetAdmin) return reply(request,env,{success:false,error:'المستخدم الإداري غير موجود'},404);
        if(targetAdmin.role==='super_admin' && admin.role!=='super_admin') return reply(request,env,{success:false,error:'لا يمكن تعديل حساب مدير أعلى إلا بواسطة مدير أعلى'},403);
        const b=await readBody(request);
        if (b.role!==undefined) { const role=clean(b.role,40); if(!ADMIN_PERMS[role]) return reply(request, env,{success:false,error:'Invalid role'},400); const target=await env.DB.prepare(`SELECT role FROM admin_users WHERE id=?`).bind(uid).first(); if(target?.role==='super_admin' && admin.role!=='super_admin') return reply(request,env,{success:false,error:'لا يمكن تعديل دور مدير أعلى إلا بواسطة مدير أعلى'},403); if(role==='super_admin' && admin.role!=='super_admin') return reply(request,env,{success:false,error:'لا يمكن منح صلاحية المدير الأعلى إلا للمدير الأعلى'},403); if(uid===admin.id && role!==admin.role) return reply(request,env,{success:false,error:'لا يمكنك تغيير دور حسابك الحالي'},403); await env.DB.prepare(`UPDATE admin_users SET role=? WHERE id=?`).bind(role,uid).run(); }
        if (b.is_active!==undefined) {
          if (!b.is_active && uid===admin.id) return reply(request,env,{success:false,error:'لا يمكنك إيقاف حسابك الحالي'},403);
          if (!b.is_active) {
            const target=await env.DB.prepare(`SELECT role FROM admin_users WHERE id=?`).bind(uid).first();
            if (target?.role==='super_admin') {
              if (admin.role!=='super_admin') return reply(request,env,{success:false,error:'لا يمكن إيقاف حساب مدير أعلى إلا بواسطة مدير أعلى'},403);
              const count=await env.DB.prepare(`SELECT COUNT(*) AS c FROM admin_users WHERE role='super_admin' AND is_active=1`).first();
              if (Number(count?.c||0)<=1) return reply(request,env,{success:false,error:'يجب أن يظل هناك مدير أعلى نشط واحد على الأقل'},409);
            }
          }
          await env.DB.prepare(`UPDATE admin_users SET is_active=? WHERE id=?`).bind(b.is_active?1:0,uid).run();
        }
        if (b.display_name!==undefined) { await env.DB.prepare(`UPDATE admin_users SET display_name=? WHERE id=?`).bind(clean(b.display_name,120),uid).run(); }
        if (b.email!==undefined) { await env.DB.prepare(`UPDATE admin_users SET email=? WHERE id=?`).bind(clean(b.email,120).toLowerCase(),uid).run(); }
        if (b.password) { const pw=String(b.password); if(pw.length<12) return reply(request, env,{success:false,error:'كلمة المرور 12+ حرف'},400); const hash=await passwordHash(pw); await env.DB.prepare(`UPDATE admin_users SET password_hash=? WHERE id=?`).bind(hash,uid).run(); }
        await logAudit(env,{actor_type:'admin',actor_id:admin.id,actor_label:admin.username,action:'admin.update',entity_type:'admin_user',entity_id:uid,details_json:{keys:Object.keys(b||{})},ip,user_agent:ua});
        return reply(request, env,{success:true});
      }
    }
    if (/^\/api\/admin\/platform\/admin-users\/\d+\/role$/.test(path)) {
      if (!hasPerm(admin.role,'roles')) return reply(request, env,{success:false,error:'Forbidden'},403);
      const uid = Number(path.split('/')[5]);
      if (method==='PUT') {
        const b=await readBody(request); const role=clean(b?.role,40);
        if(!ADMIN_PERMS[role]) return reply(request, env,{success:false,error:'Invalid role'},400);
        const target=await env.DB.prepare(`SELECT role FROM admin_users WHERE id=?`).bind(uid).first();
        if(target?.role==='super_admin' && admin.role!=='super_admin') return reply(request,env,{success:false,error:'لا يمكن تعديل دور مدير أعلى إلا بواسطة مدير أعلى'},403);
        if(role==='super_admin' && admin.role!=='super_admin') return reply(request,env,{success:false,error:'لا يمكن منح صلاحية المدير الأعلى إلا للمدير الأعلى'},403);
        if(uid===admin.id && role!==admin.role) return reply(request,env,{success:false,error:'لا يمكنك تغيير دور حسابك الحالي'},403);
        await env.DB.prepare(`UPDATE admin_users SET role=? WHERE id=?`).bind(role,uid).run();
        await logAudit(env,{actor_type:'admin',actor_id:admin.id,actor_label:admin.username,action:'admin.role.update',entity_type:'admin_user',entity_id:uid,details_json:{role},ip,user_agent:ua});
        return reply(request, env,{success:true});
      }
    }

    // Backup export (JSON)
    if (method==='GET' && path==='/api/admin/platform/backup/export') {
      if (!hasPerm(admin.role,'backups')) return reply(request, env,{success:false,error:'Forbidden'},403);
      const tables=[
        'students','subjects','materials','orders',
        'student_preferences','student_material_progress','student_favorites',
        'student_activity_days','student_hidden_purchases','student_photos',
        'archived_subjects','archived_materials',
        'platform_settings','roles','role_permissions','page_drafts',
        'page_published','page_versions','parents','parent_student_links',
        'notifications','notification_reads','ads','ad_events','exams',
        'exam_questions','exam_attempts','audit_logs','ai_logs'
      ];
      const out={version:2,exported_at:nowIso(),tables:{},warnings:[]};
      const sensitiveColumn=/password|token|secret|credential|api[_-]?key/i;
      for (const t of tables) {
        try {
          const r=await env.DB.prepare(`SELECT * FROM ${t} ORDER BY 1 DESC LIMIT 5000`).all();
          out.tables[t]=(r.results||[]).map(row=>Object.fromEntries(
            Object.entries(row).filter(([key])=>!sensitiveColumn.test(key))
          ));
        } catch {
          out.tables[t]=[];
          out.warnings.push(`Table unavailable in this installation: ${t}`);
        }
      }
      await env.DB.prepare(`INSERT INTO backup_runs(type,status,details_json,created_by) VALUES('export','success',?,?)`)
        .bind(JSON.stringify({version:out.version,tables:Object.keys(out.tables),warnings:out.warnings.length}),admin.username).run();
      return reply(request, env,{success:true,backup:out});
    }

    // Analytics CSV
    if (method==='GET' && path==='/api/admin/platform/analytics/export.csv') {
      if (!hasPerm(admin.role,'analytics')) return reply(request, env,{success:false,error:'Forbidden'},403);
      const rows = await env.DB.prepare(`SELECT date(created_at) as day, COUNT(*) as orders, SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed FROM orders GROUP BY date(created_at) ORDER BY day DESC LIMIT 90`).all().catch(()=>({results:[]}));
      const header='day,orders,completed\n';
      const body=(rows.results||[]).map(r=>`${r.day||''},${r.orders||0},${r.completed||0}`).join('\n');
      return new Response(header+body, {status:200, headers:{...corsHeaders(request,env),'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="analytics.csv"'}});
    }
    // Student progress CSV
    if (method==='GET' && path==='/api/admin/platform/progress/export.csv') {
      if (!hasPerm(admin.role,'analytics') && !hasPerm(admin.role,'students')) return reply(request, env,{success:false,error:'Forbidden'},403);
      await ensureStudentLearningTables(env);
      const rows = await env.DB.prepare(`
        SELECT s.id as student_id, s.name as student_name, s.grade, m.title as material_title, p.last_page, p.completed_at, p.updated_at
        FROM student_material_progress p
        JOIN students s ON s.id=p.student_id
        JOIN materials m ON m.id=p.material_id
        ORDER BY p.updated_at DESC LIMIT 1000
      `).all().catch(()=>({results:[]}));
      const esc=(v)=>'"'+String(v??'').replace(/"/g,'""')+'"';
      const header='student_id,student_name,grade,material_title,last_page,completed_at,updated_at\n';
      const body=(rows.results||[]).map(r=>[r.student_id,r.student_name,r.grade,r.material_title,r.last_page,r.completed_at,r.updated_at].map(esc).join(',')).join('\n');
      return new Response(header+body, {status:200, headers:{...corsHeaders(request,env),'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="student-progress.csv"'}});
    }
    // Student progress (admin view)
    if (method==='GET' && path==='/api/admin/platform/progress') {
      if (!hasPerm(admin.role,'analytics') && !hasPerm(admin.role,'students')) return reply(request, env,{success:false,error:'Forbidden'},403);
      await ensureStudentLearningTables(env);
      const rows = await env.DB.prepare(`
        SELECT s.id as student_id, s.name as student_name, s.grade, m.title as material_title, p.last_page, p.completed_at, p.updated_at
        FROM student_material_progress p
        JOIN students s ON s.id=p.student_id
        JOIN materials m ON m.id=p.material_id
        ORDER BY p.updated_at DESC LIMIT 200
      `).all().catch(()=>({results:[]}));
      return reply(request, env, {success:true, rows: rows.results||[]});
    }

    // Media library (GitHub storage)
    if (path==='/api/admin/platform/media') {
      if (!hasPerm(admin.role,'media')) return reply(request, env,{success:false,error:'Forbidden'},403);
      if (method==='GET') {
        if (!env.GITHUB_STORAGE_TOKEN) return reply(request, env,{success:false,error:'Storage not configured'},503);
        const prefix = clean(url.searchParams.get('prefix')||'media', 120);
        try {
          const r = await fetch(githubContentsUrl(prefix), {headers: githubHeaders(env)});
          if (!r.ok) return reply(request, env,{success:true, items:[]});
          const items = await r.json();
          const list = Array.isArray(items)?items.filter(i=>i.type==='file').map(i=>({name:i.name,path:i.path,size:i.size,download_url:`/api/media/${i.path}`})):[];
          return reply(request, env,{success:true, items:list});
        } catch(e){ return reply(request, env,{success:false,error:'Failed to list media'},500); }
      }
    }
    if (method==='DELETE' && /^\/api\/admin\/platform\/media\/.+/.test(path)) {
      if (!hasPerm(admin.role,'media')) return reply(request, env,{success:false,error:'Forbidden'},403);
      const fileKey = decodeURIComponent(path.replace('/api/admin/platform/media/',''));
      if (!fileKey.startsWith('media/') || fileKey.includes('..')) return reply(request, env,{success:false,error:'Invalid path'},400);
      try { await deleteFromGitHub(env, fileKey); await logAudit(env,{actor_type:'admin',actor_id:admin.id,actor_label:admin.username,action:'media.delete',entity_type:'media',entity_id:fileKey,ip,user_agent:ua}); return reply(request, env,{success:true}); }
      catch(e){ return reply(request, env,{success:false,error:'Delete failed'},500); }
    }

    return reply(request, env, {success:false,error:'Not found'}, 404);
  }

  // ---- Student exams/notifications/AI ----
  if (path.startsWith('/api/student/platform/')) {
    const session = await studentSession(request, env);
    if (!session) return reply(request, env, {success:false,error:'Unauthorized'}, 401);
    const studentPathParts=path.split('/');
    const isExamResumeRoute=studentPathParts.length===6&&studentPathParts[4]==='exam-attempts'&&/^\\d+$/.test(studentPathParts[5]);
    const isExamStartRoute=studentPathParts.length===7&&studentPathParts[4]==='exams'&&studentPathParts[6]==='start'&&/^\\d+$/.test(studentPathParts[5]);
    if (isExamResumeRoute||isExamStartRoute) await ensureColumn(env,'exam_attempts','question_order_json','TEXT');
    if (method==='GET' && path==='/api/student/platform/notifications') {
      // Only show broadcasts and notifications explicitly addressed to this student or their grade.
      // Previously, every student could see every notification marked "student".
      const rows = await env.DB.prepare(`
        SELECT n.*,
               CASE WHEN r.id IS NULL THEN 0 ELSE 1 END AS is_read
        FROM notifications n
        LEFT JOIN notification_reads r
          ON r.notification_id=n.id
         AND r.user_type='student'
         AND r.user_id=?
        WHERE (n.audience_type='all'
           OR (n.audience_type='student' AND n.audience_value=CAST(? AS TEXT))
           OR (n.audience_type='grade' AND EXISTS (
                SELECT 1 FROM students s
                WHERE s.id=? AND s.grade=n.audience_value
           )))
          AND (n.scheduled_at IS NULL OR datetime(n.scheduled_at)<=datetime('now'))
        ORDER BY n.id DESC
        LIMIT 100
      `).bind(session.student_id, session.student_id, session.student_id).all();
      return reply(request, env, {success:true, notifications: rows.results||[]});
    }
    if (method==='POST' && /^\/api\/student\/platform\/notifications\/\d+\/read$/.test(path)) {
      const nid = Number(path.split('/')[5]);
      await env.DB.prepare(`INSERT OR IGNORE INTO notification_reads(notification_id,user_type,user_id) VALUES(?, 'student', ?)`).bind(nid, session.student_id).run();
      return reply(request, env, {success:true});
    }
    if (method==='GET' && path==='/api/student/platform/exams') {
      const rows = await env.DB.prepare(`SELECT e.id,e.title,e.description,e.subject_id,e.grade,e.duration_minutes,e.attempts_allowed,e.starts_at,e.ends_at,e.show_results,(SELECT COUNT(*) FROM exam_attempts a WHERE a.exam_id=e.id AND a.student_id=?) as my_attempts,(SELECT a.id FROM exam_attempts a WHERE a.exam_id=e.id AND a.student_id=? AND a.status='in_progress' ORDER BY a.id DESC LIMIT 1) as active_attempt_id,(SELECT a.id FROM exam_attempts a WHERE a.exam_id=e.id AND a.student_id=? ORDER BY a.id DESC LIMIT 1) as last_attempt_id,(SELECT a.status FROM exam_attempts a WHERE a.exam_id=e.id AND a.student_id=? ORDER BY a.id DESC LIMIT 1) as last_attempt_status FROM exams e WHERE e.status='published' AND (COALESCE(TRIM(e.grade),'')='' OR e.grade=(SELECT s.grade FROM students s WHERE s.id=?)) AND (e.starts_at IS NULL OR datetime(e.starts_at)<=datetime('now')) AND (e.ends_at IS NULL OR datetime(e.ends_at)>=datetime('now')) ORDER BY e.id DESC LIMIT 100`).bind(session.student_id, session.student_id, session.student_id, session.student_id, session.student_id).all();
      return reply(request, env, {success:true, exams: rows.results||[]});
    }
            if (method==='PUT' && /^\/api\/student\/platform\/exam-attempts\/\d+\/answers$/.test(path)) {
      const attemptId=Number(path.split('/')[5]);
      const attempt=await env.DB.prepare(`SELECT a.id,a.exam_id,CASE WHEN e.duration_minutes>0 AND datetime(a.started_at,'+' || e.duration_minutes || ' minutes')<=datetime('now') THEN 1 ELSE 0 END AS is_expired FROM exam_attempts a JOIN exams e ON e.id=a.exam_id WHERE a.id=? AND a.student_id=? AND a.status='in_progress'`).bind(attemptId,session.student_id).first();
      if(!attempt) return reply(request,env,{success:false,error:'المحاولة غير متاحة'},404);
      if (!(await consumeApiRateLimit(env,request,'exam-autosave',attemptId,120,60))) return reply(request,env,{success:false,error:'طلبات حفظ كثيرة جدًا. انتظر دقيقة ثم حاول مرة أخرى.'},429);
      if(Number(attempt.is_expired)===1) {
        await env.DB.prepare(`UPDATE exam_attempts SET status='expired',submitted_at=datetime('now') WHERE id=? AND student_id=? AND status='in_progress'`).bind(attemptId,session.student_id).run();
        return reply(request,env,{success:false,error:'انتهى وقت الاختبار'},410);
      }
      const body=await readBody(request); const incoming=body?.answers;
      if(!incoming || typeof incoming!=='object' || Array.isArray(incoming)) return reply(request,env,{success:false,error:'الإجابات غير صالحة'},400);
      const questionRows=await env.DB.prepare(`SELECT id FROM exam_questions WHERE exam_id=?`).bind(attempt.exam_id).all();
      const allowed=new Set((questionRows.results||[]).map(q=>String(q.id)));
      const answers={};
      for(const [key,value] of Object.entries(incoming)) {
        if(!allowed.has(String(key))) continue;
        if(typeof value==='string') answers[key]=value.slice(0,5000);
        else if(typeof value==='boolean' || typeof value==='number') answers[key]=value;
        else if(value && typeof value==='object') answers[key]=value;
      }
      if(JSON.stringify(answers).length>30000) return reply(request,env,{success:false,error:'حجم الإجابات أكبر من المسموح'},413);
      await env.DB.prepare(`UPDATE exam_attempts SET answers_json=? WHERE id=? AND student_id=? AND status='in_progress'`).bind(JSON.stringify(answers),attemptId,session.student_id).run();
      return reply(request,env,{success:true,saved:true});
    }
if (method==='GET' && /^\/api\/student\/platform\/exam-attempts\/\d+$/.test(path)) {
      const attemptId=Number(path.split('/').pop());
      const attempt=await env.DB.prepare(`SELECT a.id AS attempt_id,a.exam_id,a.started_at,a.status,a.answers_json,a.question_order_json,e.title,e.description,e.duration_minutes,e.attempts_allowed,e.shuffle_questions,e.show_results,CASE WHEN e.duration_minutes>0 AND datetime(a.started_at,'+' || e.duration_minutes || ' minutes')<=datetime('now') THEN 1 ELSE 0 END AS is_expired FROM exam_attempts a JOIN exams e ON e.id=a.exam_id WHERE a.id=? AND a.student_id=? AND a.status='in_progress'`).bind(attemptId,session.student_id).first();
      if(!attempt) return reply(request,env,{success:false,error:'المحاولة المفتوحة غير موجودة'},404);
      if(Number(attempt.is_expired)===1) {
        await env.DB.prepare(`UPDATE exam_attempts SET status='expired',submitted_at=datetime('now') WHERE id=? AND student_id=? AND status='in_progress'`).bind(attemptId,session.student_id).run();
        return reply(request,env,{success:false,error:'انتهى وقت الاختبار. لا يمكن استكمال هذه المحاولة.'},410);
      }
      const qs=await env.DB.prepare(`SELECT id,type,question_text,options_json,points,order_index FROM exam_questions WHERE exam_id=? ORDER BY order_index ASC,id ASC`).bind(attempt.exam_id).all();
      const questionRows=qs.results||[]; const byId=new Map(questionRows.map(q=>[Number(q.id),q]));
      const savedOrder=safeJsonParse(attempt.question_order_json,[]);
      const orderedQuestions=Array.isArray(savedOrder)&&savedOrder.length?[...savedOrder.map(id=>byId.get(Number(id))).filter(Boolean),...questionRows.filter(q=>!savedOrder.includes(q.id))]:questionRows;
      return reply(request,env,{success:true,attempt_id:attempt.attempt_id,exam:attempt,answers:safeJsonParse(attempt.answers_json,{}),questions:orderedQuestions.map(q=>({...q,options:safeJsonParse(q.options_json,[])}))});
    }
if (method==='POST' && /^\/api\/student\/platform\/exams\/\d+\/start$/.test(path)) {
      const examId = Number(path.split('/')[5]);
      const exam = await env.DB.prepare(`SELECT * FROM exams WHERE id=? AND status='published' AND (COALESCE(TRIM(grade),'')='' OR grade=(SELECT s.grade FROM students s WHERE s.id=?)) AND (starts_at IS NULL OR datetime(starts_at)<=datetime('now')) AND (ends_at IS NULL OR datetime(ends_at)>=datetime('now'))`).bind(examId, session.student_id).first();
      if (!exam) return reply(request, env, {success:false,error:'الاختبار غير متاح لهذا الطالب أو خارج موعده'},404);
      // Close expired attempts before checking whether the student already has an open attempt.
      await env.DB.prepare(`UPDATE exam_attempts SET status='expired', submitted_at=datetime('now') WHERE exam_id=? AND student_id=? AND status='in_progress' AND EXISTS (SELECT 1 FROM exams e WHERE e.id=exam_attempts.exam_id AND e.duration_minutes>0 AND datetime(exam_attempts.started_at, '+' || e.duration_minutes || ' minutes')<=datetime('now'))`).bind(examId, session.student_id).run();
      const activeAttempt = await env.DB.prepare(`SELECT id FROM exam_attempts WHERE exam_id=? AND student_id=? AND status='in_progress' ORDER BY id DESC LIMIT 1`).bind(examId, session.student_id).first();
      if (activeAttempt) return reply(request, env, {success:false,error:'لديك محاولة مفتوحة بالفعل. أكملها قبل بدء محاولة أخرى.'},409);
      const attempts = await env.DB.prepare(`SELECT COUNT(*) c FROM exam_attempts WHERE exam_id=? AND student_id=?`).bind(examId, session.student_id).first();
      if ((attempts?.c||0) >= Number(exam.attempts_allowed||1)) return reply(request, env, {success:false,error:'لا توجد محاولات متبقية'},400);
      const qs = await env.DB.prepare(`SELECT id,type,question_text,options_json,points,order_index FROM exam_questions WHERE exam_id=? ORDER BY order_index ASC, id ASC`).bind(examId).all();
      const questions = [...(qs.results||[])];
      if (!questions.length) return reply(request, env, {success:false,error:'الاختبار لا يحتوي على أسئلة بعد'},400);
      const maxScore = questions.reduce((sum,q)=>sum+Number(q.points||1),0);
      // Shuffle only the presentation order for this attempt; question IDs remain stable for answer grading.
      if (Number(exam.shuffle_questions) === 1) {
        for (let i=questions.length-1;i>0;i--) {
          const j=Math.floor(Math.random()*(i+1));
          [questions[i],questions[j]]=[questions[j],questions[i]];
        }
      }
      const res = await env.DB.prepare(`INSERT INTO exam_attempts(exam_id,student_id,status,answers_json,max_score,question_order_json) VALUES(?, ?, 'in_progress','{}',?,?)`).bind(examId, session.student_id, maxScore, JSON.stringify(questions.map(q=>q.id))).run();
      const started=await env.DB.prepare(`SELECT started_at FROM exam_attempts WHERE id=? AND student_id=?`).bind(res.meta?.last_row_id,session.student_id).first();
      return reply(request, env, {success:true, attempt_id: res.meta?.last_row_id, started_at:started?.started_at||null, exam, questions:questions.map(q=>({...q, options:safeJsonParse(q.options_json,[])}))});
    }
    if (method==='POST' && /^\/api\/student\/platform\/exam-attempts\/\d+\/submit$/.test(path)) {
      const attemptId = Number(path.split('/')[5]);
      const attempt = await env.DB.prepare(`SELECT a.*, e.show_results, e.duration_minutes, CASE WHEN e.duration_minutes>0 AND datetime(a.started_at, '+' || e.duration_minutes || ' minutes')<=datetime('now') THEN 1 ELSE 0 END AS is_expired FROM exam_attempts a JOIN exams e ON e.id=a.exam_id WHERE a.id=? AND a.student_id=?`).bind(attemptId, session.student_id).first();
      if (!attempt || attempt.status!=='in_progress') return reply(request, env, {success:false,error:'Attempt not available'},400);
      if (Number(attempt.is_expired)===1) {
        await env.DB.prepare(`UPDATE exam_attempts SET status='expired', submitted_at=datetime('now') WHERE id=? AND student_id=? AND status='in_progress'`).bind(attemptId, session.student_id).run();
        return reply(request, env, {success:false,error:'انتهى الوقت المحدد للاختبار. تم إغلاق المحاولة.'}, 400);
      }
      const b = await readBody(request);
      const answers = b?.answers && typeof b.answers==='object' ? b.answers : {};
      const qs = await env.DB.prepare(`SELECT * FROM exam_questions WHERE exam_id=?`).bind(attempt.exam_id).all();
      let score=0, max=0, needsManual=false;
      for (const q of (qs.results||[])) {
        max += Number(q.points||1);
        const ans = answers[q.id];
        if (q.type==='essay') { needsManual=true; continue; }
        const correct = safeJsonParse(q.correct_answer_json, null);
        if (JSON.stringify(ans) === JSON.stringify(correct)) score += Number(q.points||1);
      }
      const status = needsManual ? 'submitted' : 'graded';
      await env.DB.prepare(`UPDATE exam_attempts SET submitted_at=datetime('now'), answers_json=?, score=?, max_score=?, status=?, graded_at=CASE WHEN ?='graded' THEN datetime('now') ELSE NULL END WHERE id=?`)
        .bind(JSON.stringify(answers), score, max, status, status, attemptId).run();
      const showResults = Number(attempt.show_results) !== 0;
      return reply(request, env, {success:true, score:showResults&&!needsManual?score:null, max_score:showResults?max:null, status, results_hidden:!showResults, results_pending_manual:needsManual});
    }
    if (method==='GET' && /^\/api\/student\/platform\/exam-attempts\/\d+\/result$/.test(path)) {
      const attemptId=Number(path.split('/')[5]);
      const attempt=await env.DB.prepare(`SELECT a.id,a.exam_id,a.status,a.score,a.max_score,a.feedback_json,e.show_results FROM exam_attempts a JOIN exams e ON e.id=a.exam_id WHERE a.id=? AND a.student_id=?`).bind(attemptId,session.student_id).first();
      if(!attempt) return reply(request, env,{success:false,error:'المحاولة غير موجودة'},404);
      const showResults=Number(attempt.show_results)!==0;
      let feedback=[];
      if(showResults&&attempt.status==='graded') {
        const questions=await env.DB.prepare(`SELECT id,question_text FROM exam_questions WHERE exam_id=? AND type='essay' ORDER BY order_index ASC,id ASC`).bind(attempt.exam_id).all();
        const saved=safeJsonParse(attempt.feedback_json,{});
        feedback=(questions.results||[]).map(q=>({question_id:q.id,question_text:q.question_text,comment:saved[q.id]||''}));
      }
      return reply(request,env,{success:true,status:attempt.status,score:showResults&&attempt.status==='graded'?attempt.score:null,max_score:showResults&&attempt.status==='graded'?attempt.max_score:null,feedback,results_hidden:!showResults,results_pending_manual:attempt.status==='submitted'});
    }
    if (method==='POST' && path==='/api/student/platform/ai') {
      const b = await readBody(request); const prompt = clean(b?.prompt,4000);
      if(!prompt) return reply(request, env,{success:false,error:'prompt required'},400);
      if (!(await consumeApiRateLimit(env,request,'student_ai',session.student_id,10,60))) return reply(request, env,{success:false,error:'تم تجاوز الحد المؤقت لطلبات المساعد. حاول بعد دقيقة.',code:'RATE_LIMITED'},429);
      const key = env.AI_API_KEY || env.OPENAI_API_KEY || '';
      if (!key) return reply(request, env, {success:false,error:'AI service not configured', code:'AI_NOT_CONFIGURED'}, 503);
      const endpoint = env.AI_API_URL || 'https://api.openai.com/v1/chat/completions';
      const model = env.AI_MODEL || 'gpt-4o-mini';
      try {
        const resp = await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${key}`},body:JSON.stringify({model,messages:[{role:'system',content:'أنت مساعد تعليمي لطلاب ZM Academy. اشرح بوضوح وبساطة، ولا تكشف بيانات طلاب آخرين أو أدوات الإدارة.'},{role:'user',content:prompt}],temperature:0.5})});
        const data = await resp.json(); const text = data?.choices?.[0]?.message?.content||'';
        await env.DB.prepare(`INSERT INTO ai_logs(actor_type,actor_id,tool,prompt_preview,response_status) VALUES('student',?, 'student_assistant', ?, ?)`).bind(session.student_id,prompt.slice(0,200),resp.ok?'ok':'error').run();
        return reply(request, env, {success:resp.ok, text}, resp.ok?200:502);
      } catch { return reply(request, env, {success:false,error:'AI request failed'},502); }
    }
    return reply(request, env, {success:false,error:'Not found'},404);
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
      const url = new URL(request.url);
      const requestId = crypto.randomUUID();
      console.error("Worker Error:", {
        requestId,
        method: request.method,
        path: url.pathname,
        message: error?.message || String(error),
        stack: error?.stack || null
      });

      return reply(
        request,
        env,
        {
          success: false,
          error: "Internal server error.",
          request_id: requestId
        },
        500
      );
    }
  },
};
