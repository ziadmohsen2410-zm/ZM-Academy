
const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 210000;

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
    .split(",").map(x => x.trim()).filter(Boolean);
  const allowOrigin =
    allowed.includes("*") || allowed.includes(origin)
      ? (allowed.includes("*") ? "*" : origin)
      : "";

  return {
    ...(allowOrigin ? {
      "access-control-allow-origin": allowOrigin,
      "vary": "Origin"
    } : {}),
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
  return typeof value === "string"
    ? value.trim().slice(0, max)
    : "";
}

function randomToken(bytes = 32) {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64Url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
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
      iterations: PBKDF2_ITERATIONS
    },
    key,
    256
  );

  return `pbkdf2$${PBKDF2_ITERATIONS}$${toBase64Url(salt)}$${toBase64Url(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  try {
    const parts = String(stored || "").split("$");

    if (parts.length !== 4 || parts[0] !== "pbkdf2") {
      return false;
    }

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

    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations
      },
      key,
      expected.length * 8
    ));

    if (bits.length !== expected.length) {
      return false;
    }

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
  return value.startsWith("Bearer ")
    ? value.slice(7).trim()
    : "";
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
  ).bind(tokenHash).first();

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
     WHERE ss.token_hash = ?
     AND ss.expires_at > datetime('now')`
  ).bind(tokenHash).first();

  return row ? { ...row, tokenHash } : null;
}

async function route(request, env) {
  if (!env.DB) {
    return reply(request, env, {
      success: false,
      error: "Database binding DB is missing."
    }, 500);
  }

  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders(request, env)
    });
  }

  // فحص اتصال قاعدة البيانات
  if (method === "GET" && path === "/api/health") {
    try {
      await env.DB.prepare("SELECT 1").first();

      return reply(request, env, {
        success: true,
        database: "connected"
      });
    } catch {
      return reply(request, env, {
        success: false,
        database: "error"
      }, 500);
    }
  }

  // إنشاء حساب الإدارة لأول مرة
  if (method === "POST" && path === "/api/admin/setup") {
    if (!env.ADMIN_SETUP_KEY) {
      return reply(request, env, {
        success: false,
        error: "Admin setup is not configured."
      }, 503);
    }

    const body = await readBody(request);

    if (!body || clean(body.setupKey, 300) !== env.ADMIN_SETUP_KEY) {
      return reply(request, env, {
        success: false,
        error: "Invalid setup key."
      }, 403);
    }

    const username = clean(body.username, 60);
    const password = typeof body.password === "string"
      ? body.password
      : "";

    if (
      !/^[A-Za-z0-9_.-]{3,60}$/.test(username) ||
      password.length < 12 ||
      password.length > 200
    ) {
      return reply(request, env, {
        success: false,
        error: "Username must be 3-60 characters; password must be at least 12 characters."
      }, 400);
    }

    const count = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM admin_users"
    ).first();

    if ((count?.n || 0) > 0) {
      return reply(request, env, {
        success: false,
        error: "An admin already exists. Setup is closed."
      }, 409);
    }

    const hash = await passwordHash(password);

    try {
      await env.DB.prepare(
        "INSERT INTO admin_users (username, password_hash) VALUES (?, ?)"
      ).bind(username, hash).run();

      return reply(request, env, {
        success: true,
        message: "Admin account created. You can now sign in."
      }, 201);
    } catch {
      return reply(request, env, {
        success: false,
        error: "Could not create admin account."
      }, 500);
    }
  }

  // تسجيل دخول الإدارة
  if (method === "POST" && path === "/api/admin/login") {
    const body = await readBody(request);
    const username = clean(body?.username, 60);
    const password = typeof body?.password === "string"
      ? body.password
      : "";

    if (!username || !password) {
      return reply(request, env, {
        success: false,
        error: "Username and password are required."
      }, 400);
    }

    const admin = await env.DB.prepare(
      "SELECT id, username, password_hash FROM admin_users WHERE username = ?"
    ).bind(username).first();

    if (!admin || !(await verifyPassword(password, admin.password_hash))) {
      return reply(request, env, {
        success: false,
        error: "Invalid username or password."
      }, 401);
    }

    const token = randomToken();
    const tokenHash = await sha256(token);

    await env.DB.prepare(
      `INSERT INTO admin_sessions
       (token_hash, expires_at, admin_id)
       VALUES (?, datetime('now', ?), ?)`
    ).bind(tokenHash, `+${SESSION_DAYS} days`, admin.id).run();

    return reply(request, env, {
      success: true,
      token,
      expiresInDays: SESSION_DAYS,
      admin: {
        id: admin.id,
        username: admin.username
      }
    });
  }

  // تسجيل خروج الإدارة
  if (method === "POST" && path === "/api/admin/logout") {
    const session = await adminSession(request, env);

    if (session) {
      await env.DB.prepare(
        "DELETE FROM admin_sessions WHERE token_hash = ?"
      ).bind(session.tokenHash).run();
    }

    return reply(request, env, { success: true });
  }

  // جميع مسارات الإدارة محمية
  if (path.startsWith("/api/admin/") || path === "/api/admin/me") {
    const session = await requireAdmin(request, env);

    if (!session) {
      return reply(request, env, {
        success: false,
        error: "Unauthorized."
      }, 401);
    }

    if (method === "GET" && path === "/api/admin/me") {
      return reply(request, env, {
        success: true,
        admin: {
          id: session.admin_id,
          username: session.username
        }
      });
    }

    // الطلبات
    if (method === "GET" && path === "/api/admin/orders") {
      const rows = await env.DB.prepare(
        `SELECT o.id, o.status, o.created_at,
                s.name AS student_name, s.phone,
                m.title AS material_title, m.price
         FROM orders o
         JOIN students s ON s.id = o.student_id
         JOIN materials m ON m.id = o.material_id
         ORDER BY o.id DESC LIMIT 500`
      ).all();

      return reply(request, env, {
        success: true,
        orders: rows.results || []
      });
    }

    // تحديث حالة الطلب
    const orderStatus = path.match(/^\/api\/admin\/orders\/(\d+)$/);

    if (method === "PATCH" && orderStatus) {
      const body = await readBody(request);
      const status = clean(body?.status, 30);

      if (!["pending", "approved", "rejected", "completed"].includes(status)) {
        return reply(request, env, {
          success: false,
          error: "Invalid order status."
        }, 400);
      }

      const result = await env.DB.prepare(
        "UPDATE orders SET status = ? WHERE id = ?"
      ).bind(status, Number(orderStatus[1])).run();

      return reply(request, env, {
        success: true,
        changed: result.meta?.changes || 0
      });
    }

    // قائمة الطلاب بالتفاصيل الجديدة
    if (method === "GET" && path === "/api/admin/students") {
      const rows = await env.DB.prepare(
        `SELECT s.id, s.name, s.phone, s.parent_phone,
                s.grade, s.school, s.governorate,
                s.created_at, a.username,
                (SELECT GROUP_CONCAT(sub.name, '، ')
                 FROM student_subjects ss
                 JOIN subjects sub ON sub.id = ss.subject_id
                 WHERE ss.student_id = s.id) AS selected_subjects
         FROM students s
         LEFT JOIN student_accounts a ON a.student_id = s.id
         ORDER BY s.id DESC LIMIT 1000`
      ).all();

      return reply(request, env, {
        success: true,
        students: rows.results || []
      });
    }

    // حذف طالب مع الحفاظ على سجل الطلبات
    if (
      method === "DELETE" &&
      /^\/api\/admin\/students\/\d+$/.test(path)
    ) {
      const studentId = Number(path.split("/").pop());

      const student = await env.DB.prepare(
        "SELECT id FROM students WHERE id = ?"
      ).bind(studentId).first();

      if (!student) {
        return reply(request, env, {
          success: false,
          error: "الطالب غير موجود."
        }, 404);
      }

      const linkedOrders = await env.DB.prepare(
        "SELECT COUNT(*) AS n FROM orders WHERE student_id = ?"
      ).bind(studentId).first();

      if ((linkedOrders?.n || 0) > 0) {
        return reply(request, env, {
          success: false,
          error: "لا يمكن حذف الطالب لوجود طلبات مرتبطة به. احتفظ بسجل الطلبات."
        }, 409);
      }

      await env.DB.batch([
        env.DB.prepare(
          "DELETE FROM student_sessions WHERE student_id = ?"
        ).bind(studentId),

        env.DB.prepare(
          "DELETE FROM student_subjects WHERE student_id = ?"
        ).bind(studentId),

        env.DB.prepare(
          "DELETE FROM student_accounts WHERE student_id = ?"
        ).bind(studentId),

        env.DB.prepare(
          "DELETE FROM students WHERE id = ?"
        ).bind(studentId)
      ]);

      return reply(request, env, {
        success: true,
        deleted: studentId
      });
    }

    // المواد
    if (method === "GET" && path === "/api/admin/materials") {
      const rows = await env.DB.prepare(
        `SELECT id, subject_id, title, type, price, is_free
         FROM materials ORDER BY id DESC`
      ).all();

      return reply(request, env, {
        success: true,
        materials: rows.results || []
      });
    }

    // إضافة مادة دراسية
    if (method === "POST" && path === "/api/admin/subjects") {
      const body = await readBody(request);
      const name = clean(body?.name, 120);
      const grade = clean(body?.grade, 80);

      if (!name || !grade) {
        return reply(request, env, {
          success: false,
          error: "Subject name and grade are required."
        }, 400);
      }

      const result = await env.DB.prepare(
        "INSERT INTO subjects (name, grade) VALUES (?, ?)"
      ).bind(name, grade).run();

      return reply(request, env, {
        success: true,
        id: result.meta.last_row_id
      }, 201);
    }

    // إضافة محتوى دراسي
    if (method === "POST" && path === "/api/admin/materials") {
      const body = await readBody(request);
      const subjectId = Number(body?.subject_id);
      const title = clean(body?.title, 180);
      const type = clean(body?.type, 40);
      const price = Number(body?.price ?? 0);
      const isFree =
        body?.is_free === false || Number(body?.is_free) === 0
          ? 0
          : 1;

      if (
        !Number.isInteger(subjectId) ||
        subjectId < 1 ||
        !title ||
        !type ||
        !Number.isFinite(price) ||
        price < 0
      ) {
        return reply(request, env, {
          success: false,
          error: "Valid subject_id, title, type and non-negative price are required."
        }, 400);
      }

      const subject = await env.DB.prepare(
        "SELECT id FROM subjects WHERE id = ?"
      ).bind(subjectId).first();

      if (!subject) {
        return reply(request, env, {
          success: false,
          error: "Subject not found."
        }, 404);
      }

      const result = await env.DB.prepare(
        `INSERT INTO materials
         (subject_id, title, type, price, is_free, file_key)
         VALUES (?, ?, ?, ?, ?, ?)`
      ).bind(
        subjectId,
        title,
        type,
        price,
        isFree,
        clean(body?.file_key, 500) || null
      ).run();

      return reply(request, env, {
        success: true,
        id: result.meta.last_row_id
      }, 201);
    }

    return reply(request, env, {
      success: false,
      error: "Admin endpoint not found."
    }, 404);
  }

  // المواد والصفوف المتاحة للتسجيل
  if (method === "GET" && path === "/api/subjects") {
    const rows = await env.DB.prepare(
      "SELECT id, name, grade FROM subjects ORDER BY grade, name"
    ).all();

    return reply(request, env, {
      success: true,
      subjects: rows.results || []
    });
  }

  // المحتوى المجاني فقط
  if (method === "GET" && path === "/api/materials") {
    const subjectId = Number(url.searchParams.get("subject_id") || 0);

    const rows = subjectId
      ? await env.DB.prepare(
          `SELECT id, subject_id, title, type, price, is_free
           FROM materials
           WHERE subject_id = ? AND is_free = 1
           ORDER BY id DESC`
        ).bind(subjectId).all()
      : await env.DB.prepare(
          `SELECT id, subject_id, title, type, price, is_free
           FROM materials
           WHERE is_free = 1
           ORDER BY id DESC`
        ).all();

    return reply(request, env, {
      success: true,
      materials: rows.results || []
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

    const password = typeof body?.password === "string"
      ? body.password
      : "";

    const subjectIds = Array.isArray(body?.subjects)
      ? [...new Set(
          body.subjects
            .map(Number)
            .filter(x => Number.isInteger(x) && x > 0)
        )]
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
      return reply(request, env, {
        success: false,
        error: "تأكد من إدخال جميع البيانات بشكل صحيح، واختر مادة واحدة على الأقل. اسم المستخدم من 3 إلى 40 حرفًا إنجليزيًا أو رقمًا، وكلمة المرور 8 أحرف على الأقل."
      }, 400);
    }

    // منع تكرار رقم الطالب
    const existingPhone = await env.DB.prepare(
      "SELECT id FROM students WHERE phone = ?"
    ).bind(phone).first();

    if (existingPhone) {
      return reply(request, env, {
        success: false,
        error: "رقم الطالب مسجل بالفعل. تواصل مع الإدارة للمساعدة."
      }, 409);
    }

    // منع تكرار اسم المستخدم
    const existingUsername = await env.DB.prepare(
      "SELECT id FROM student_accounts WHERE username = ?"
    ).bind(username).first();

    if (existingUsername) {
      return reply(request, env, {
        success: false,
        error: "اسم المستخدم مستخدم بالفعل، اختر اسمًا آخر."
      }, 409);
    }

    // التأكد أن كل المواد تابعة للصف المختار
    const placeholders = subjectIds.map(() => "?").join(",");

    const validSubjects = await env.DB.prepare(
      `SELECT id FROM subjects
       WHERE grade = ?
       AND id IN (${placeholders})`
    ).bind(grade, ...subjectIds).all();

    if ((validSubjects.results || []).length !== subjectIds.length) {
      return reply(request, env, {
        success: false,
        error: "يوجد اختيار مادة غير تابع للصف الدراسي المحدد."
      }, 400);
    }

    let studentId = null;

    try {
      const studentResult = await env.DB.prepare(
        `INSERT INTO students
         (name, phone, parent_phone, grade, school, governorate)
         VALUES (?, ?, ?, ?, ?, ?)`
      ).bind(
        name,
        phone,
        parentPhone,
        grade,
        school,
        governorate
      ).run();

      studentId = studentResult.meta.last_row_id;

      const hash = await passwordHash(password);

      const statements = [
        env.DB.prepare(
          `INSERT INTO student_accounts
           (student_id, username, password_hash)
           VALUES (?, ?, ?)`
        ).bind(studentId, username, hash),

        ...subjectIds.map(subjectId =>
          env.DB.prepare(
            `INSERT INTO student_subjects
             (student_id, subject_id)
             VALUES (?, ?)`
          ).bind(studentId, subjectId)
        )
      ];

      await env.DB.batch(statements);

      return reply(request, env, {
        success: true,
        student_id: studentId,
        username,
        message: "تم إنشاء حسابك بنجاح."
      }, 201);

    } catch (error) {
      // تنظيف السجلات إذا فشل إنشاء الحساب
      if (studentId) {
        try {
          await env.DB.batch([
            env.DB.prepare(
              "DELETE FROM student_subjects WHERE student_id = ?"
            ).bind(studentId),

            env.DB.prepare(
              "DELETE FROM student_accounts WHERE student_id = ?"
            ).bind(studentId),

            env.DB.prepare(
              "DELETE FROM students WHERE id = ?"
            ).bind(studentId)
          ]);
        } catch {}
      }

      return reply(request, env, {
        success: false,
        error: "تعذر إنشاء الحساب. تأكد من البيانات وحاول مرة أخرى."
      }, 500);
    }
  }

  // تسجيل دخول الطالب
  if (method === "POST" && path === "/api/students/login") {
    const body = await readBody(request);

    const username = clean(body?.username, 40).toLowerCase();
    const password = typeof body?.password === "string"
      ? body.password
      : "";

    if (!username || !password) {
      return reply(request, env, {
        success: false,
        error: "أدخل اسم المستخدم وكلمة المرور."
      }, 400);
    }

    const account = await env.DB.prepare(
      `SELECT id, student_id, password_hash
       FROM student_accounts
       WHERE username = ?`
    ).bind(username).first();

    if (
      !account ||
      !(await verifyPassword(password, account.password_hash))
    ) {
      return reply(request, env, {
        success: false,
        error: "اسم المستخدم أو كلمة المرور غير صحيحة."
      }, 401);
    }

    const token = randomToken();
    const tokenHash = await sha256(token);

    await env.DB.prepare(
      `INSERT INTO student_sessions
       (student_id, token_hash, expires_at)
       VALUES (?, ?, datetime('now', ?))`
    ).bind(
      account.student_id,
      tokenHash,
      `+${SESSION_DAYS} days`
    ).run();

    return reply(request, env, {
      success: true,
      token,
      expiresInDays: SESSION_DAYS
    });
  }

  // مسارات الطالب المحمية بتسجيل الدخول
  if (path.startsWith("/api/student/")) {
    const session = await studentSession(request, env);

    if (!session) {
      return reply(request, env, {
        success: false,
        error: "يلزم تسجيل الدخول."
      }, 401);
    }

    // بيانات الطالب ومواده
    if (method === "GET" && path === "/api/student/me") {
      const student = await env.DB.prepare(
        `SELECT id, name, phone, parent_phone,
                grade, school, governorate, created_at
         FROM students
         WHERE id = ?`
      ).bind(session.student_id).first();

      const subjects = await env.DB.prepare(
        `SELECT sub.id, sub.name, sub.grade
         FROM student_subjects ss
         JOIN subjects sub ON sub.id = ss.subject_id
         WHERE ss.student_id = ?
         ORDER BY sub.name`
      ).bind(session.student_id).all();

      return reply(request, env, {
        success: true,
        student,
        subjects: subjects.results || []
      });
    }

    // المشتريات المعتمدة والمكتملة
    if (method === "GET" && path === "/api/student/purchases") {
      const rows = await env.DB.prepare(
        `SELECT o.id AS order_id, o.status, o.created_at,
                m.id AS material_id, m.title, m.type,
                m.price, m.file_key,
                sub.name AS subject_name
         FROM orders o
         JOIN materials m ON m.id = o.material_id
         JOIN subjects sub ON sub.id = m.subject_id
         WHERE o.student_id = ?
         AND o.status IN ('approved', 'completed')
         ORDER BY o.id DESC`
      ).bind(session.student_id).all();

      return reply(request, env, {
        success: true,
        purchases: rows.results || []
      });
    }

    // تسجيل خروج الطالب
    if (method === "POST" && path === "/api/student/logout") {
      await env.DB.prepare(
        "DELETE FROM student_sessions WHERE token_hash = ?"
      ).bind(session.tokenHash).run();

      return reply(request, env, {
        success: true
      });
    }

    return reply(request, env, {
      success: false,
      error: "Student endpoint not found."
    }, 404);
  }

  // إنشاء طلب شراء بالطريقة القديمة
  if (method === "POST" && path === "/api/orders") {
    const body = await readBody(request);

    const studentId = Number(body?.student_id);
    const materialId = Number(body?.material_id);

    if (
      !Number.isInteger(studentId) ||
      !Number.isInteger(materialId) ||
      studentId < 1 ||
      materialId < 1
    ) {
      return reply(request, env, {
        success: false,
        error: "student_id and material_id are required."
      }, 400);
    }

    const student = await env.DB.prepare(
      "SELECT id FROM students WHERE id = ?"
    ).bind(studentId).first();

    const material = await env.DB.prepare(
      "SELECT id FROM materials WHERE id = ?"
    ).bind(materialId).first();

    if (!student || !material) {
      return reply(request, env, {
        success: false,
        error: "Student or material not found."
      }, 404);
    }

    const result = await env.DB.prepare(
      `INSERT INTO orders
       (student_id, material_id, status)
       VALUES (?, ?, 'pending')`
    ).bind(studentId, materialId).run();

    return reply(request, env, {
      success: true,
      order_id: result.meta.last_row_id,
      status: "pending"
    }, 201);
  }

  return reply(request, env, {
    success: false,
    error: "Not found."
  }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (error) {
      // لا نعرض تفاصيل الأخطاء الداخلية للزوار
      return reply(request, env, {
        success: false,
        error: "Internal server error."
      }, 500);
    }
  },
};
