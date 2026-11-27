-- ZM Academy Platform Core Migration (idempotent where possible)
-- Safe for Cloudflare D1 / SQLite. Run in order.

PRAGMA foreign_keys = ON;

-- Platform settings / key-value config
CREATE TABLE IF NOT EXISTS platform_settings (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_by TEXT
);

-- Roles & permissions
CREATE TABLE IF NOT EXISTS roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  description TEXT DEFAULT '',
  is_system INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS role_permissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role_id INTEGER NOT NULL,
  permission TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(role_id, permission),
  FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS admin_user_roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_user_id INTEGER NOT NULL,
  role_id INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(admin_user_id, role_id)
);

-- Extend admin_users safely (SQLite: ADD COLUMN is idempotent only by ignoring error; handle in runner)
-- ALTER TABLE admin_users ADD COLUMN display_name TEXT;
-- ALTER TABLE admin_users ADD COLUMN email TEXT;
-- ALTER TABLE admin_users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;
-- ALTER TABLE admin_users ADD COLUMN last_login_at TEXT;
-- ALTER TABLE admin_users ADD COLUMN created_at TEXT DEFAULT (datetime('now'));

-- Audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_type TEXT NOT NULL, -- admin|student|parent|system
  actor_id INTEGER,
  actor_label TEXT,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id TEXT,
  details_json TEXT,
  ip TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);

-- Page builder
CREATE TABLE IF NOT EXISTS page_drafts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  page_key TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  content_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_by TEXT
);

CREATE TABLE IF NOT EXISTS page_published (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  page_key TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  content_json TEXT NOT NULL DEFAULT '{}',
  published_at TEXT NOT NULL DEFAULT (datetime('now')),
  published_by TEXT
);

CREATE TABLE IF NOT EXISTS page_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  page_key TEXT NOT NULL,
  title TEXT NOT NULL,
  content_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'published', -- draft|published
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_page_versions_key ON page_versions(page_key, created_at DESC);

-- Student UI preferences (per student, isolated)
CREATE TABLE IF NOT EXISTS student_preferences (
  student_id INTEGER PRIMARY KEY,
  preferences_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Parent portal
CREATE TABLE IF NOT EXISTS parents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS parent_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  parent_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(parent_id) REFERENCES parents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_parent_sessions_parent ON parent_sessions(parent_id);

CREATE TABLE IF NOT EXISTS parent_student_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  parent_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', -- pending|approved|rejected
  requested_at TEXT NOT NULL DEFAULT (datetime('now')),
  reviewed_at TEXT,
  reviewed_by TEXT,
  note TEXT,
  UNIQUE(parent_id, student_id),
  FOREIGN KEY(parent_id) REFERENCES parents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_parent_links_parent ON parent_student_links(parent_id);
CREATE INDEX IF NOT EXISTS idx_parent_links_student ON parent_student_links(student_id);

-- Notifications
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'general', -- general|order|exam|lesson|important
  audience_type TEXT NOT NULL DEFAULT 'all', -- all|grade|subject|student|parents
  audience_value TEXT,
  scheduled_at TEXT,
  sent_at TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  is_important INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS notification_reads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  notification_id INTEGER NOT NULL,
  user_type TEXT NOT NULL, -- student|parent|admin
  user_id INTEGER NOT NULL,
  read_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(notification_id, user_type, user_id),
  FOREIGN KEY(notification_id) REFERENCES notifications(id) ON DELETE CASCADE
);

-- Ads
CREATE TABLE IF NOT EXISTS ads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  body TEXT,
  image_url TEXT,
  link_url TEXT,
  cta_text TEXT,
  placement TEXT NOT NULL DEFAULT 'home',
  audience_type TEXT NOT NULL DEFAULT 'all',
  audience_value TEXT,
  priority INTEGER NOT NULL DEFAULT 0,
  starts_at TEXT,
  ends_at TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ad_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ad_id INTEGER NOT NULL,
  event_type TEXT NOT NULL, -- view|click
  user_type TEXT,
  user_id INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(ad_id) REFERENCES ads(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ad_events_ad ON ad_events(ad_id, event_type);

-- Exams
CREATE TABLE IF NOT EXISTS exams (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT,
  subject_id INTEGER,
  grade TEXT,
  status TEXT NOT NULL DEFAULT 'draft', -- draft|published|archived
  duration_minutes INTEGER,
  attempts_allowed INTEGER DEFAULT 1,
  starts_at TEXT,
  ends_at TEXT,
  shuffle_questions INTEGER NOT NULL DEFAULT 0,
  show_results INTEGER NOT NULL DEFAULT 1,
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS exam_questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  exam_id INTEGER NOT NULL,
  type TEXT NOT NULL, -- mcq|true_false|essay
  question_text TEXT NOT NULL,
  options_json TEXT, -- for mcq/true_false
  correct_answer_json TEXT,
  points REAL NOT NULL DEFAULT 1,
  order_index INTEGER NOT NULL DEFAULT 0,
  explanation TEXT,
  FOREIGN KEY(exam_id) REFERENCES exams(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_exam_questions_exam ON exam_questions(exam_id);

CREATE TABLE IF NOT EXISTS exam_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  exam_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  submitted_at TEXT,
  score REAL,
  max_score REAL,
  status TEXT NOT NULL DEFAULT 'in_progress', -- in_progress|submitted|graded
  answers_json TEXT,
  question_order_json TEXT,
  feedback_json TEXT,
  graded_by TEXT,
  graded_at TEXT,
  FOREIGN KEY(exam_id) REFERENCES exams(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_exam_attempts_exam_student ON exam_attempts(exam_id, student_id);

-- AI logs / usage
CREATE TABLE IF NOT EXISTS ai_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_type TEXT NOT NULL, -- student|admin|system
  actor_id INTEGER,
  tool TEXT NOT NULL, -- student_assistant|admin_assistant|builder|content_studio
  prompt_preview TEXT,
  response_status TEXT,
  tokens_estimate INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ai_logs_created_at ON ai_logs(created_at DESC);

-- Backups metadata
CREATE TABLE IF NOT EXISTS backup_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL, -- export|restore_check
  status TEXT NOT NULL, -- success|failed
  details_json TEXT,
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Default roles
INSERT OR IGNORE INTO roles (id, name, label, description, is_system) VALUES
  (1, 'super_admin', 'Super Admin', 'Full access', 1),
  (2, 'admin', 'Admin', 'Administrative access', 1),
  (3, 'content_manager', 'Content Manager', 'Manage content', 1),
  (4, 'teacher', 'Teacher', 'Manage exams and content', 1),
  (5, 'support', 'Support', 'Support and student requests', 1);

INSERT OR IGNORE INTO role_permissions (role_id, permission)
SELECT 1, p FROM (
  SELECT '*' AS p
);

