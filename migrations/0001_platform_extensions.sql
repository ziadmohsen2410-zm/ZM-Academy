-- ZM Academy platform extensions. Additive only; existing tables and records are untouched.
CREATE TABLE IF NOT EXISTS platform_pages (
  slug TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  draft_json TEXT NOT NULL DEFAULT '{"version":1,"blocks":[]}',
  published_json TEXT NOT NULL DEFAULT '{"version":1,"blocks":[]}',
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published')),
  updated_by INTEGER,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS platform_page_revisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL,
  snapshot_json TEXT NOT NULL,
  revision_type TEXT NOT NULL DEFAULT 'save' CHECK (revision_type IN ('save','publish','restore')),
  created_by INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_platform_page_revisions_slug_created
  ON platform_page_revisions(slug, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS student_preferences (
  student_id INTEGER PRIMARY KEY,
  settings_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS parent_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS parent_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  parent_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_parent_sessions_parent_expiry
  ON parent_sessions(parent_id, expires_at);
CREATE TABLE IF NOT EXISTS parent_link_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  parent_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at TEXT,
  reviewed_by INTEGER,
  UNIQUE(parent_id, student_id)
);
CREATE INDEX IF NOT EXISTS idx_parent_link_requests_status_created
  ON parent_link_requests(status, created_at DESC);
CREATE TABLE IF NOT EXISTS parent_student_links (
  parent_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  linked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_by INTEGER,
  PRIMARY KEY(parent_id, student_id)
);
CREATE INDEX IF NOT EXISTS idx_parent_student_links_student
  ON parent_student_links(student_id);

CREATE TABLE IF NOT EXISTS admin_role_assignments (
  admin_id INTEGER PRIMARY KEY,
  role TEXT NOT NULL DEFAULT 'super_admin'
    CHECK (role IN ('super_admin','admin','content_manager','teacher','support')),
  updated_by INTEGER,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_type TEXT NOT NULL,
  actor_id INTEGER,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id TEXT,
  details_json TEXT NOT NULL DEFAULT '{}',
  ip_address TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_type, actor_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '',
  image_url TEXT,
  target_url TEXT,
  button_text TEXT NOT NULL DEFAULT '',
  placement TEXT NOT NULL DEFAULT 'home',
  audience TEXT NOT NULL DEFAULT 'all',
  starts_at TEXT,
  ends_at TEXT,
  priority INTEGER NOT NULL DEFAULT 0,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
  impressions INTEGER NOT NULL DEFAULT 0,
  clicks INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ads_publication ON ads(placement, is_active, starts_at, ends_at, priority DESC);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_value TEXT,
  is_important INTEGER NOT NULL DEFAULT 0 CHECK (is_important IN (0,1)),
  scheduled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_by INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notification_recipients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  notification_id INTEGER NOT NULL,
  recipient_type TEXT NOT NULL CHECK (recipient_type IN ('student','parent')),
  recipient_id INTEGER NOT NULL,
  read_at TEXT,
  UNIQUE(notification_id, recipient_type, recipient_id)
);
CREATE INDEX IF NOT EXISTS idx_notification_recipients_inbox
  ON notification_recipients(recipient_type, recipient_id, read_at, notification_id DESC);

CREATE TABLE IF NOT EXISTS ai_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_type TEXT NOT NULL,
  actor_id INTEGER NOT NULL,
  feature TEXT NOT NULL,
  input_chars INTEGER NOT NULL DEFAULT 0,
  output_chars INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ai_usage_actor_created
  ON ai_usage(actor_type, actor_id, created_at DESC);

-- Future exam foundation; it does not alter legacy subjects, materials, students, or orders.
CREATE TABLE IF NOT EXISTS quizzes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  grade TEXT NOT NULL DEFAULT '',
  subject_id INTEGER,
  duration_minutes INTEGER NOT NULL DEFAULT 30,
  max_attempts INTEGER NOT NULL DEFAULT 1,
  starts_at TEXT,
  ends_at TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published','archived')),
  created_by INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_quizzes_publication ON quizzes(status, grade, subject_id, starts_at, ends_at);
CREATE TABLE IF NOT EXISTS quiz_questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  quiz_id INTEGER NOT NULL,
  question_type TEXT NOT NULL CHECK (question_type IN ('mcq','true_false','essay')),
  prompt TEXT NOT NULL,
  options_json TEXT NOT NULL DEFAULT '[]',
  answer_json TEXT,
  points REAL NOT NULL DEFAULT 1,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_quiz_questions_quiz_order ON quiz_questions(quiz_id, sort_order, id);
CREATE TABLE IF NOT EXISTS quiz_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  quiz_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  answers_json TEXT NOT NULL DEFAULT '{}',
  score REAL,
  max_score REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('in_progress','submitted','graded')),
  started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  submitted_at TEXT,
  graded_by INTEGER,
  graded_at TEXT,
  essay_scores_json TEXT NOT NULL DEFAULT '{}',
  teacher_feedback TEXT
);
CREATE INDEX IF NOT EXISTS idx_quiz_attempts_student ON quiz_attempts(student_id, quiz_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_quiz_attempts_quiz ON quiz_attempts(quiz_id, status, submitted_at DESC);

-- AI-generated drafts require human review before they can be used in lessons.
CREATE TABLE IF NOT EXISTS ai_content_drafts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content_type TEXT NOT NULL CHECK (content_type IN ('summary','lesson','mcq','essay','flashcards','study_plan')),
  title TEXT NOT NULL,
  prompt TEXT NOT NULL,
  content TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending_review' CHECK (status IN ('pending_review','approved','rejected')),
  created_by INTEGER,
  reviewed_by INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_ai_content_drafts_status_created
  ON ai_content_drafts(status, created_at DESC, id DESC);

-- Managed media metadata; file bytes remain in the existing private GitHub Storage repository.
CREATE TABLE IF NOT EXISTS media_assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_key TEXT NOT NULL UNIQUE,
  file_name TEXT NOT NULL,
  content_type TEXT NOT NULL CHECK (content_type IN ('application/pdf','image/jpeg','image/png','image/webp')),
  size_bytes INTEGER NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 8388608),
  folder TEXT NOT NULL DEFAULT 'general',
  alt_text TEXT NOT NULL DEFAULT '',
  is_public INTEGER NOT NULL DEFAULT 0 CHECK (is_public IN (0,1)),
  uploaded_by INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_media_assets_folder_created ON media_assets(folder, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_media_assets_public_type ON media_assets(is_public, content_type);
