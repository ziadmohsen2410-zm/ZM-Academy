-- Teacher-submitted content approval workflow. Additive and safe for existing student/parent data.
CREATE TABLE IF NOT EXISTS teacher_content_submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  teacher_admin_id INTEGER NOT NULL,
  subject_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  content_type TEXT NOT NULL CHECK(content_type IN ('pdf','image','video','link')),
  file_key TEXT,
  external_url TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
  review_note TEXT,
  reviewed_by INTEGER,
  reviewed_at TEXT,
  material_id INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_teacher_content_status ON teacher_content_submissions(status, id);
CREATE INDEX IF NOT EXISTS idx_teacher_content_teacher ON teacher_content_submissions(teacher_admin_id, id);
ALTER TABLE materials ADD COLUMN external_url TEXT;
