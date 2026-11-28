-- Additive teacher-to-grade/subject assignments for Phase 2.
-- Safe to apply repeatedly; existing student and parent data is untouched.
CREATE TABLE IF NOT EXISTS teacher_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  teacher_admin_id INTEGER NOT NULL,
  grade TEXT NOT NULL,
  subject TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(teacher_admin_id, grade, subject)
);
CREATE INDEX IF NOT EXISTS idx_teacher_assignments_teacher
  ON teacher_assignments(teacher_admin_id);
CREATE INDEX IF NOT EXISTS idx_teacher_assignments_grade_subject
  ON teacher_assignments(grade, subject);
