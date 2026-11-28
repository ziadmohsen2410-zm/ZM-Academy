-- ZM Academy attendance foundation. Additive and repeat-safe.
CREATE TABLE IF NOT EXISTS attendance_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  grade TEXT NOT NULL,
  subject_id INTEGER,
  session_date TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS attendance_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('present','absent','late','excused')),
  note TEXT NOT NULL DEFAULT '',
  marked_by TEXT,
  marked_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(session_id,student_id)
);
CREATE INDEX IF NOT EXISTS idx_attendance_sessions_date ON attendance_sessions(session_date DESC, grade);
CREATE INDEX IF NOT EXISTS idx_attendance_records_student ON attendance_records(student_id, session_id);
