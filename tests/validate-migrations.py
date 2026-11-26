"""Apply every migration twice to a temporary SQLite DB and verify legacy rows survive."""
from pathlib import Path
import sqlite3

root = Path(__file__).resolve().parents[1]
con = sqlite3.connect(":memory:")
con.execute("PRAGMA foreign_keys = ON")

# A minimal representation of legacy records that must never be dropped.
con.executescript("""
CREATE TABLE students (id INTEGER PRIMARY KEY, name TEXT NOT NULL, phone TEXT, parent_phone TEXT, grade TEXT);
CREATE TABLE subjects (id INTEGER PRIMARY KEY, name TEXT NOT NULL, grade TEXT);
CREATE TABLE orders (id INTEGER PRIMARY KEY, student_id INTEGER, material_id INTEGER, status TEXT);
INSERT INTO students(id, name, phone, parent_phone, grade) VALUES (41, 'Keep Student', '01000000000', '01000000001', 'الثالث الثانوي');
INSERT INTO subjects(id, name, grade) VALUES (7, 'Keep Subject', 'الثالث الثانوي');
INSERT INTO orders(id, student_id, material_id, status) VALUES (91, 41, 7, 'approved');
""")

migration_files = sorted((root / "migrations").glob("*.sql"))
if not migration_files:
    raise SystemExit("FAIL: no migration files found")
for migration in migration_files:
    sql = migration.read_text(encoding="utf-8")
    con.executescript(sql)
    con.executescript(sql)  # idempotency check

assert con.execute("SELECT name FROM students WHERE id=41").fetchone() == ("Keep Student",)
assert con.execute("SELECT name FROM subjects WHERE id=7").fetchone() == ("Keep Subject",)
assert con.execute("SELECT status FROM orders WHERE id=91").fetchone() == ("approved",)
expected = {
    "platform_pages", "platform_page_revisions", "student_preferences", "parent_accounts",
    "parent_sessions", "parent_link_requests", "parent_student_links", "admin_role_assignments",
    "audit_logs", "ads", "notifications", "notification_recipients", "ai_usage", "quizzes",
    "quiz_questions", "quiz_attempts", "ai_content_drafts", "media_assets",
}
actual = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
missing = expected - actual
assert not missing, f"missing tables: {sorted(missing)}"
print(f"PASS: {len(migration_files)} migration(s) applied twice; legacy student/subject/order rows preserved; {len(expected)} extension tables present.")
