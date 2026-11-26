-- Column extensions for existing tables (run manually if needed; SQLite errors on duplicate ADD COLUMN)
-- The worker also attempts these via ensureColumn() at runtime.
ALTER TABLE admin_users ADD COLUMN display_name TEXT;
ALTER TABLE admin_users ADD COLUMN email TEXT;
ALTER TABLE admin_users ADD COLUMN role TEXT DEFAULT 'super_admin';
ALTER TABLE admin_users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;
ALTER TABLE admin_users ADD COLUMN last_login_at TEXT;
ALTER TABLE admin_users ADD COLUMN created_at TEXT;
ALTER TABLE students ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;
ALTER TABLE students ADD COLUMN created_at TEXT;
ALTER TABLE students ADD COLUMN updated_at TEXT;
ALTER TABLE orders ADD COLUMN review_note TEXT;
ALTER TABLE orders ADD COLUMN reviewed_at TEXT;
ALTER TABLE orders ADD COLUMN reviewed_by TEXT;
ALTER TABLE materials ADD COLUMN is_archived INTEGER NOT NULL DEFAULT 0;
ALTER TABLE subjects ADD COLUMN is_archived INTEGER NOT NULL DEFAULT 0;
