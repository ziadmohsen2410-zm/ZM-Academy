-- This database is the dedicated disposable Preview D1 database (wrangler.preview.toml), never production.
-- Clear Preview-only admin identities so the setup smoke test always starts from a known state.
DELETE FROM admin_sessions;
DELETE FROM admin_users;

-- Remove only records owned by this smoke test from the remaining Preview fixtures.
DELETE FROM parent_sessions
WHERE parent_id IN (SELECT id FROM parents WHERE username = 'preview_parent');

DELETE FROM parent_student_links
WHERE parent_id IN (SELECT id FROM parents WHERE username = 'preview_parent');

DELETE FROM parents WHERE username = 'preview_parent';

DELETE FROM student_sessions
WHERE student_id IN (
  SELECT id FROM students WHERE id = 990001 OR phone = '01000000002'
);

DELETE FROM student_devices
WHERE student_id IN (
  SELECT id FROM students WHERE id = 990001 OR phone = '01000000002'
);

DELETE FROM student_hidden_purchases
WHERE order_id IN (
  SELECT id FROM orders
  WHERE material_id IN (990001, 990002)
     OR student_id IN (SELECT id FROM students WHERE phone = '01000000002')
)
OR student_id IN (SELECT id FROM students WHERE id = 990001 OR phone = '01000000002');

DELETE FROM preview_material_notes WHERE material_id IN (990001, 990002);

DELETE FROM student_material_progress
WHERE material_id IN (990001, 990002)
   OR student_id IN (SELECT id FROM students WHERE id = 990001 OR phone = '01000000002');

DELETE FROM student_favorites
WHERE material_id IN (990001, 990002)
   OR student_id IN (SELECT id FROM students WHERE id = 990001 OR phone = '01000000002');

DELETE FROM archived_materials WHERE material_id IN (990001, 990002);
DELETE FROM archived_subjects WHERE subject_id = 990001;

DELETE FROM orders
WHERE material_id IN (990001, 990002)
   OR student_id IN (SELECT id FROM students WHERE phone = '01000000002');

DELETE FROM student_subjects
WHERE subject_id = 990001
   OR student_id IN (SELECT id FROM students WHERE id = 990001 OR phone = '01000000002');

DELETE FROM student_accounts
WHERE username = 'preview_student'
   OR student_id = 990001;

DELETE FROM students
WHERE id = 990001 OR phone = '01000000002';

DELETE FROM materials WHERE id IN (990001, 990002);
DELETE FROM subjects WHERE id = 990001;

DELETE FROM admin_sessions
WHERE admin_id IN (SELECT id FROM admin_users WHERE username = 'preview_smoke_admin');

DELETE FROM admin_users WHERE username = 'preview_smoke_admin';
