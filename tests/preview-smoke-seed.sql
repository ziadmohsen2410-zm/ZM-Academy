INSERT OR REPLACE INTO subjects (id, name, grade) VALUES (990001, 'Preview smoke test', 'Preview');
INSERT OR REPLACE INTO students (id, name, phone, parent_phone, grade, school, governorate) VALUES (990001, 'Preview smoke student', '01000000000', '01000000001', 'Preview', 'Test school', 'Preview');
INSERT OR REPLACE INTO materials (id, subject_id, title, type, price, is_free, file_key) VALUES (990001, 990001, 'Preview deletion fixture', 'lesson', 10, 0, NULL);
INSERT OR REPLACE INTO orders (id, student_id, material_id, status) VALUES (990001, 990001, 990001, 'approved');
INSERT OR REPLACE INTO student_hidden_purchases (student_id, order_id) VALUES (990001, 990001);
INSERT OR REPLACE INTO student_material_progress (student_id, material_id, last_page) VALUES (990001, 990001, 3);
INSERT OR REPLACE INTO student_favorites (student_id, material_id) VALUES (990001, 990001);
INSERT OR REPLACE INTO archived_materials (material_id) VALUES (990001);
INSERT OR REPLACE INTO preview_material_notes (material_id, note) VALUES (990001, 'recursive dependency fixture');
