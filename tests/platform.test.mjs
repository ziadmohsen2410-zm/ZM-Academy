import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validatePageDocument,
  sanitizeStudentPreferences,
  sanitizeQuizDefinition,
  isValidMediaBytes,
} from '../worker.js';

test('page schema accepts allow-listed blocks and strips unapproved fields', () => {
  const result = validatePageDocument({ version: 1, blocks: [{
    id: 'hero_1', type: 'heading', visible: true,
    content: { title: 'مرحبًا', text: 'أكاديمية', href: 'javascript:alert(1)', unexpected: '<script>' },
    style: { color: '#123456', position: 'fixed', fontSize: 22 },
    responsive: { mobile: { hidden: true, width: 90, html: '<b>' } },
    html: '<script>alert(1)</script>',
  }] });
  assert.equal(result.ok, true);
  assert.equal(result.value.blocks[0].content.href, '');
  assert.equal(result.value.blocks[0].style.position, undefined);
  assert.equal(result.value.blocks[0].responsive.mobile.hidden, true);
  assert.equal(result.value.blocks[0].html, undefined);
});

test('page schema rejects javascript URLs and overlarge documents', () => {
  assert.equal(validatePageDocument({ version: 1, blocks: [{ id: 'a1', type: 'button', content: { href: 'javascript:alert(1)' } }] }).ok, false);
  assert.equal(validatePageDocument({ version: 1, blocks: [{ id: 'a2', type: 'image', content: { src: '/assets/../../private.png' } }] }).ok, false);
  assert.equal(validatePageDocument({ version: 1, blocks: Array.from({ length: 61 }, (_, i) => ({ id: `b${i}`, type: 'text', content: { text: 'x' } })) }).ok, false);
});

test('student preferences enforce enum values, valid colors and bounded scale', () => {
  const p = sanitizeStudentPreferences({ mode: 'dark', template: 'luxury', cardStyle: 'glass', primary: '#AABBCC', fontScale: 1.1, dashboardOrder: ['subjects', 'bad', 'subjects'], admin: true, fontScaleHack: 100 });
  assert.equal(p.mode, 'dark');
  assert.equal(p.template, 'luxury');
  assert.equal(p.primary, '#AABBCC');
  assert.equal(p.dashboardOrder.length, 1);
  assert.equal(p.admin, undefined);
  assert.deepEqual(sanitizeStudentPreferences({ fontScale: 2 }), {});
});

test('quiz definition validates answers and limits before storage', () => {
  const valid = sanitizeQuizDefinition({
    title: 'اختبار تجريبي', grade: 'الصف الأول', duration_minutes: 20, max_attempts: 2,
    questions: [
      { type: 'mcq', prompt: '2 + 2؟', options: ['3', '4'], correct_index: 1, points: 2 },
      { type: 'true_false', prompt: 'الشمس نجم', correct_value: true, points: 1 },
      { type: 'essay', prompt: 'اشرح السبب', points: 4 },
    ],
  });
  assert.equal(valid.ok, true);
  assert.equal(valid.value.questions.length, 3);
  assert.equal(valid.value.questions[0].answer, 1);
  assert.equal(valid.value.questions[2].answer, null);
  assert.equal(sanitizeQuizDefinition({ title: 'x', grade: 'x', questions: [{ type: 'mcq', prompt: 'q', options: ['a'], correct_index: 0 }] }).ok, false);
  assert.equal(sanitizeQuizDefinition({ title: 'x', grade: 'x', questions: [{ type: 'true_false', prompt: 'q', correct_value: 'yes' }] }).ok, false);
});


test('media upload validates file signatures rather than trusting MIME labels', () => {
  assert.equal(isValidMediaBytes(new Uint8Array([0x25,0x50,0x44,0x46,0x2d,0x31]), 'application/pdf'), true);
  assert.equal(isValidMediaBytes(new Uint8Array([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]), 'image/png'), true);
  assert.equal(isValidMediaBytes(new Uint8Array([0x25,0x50,0x44,0x46]), 'image/png'), false);
  assert.equal(isValidMediaBytes(new Uint8Array([0xff,0xd8,0xff]), 'image/jpeg'), true);
});
