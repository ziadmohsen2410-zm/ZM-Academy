import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const root = path.resolve(new URL('..', import.meta.url).pathname);
const files = ['index.html', 'welcome.html', 'admin.html', 'student.html', 'login.html', 'register.html', 'parent.html', 'page.html'];
let failures = 0;
for (const file of files) {
  const html = fs.readFileSync(path.join(root, file), 'utf8');
  const scripts = [...html.matchAll(/<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script\s*>/gi)];
  for (let i = 0; i < scripts.length; i++) {
    const tmp = path.join(os.tmpdir(), `zm-academy-${process.pid}-${i}.mjs`);
    fs.writeFileSync(tmp, scripts[i][1]);
    const check = spawnSync(process.execPath, ['--check', tmp], { encoding: 'utf8' });
    fs.rmSync(tmp, { force: true });
    if (check.status !== 0) {
      failures++;
      process.stderr.write(`${file} inline script ${i + 1}:\n${check.stderr}`);
    }
  }
}
if (failures) process.exitCode = 1;
else console.log(`PASS: syntax checked ${files.length} HTML files and all inline scripts.`);
