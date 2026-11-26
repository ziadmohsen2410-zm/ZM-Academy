const fs=require('fs'); const path=require('path');
const root=process.cwd();
const required=['index.html','admin.html','student.html','login.html','register.html','welcome.html','parent.html','worker.js','wrangler.toml','sw.js','manifest.webmanifest','migrations/001_platform_core.sql','docs/DEPLOYMENT.md','docs/IMPLEMENTATION-REPORT.md'];
let ok=true;
for(const f of required){ if(!fs.existsSync(path.join(root,f))){ console.error('MISSING',f); ok=false; } }
try{ JSON.parse(fs.readFileSync(path.join(root,'manifest.webmanifest'),'utf8')); }catch(e){ console.error('BAD manifest',e.message); ok=false; }
const worker=fs.readFileSync(path.join(root,'worker.js'),'utf8');
['/api/admin/platform/roles','/api/admin/platform/media','/api/admin/platform/backup/export','/api/parent/login','/api/student/platform/exams','/api/admin/platform/pages'].forEach(p=>{ if(!worker.includes(p)){ console.error('MISSING_ENDPOINT',p); ok=false; }});
const admin=fs.readFileSync(path.join(root,'admin.html'),'utf8');
['sec-roles','sec-media','sec-backups','sec-pages','sec-ai'].forEach(id=>{ if(!admin.includes(id)){ console.error('MISSING_ADMIN_SECTION',id); ok=false; }});
console.log(ok?'SMOKE_OK':'SMOKE_FAIL');
process.exit(ok?0:1);
