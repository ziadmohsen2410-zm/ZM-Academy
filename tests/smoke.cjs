const fs=require('fs'); const path=require('path');
const root=process.cwd();
const required=['index.html','admin.html','student.html','login.html','register.html','welcome.html','parent.html','worker.js','wrangler.toml','sw.js','manifest.webmanifest','migrations/001_platform_core.sql','docs/DEPLOYMENT.md','docs/IMPLEMENTATION-REPORT.md'];
let ok=true;
for(const f of required){ if(!fs.existsSync(path.join(root,f))){ console.error('MISSING',f); ok=false; } }
try{ JSON.parse(fs.readFileSync(path.join(root,'manifest.webmanifest'),'utf8')); }catch(e){ console.error('BAD manifest',e.message); ok=false; }
console.log(ok?'SMOKE_OK':'SMOKE_FAIL');
process.exit(ok?0:1);
