import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const root = process.cwd();
const pages = [
  "index.html", "welcome.html", "login.html", "register.html",
  "admin.html", "student.html", "parent.html", "page.html", "certificate.html"
];

for (const page of pages) {
  const file = path.join(root, page);
  if (!fs.existsSync(file)) throw new Error("Missing required page: " + page);
  const html = fs.readFileSync(file, "utf8");
  const scripts = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let match;
  let index = 0;
  while ((match = scripts.exec(html))) {
    index += 1;
    const attrs = match[1] || "";
    const source = match[2] || "";
    if (/\bsrc\s*=/i.test(attrs) || /type\s*=\s*["'](?:application\/ld\+json|application\/json|importmap)["']/i.test(attrs)) continue;
    try {
      new vm.Script(source, { filename: page + " inline script " + index });
    } catch (error) {
      throw new Error("Invalid JavaScript in " + page + ", inline script " + index + ": " + error.stack);
    }
  }

  const externalScripts = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
  while ((match = externalScripts.exec(html))) {
    const src = match[1];
    if (/^(?:https?:)?\/\//i.test(src) || src.startsWith("data:")) continue;
    const local = path.resolve(path.dirname(file), src.split(/[?#]/)[0]);
    if (!fs.existsSync(local)) throw new Error("Missing local script asset referenced by " + page + ": " + src);
  }
}

const manifestPath = path.join(root, "manifest.webmanifest");
if (fs.existsSync(manifestPath)) JSON.parse(fs.readFileSync(manifestPath, "utf8"));
console.log("HTML_CHECK_OK");
