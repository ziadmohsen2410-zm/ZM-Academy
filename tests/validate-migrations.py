from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
migration_dir = root / "migrations"
files = sorted(migration_dir.glob("*.sql"))
if not files:
    raise SystemExit("No SQL migrations found")

for file in files:
    sql = file.read_text(encoding="utf-8")
    sql = re.sub(r"(?m)^\s*--.*$", "", sql)
    if re.search(r"\bDROP\s+(?:TABLE|COLUMN|INDEX)\b|\bTRUNCATE\b|\bDELETE\s+FROM\b", sql, re.I):
        raise SystemExit(f"Destructive SQL is not allowed in additive migrations: {file.name}")

core = (migration_dir / "001_platform_core.sql").read_text(encoding="utf-8")
for table in ("platform_settings", "roles", "audit_logs", "page_drafts", "student_preferences", "parents", "notifications", "ads", "exams", "exam_questions", "exam_attempts", "ai_logs", "backup_runs"):
    if not re.search(rf"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+{table}\b", core, re.I):
        raise SystemExit(f"Core migration is missing an idempotent table declaration: {table}")

extensions = migration_dir / "002_column_extensions.sql"
if extensions.exists():
    sql = extensions.read_text(encoding="utf-8")
    sql = re.sub(r"(?m)^\s*--.*$", "", sql)
    statements = [s.strip() for s in sql.split(";") if s.strip()]
    for statement in statements:
        if not re.match(r"ALTER\s+TABLE\s+\w+\s+ADD\s+COLUMN\s+", statement, re.I):
            raise SystemExit(f"Unexpected non-additive statement in {extensions.name}: {statement[:80]}")

print("MIGRATION_CHECK_OK")
