"""Restricted administrator for fresh UPTIP migration regression databases."""
import argparse
import re
import sys
import psycopg
from psycopg import sql

PATTERN = re.compile(r"uptip_test_migration_[0-9a-f]{32}\Z")
MARKER = "UPTIP disposable isolated migration test database"
OWNER = "uptip"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("create", "drop"))
    parser.add_argument("database")
    args = parser.parse_args()
    name = args.database
    if not PATTERN.fullmatch(name):
        raise RuntimeError("Unsafe migration test database name")
    with psycopg.connect(dbname="postgres", user="postgres", host="/var/run/postgresql", autocommit=True) as conn:
        if args.action == "create":
            if conn.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,)).fetchone():
                raise RuntimeError("Database already exists; refusing overwrite")
            conn.execute(sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0").format(sql.Identifier(name), sql.Identifier(OWNER)))
            conn.execute(sql.SQL("COMMENT ON DATABASE {} IS {}").format(sql.Identifier(name), sql.Literal(MARKER)))
        else:
            record = conn.execute("""
                SELECT r.rolname, shobj_description(d.oid,'pg_database')
                FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba
                WHERE d.datname=%s
            """, (name,)).fetchone()
            if record != (OWNER, MARKER):
                raise RuntimeError("Database owner or marker mismatch; refusing deletion")
            active = conn.execute("SELECT count(*) FROM pg_stat_activity WHERE datname=%s", (name,)).fetchone()[0]
            if active:
                raise RuntimeError(f"Database has {active} active connections; refusing deletion")
            conn.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))
    print(f"Migration database {args.action} verified: {name}")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Migration database administration refused: {exc}", file=sys.stderr)
        sys.exit(1)
