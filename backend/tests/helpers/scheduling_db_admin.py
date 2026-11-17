"""Administrator operations for disposable scheduling-test databases only."""

import argparse
import re
import sys

import psycopg
from psycopg import sql

PREFIX = "uptip_test_schedule_"
MARKER = "UPTIP disposable scheduling concurrency database"
NAME_PATTERN = re.compile(r"^uptip_test_schedule_[0-9a-f]{32}$")


def verify_name(name):
    if not NAME_PATTERN.fullmatch(name):
        raise ValueError("Refusing unsafe test database name")


def connect():
    return psycopg.connect(
        dbname="postgres",
        user="postgres",
        host="/var/run/postgresql",
        autocommit=True,
    )


def create_database(connection, name):
    existing = connection.execute(
        "SELECT 1 FROM pg_database WHERE datname = %s",
        (name,),
    ).fetchone()

    if existing:
        raise RuntimeError("Refusing to overwrite an existing database")

    connection.execute(
        sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0").format(
            sql.Identifier(name),
            sql.Identifier("uptip"),
        )
    )

    try:
        connection.execute(
            sql.SQL("COMMENT ON DATABASE {} IS {}").format(
                sql.Identifier(name),
                sql.Literal(MARKER),
            )
        )
    except Exception:
        # Only clean up the database created by this invocation.
        connection.execute(
            sql.SQL("DROP DATABASE {} WITH (FORCE)").format(
                sql.Identifier(name)
            )
        )
        raise


def drop_database(connection, name):
    identity = connection.execute(
        """
        SELECT shobj_description(oid, 'pg_database')
        FROM pg_database
        WHERE datname = %s
        """,
        (name,),
    ).fetchone()

    if identity is None or identity[0] != MARKER:
        raise RuntimeError("Refusing to delete an unverified database")

    connection.execute(
        sql.SQL("DROP DATABASE {} WITH (FORCE)").format(
            sql.Identifier(name)
        )
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("create", "drop"))
    parser.add_argument("database")
    args = parser.parse_args()

    verify_name(args.database)

    with connect() as connection:
        if args.action == "create":
            create_database(connection, args.database)
        else:
            drop_database(connection, args.database)

    print(f"Scheduling test database {args.action} completed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Database administration refused: {exc}", file=sys.stderr)
        sys.exit(1)
