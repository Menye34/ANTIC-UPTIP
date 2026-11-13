"""Safe lifecycle for UPTIP's disposable concurrency-test database."""

import os

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


SOURCE = "uptip_test_readiness_fix"
DESTINATION = "uptip_test_concurrency"

SOURCE_COMMENT = "UPTIP disposable integration test database"
DESTINATION_COMMENT = "UPTIP disposable concurrency test database"


def recreate_concurrency_database():
    raw_url = os.environ.get("UPTIP_TEST_DATABASE_URL")

    if not raw_url:
        raise RuntimeError("UPTIP_TEST_DATABASE_URL is required")

    url = make_url(raw_url)

    if (
        url.drivername != "postgresql+psycopg"
        or url.host not in {"127.0.0.1", "::1"}
        or url.database != SOURCE
        or url.query
    ):
        raise RuntimeError("Unsafe PostgreSQL configuration")

    admin_url = url.set(database="postgres")

    engine = create_engine(
        admin_url,
        isolation_level="AUTOCOMMIT",
        hide_parameters=True,
    )

    try:
        with engine.connect() as connection:
            rows = connection.execute(
                text("""
                    SELECT
                        datname,
                        pg_get_userbyid(datdba),
                        shobj_description(oid, 'pg_database')
                    FROM pg_database
                    WHERE datname IN (:source, :destination)
                """),
                {
                    "source": SOURCE,
                    "destination": DESTINATION,
                },
            ).all()

            databases = {
                name: (owner, description)
                for name, owner, description in rows
            }

            expected_owner = url.username

            if databases.get(SOURCE) != (
                expected_owner,
                SOURCE_COMMENT,
            ):
                raise RuntimeError("Source database verification failed")

            if databases.get(DESTINATION) != (
                expected_owner,
                DESTINATION_COMMENT,
            ):
                raise RuntimeError("Destination database verification failed")

            active = connection.scalar(
                text("""
                    SELECT COUNT(*)
                    FROM pg_stat_activity
                    WHERE datname = :destination
                """),
                {"destination": DESTINATION},
            )

            if active:
                raise RuntimeError(
                    "Concurrency database has active connections"
                )

            connection.exec_driver_sql(
                f'DROP DATABASE "{DESTINATION}"'
            )

            connection.exec_driver_sql(
                f'CREATE DATABASE "{DESTINATION}" '
                f'WITH TEMPLATE "{SOURCE}"'
            )

            connection.exec_driver_sql(
                f"COMMENT ON DATABASE \"{DESTINATION}\" "
                f"IS '{DESTINATION_COMMENT}'"
            )

    finally:
        engine.dispose()
