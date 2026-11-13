from sqlalchemy import text


def test_committed_database_connection(committed_db):
    result = committed_db.execute(text("""
        SELECT
            current_database(),
            shobj_description(oid, 'pg_database')
        FROM pg_database
        WHERE datname = current_database()
    """)).one()

    assert result == (
        "uptip_test_concurrency",
        "UPTIP disposable concurrency test database",
    )
