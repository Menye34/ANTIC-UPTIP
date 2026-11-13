"""Isolated fixtures for persisted authorization provider tests."""

import os
from pathlib import Path

import pytest
from dotenv import dotenv_values
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session


@pytest.fixture(scope='session')
def engine():
    values = dotenv_values(Path(__file__).resolve().parents[3] / '.env')
    raw_url = values.get('UPTIP_DATABASE_URL')

    if not raw_url:
        pytest.fail('Missing application database configuration.', pytrace=False)

    source = make_url(raw_url)

    if (
        source.drivername != 'postgresql+psycopg'
        or source.host != '127.0.0.1'
        or source.database != 'uptip'
        or source.username != 'uptip_runtime'
    ):
        pytest.fail('Unexpected source database configuration.', pytrace=False)

    url = source.set(database='uptip_test_authz_stage1')

    if url.database == source.database:
        pytest.fail('Test database must differ from development.', pytrace=False)

    test_engine = create_engine(url, hide_parameters=True)

    try:
        with test_engine.connect() as connection:
            identity = connection.execute(text("""
                SELECT current_database(), current_user
            """)).one()

            if identity != ('uptip_test_authz_stage1', 'uptip_runtime'):
                pytest.fail('Unexpected test database identity.', pytrace=False)

            revision = connection.scalar(
                text('SELECT version_num FROM alembic_version')
            )

            if revision != '0017':
                pytest.fail('Test database must be at migration 0011.', pytrace=False)

        yield test_engine
    finally:
        test_engine.dispose()


@pytest.fixture
def db(engine):
    with engine.connect() as connection:
        transaction = connection.begin()

        try:
            with Session(bind=connection, expire_on_commit=False) as session:
                yield session
        finally:
            transaction.rollback()
