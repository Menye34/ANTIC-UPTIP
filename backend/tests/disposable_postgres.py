"""Opt-in administration for an explicitly marked disposable test cluster.

Never used by application code. No operational database may be administered.
"""
import re
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

MARKER = 'UPTIP disposable scheduling concurrency database'
CLUSTER_MARKER = 'UPTIP disposable test cluster'


def scheduling_database(name, admin_raw, owner_raw, runtime_raw, test_url, *, kind='schedule'):
    marker = {'schedule': MARKER, 'migration': 'UPTIP disposable isolated migration test database'}.get(kind)
    if marker is None:
        raise RuntimeError('Refusing unverified database kind')
    admin, owner, runtime = map(make_url, (admin_raw, owner_raw, runtime_raw))
    test = make_url(str(test_url))
    if not (re.fullmatch(r'uptip_test_' + kind + r'_[0-9a-f]{32}', name)
            and admin.database == 'postgres' and admin.username == 'postgres'
            and owner.username == 'uptip' and runtime.username == 'uptip_runtime'
            and owner.database == runtime.database == test.database == 'uptip_test_readiness_fix'
            and all(url.drivername == 'postgresql+psycopg' and url.host == '127.0.0.1'
                    and not url.query for url in (admin, owner, runtime, test))
            and len({url.port for url in (admin, owner, runtime, test)}) == 1):
        raise RuntimeError('Refusing unverified disposable cluster configuration')
    engine = create_engine(admin, isolation_level='AUTOCOMMIT', poolclass=NullPool, hide_parameters=True)

    def administer(action):
        with engine.connect() as conn:
            if conn.scalar(text("SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()")) != CLUSTER_MARKER:
                raise RuntimeError('Disposable cluster marker missing')
            base = conn.execute(text("SELECT pg_get_userbyid(datdba), shobj_description(oid,'pg_database') FROM pg_database WHERE datname=:name"), {'name': 'uptip_test_readiness_fix'}).one_or_none()
            if base != ('uptip', 'UPTIP disposable integration test database'):
                raise RuntimeError('Disposable test database identity mismatch')
            if action == 'verify':
                return
            if action == 'create':
                conn.execute(text(f'CREATE DATABASE "{name}" OWNER uptip TEMPLATE template0'))
                conn.execute(text(f"COMMENT ON DATABASE \"{name}\" IS '{marker}'"))
            elif action == 'drop':
                identity = conn.execute(text("SELECT pg_get_userbyid(datdba), shobj_description(oid,'pg_database') FROM pg_database WHERE datname=:name"), {'name': name}).one_or_none()
                if identity != ('uptip', marker):
                    raise RuntimeError('Refusing to drop an unverified test database')
                conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
            else:
                raise ValueError('Unsupported test administration action')
    return administer, owner.set(database=name), runtime.set(database=name)
