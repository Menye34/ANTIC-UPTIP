from alembic import context
from sqlalchemy import create_engine
from app.config import get_settings
from app.database import Base
from app import models  # noqa: F401

target_metadata = Base.metadata

settings = get_settings()
migration_url = settings.migration_database_url

if not migration_url:
    raise RuntimeError(
        "UPTIP_MIGRATION_DATABASE_URL must be configured for Alembic"
    )

if not migration_url.startswith("postgresql+psycopg://"):
    raise RuntimeError("Migration URL must use PostgreSQL with psycopg")

from sqlalchemy.engine import make_url

runtime_identity = make_url(settings.database_url)
migration_identity = make_url(migration_url)

if runtime_identity.username == migration_identity.username:
    raise RuntimeError(
        "Migration and runtime database usernames must be different"
    )
if context.is_offline_mode():
    context.configure(url=migration_url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = create_engine(migration_url, hide_parameters=True)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
