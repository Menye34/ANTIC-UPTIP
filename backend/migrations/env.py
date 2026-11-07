from alembic import context
from sqlalchemy import create_engine
from app.config import get_settings
from app.database import Base
from app import models  # noqa: F401

target_metadata = Base.metadata
if context.is_offline_mode():
    context.configure(url=get_settings().database_url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = create_engine(get_settings().database_url, hide_parameters=True)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
