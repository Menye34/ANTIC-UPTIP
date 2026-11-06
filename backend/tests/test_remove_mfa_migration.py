"""Exercise the real 0003 → 0004 schema transition on the disposable test DB."""
from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text


def test_upgrade_preserves_accounts_sessions_and_history(engine):
    config = Config(str(Path(__file__).resolve().parents[1] / 'alembic.ini'))
    command.downgrade(config, '0003')
    user_id, credential_id, event_id = uuid4(), uuid4(), uuid4()
    try:
        with engine.begin() as conn:
            conn.execute(text('TRUNCATE auth_events, auth_sessions, login_buckets, users, roles CASCADE'))
            conn.execute(text("INSERT INTO roles VALUES ('migration-test-role')"))
            conn.execute(text("""INSERT INTO users (id,username,password_hash,status,role,password_change_required,mfa_required,mfa_enrolled)
                VALUES (:id,'migration-test-user','preserved-test-hash','active','migration-test-role',false,true,true)"""), {'id': user_id})
            conn.execute(text("INSERT INTO mfa_credentials (id,user_id,secret_ciphertext,failed_attempts) VALUES (:id,:user,'test-ciphertext',0)"), {'id': credential_id, 'user': user_id})
            conn.execute(text("""INSERT INTO auth_sessions (token_hash,csrf_hash,user_id,expires_at,mfa_credential_id)
                VALUES (:token,:csrf,:user,now()+interval '20 minutes',:credential)"""),
                {'token': 'a'*64, 'csrf': 'b'*64, 'user': user_id, 'credential': credential_id})
            conn.execute(text("""INSERT INTO mfa_challenges VALUES (:token,:user,:credential,:fingerprint,now()+interval '5 minutes',false,'test')"""),
                {'token': 'c'*64, 'user': user_id, 'credential': credential_id, 'fingerprint': 'd'*64})
            conn.execute(text("INSERT INTO auth_events (id,user_id,reason,client_key) VALUES (:id,:user,'mfa_verified',:key)"),
                {'id': event_id, 'user': user_id, 'key': 'e'*64})
            conn.execute(text("""INSERT INTO password_change_challenges VALUES (:token,:user,:fingerprint,now()+interval '5 minutes',false,'test')"""),
                {'token': 'f'*64, 'user': user_id, 'fingerprint': 'd'*64})
        command.upgrade(config, 'head')
        with engine.connect() as conn:
            schema = inspect(conn)
            assert 'mfa_credentials' not in schema.get_table_names()
            assert 'mfa_challenges' not in schema.get_table_names()
            assert not any(c['name'].startswith('mfa_') for c in schema.get_columns('users'))
            assert 'mfa_credential_id' not in {c['name'] for c in schema.get_columns('auth_sessions')}
            assert conn.execute(text('SELECT password_hash,status,role,password_change_required FROM users WHERE id=:id'), {'id': user_id}).one() == ('preserved-test-hash','active','migration-test-role',False)
            assert conn.execute(text('SELECT csrf_hash FROM auth_sessions')).scalar_one() == 'b'*64
            assert conn.execute(text('SELECT reason FROM auth_events WHERE id=:id'), {'id': event_id}).scalar_one() == 'mfa_verified'
            assert conn.execute(text('SELECT count(*) FROM password_change_challenges')).scalar_one() == 1
        command.downgrade(config, '0003')
        with engine.connect() as conn:
            assert conn.execute(text('SELECT count(*) FROM auth_sessions')).scalar_one() == 0
            assert conn.execute(text('SELECT mfa_required,mfa_enrolled FROM users WHERE id=:id'), {'id': user_id}).one() == (True,False)
            assert conn.execute(text('SELECT count(*) FROM mfa_credentials')).scalar_one() == 0
            assert conn.execute(text('SELECT count(*) FROM auth_events WHERE id=:id'), {'id': event_id}).scalar_one() == 1
    finally:
        command.upgrade(config, 'head')
        with engine.begin() as conn:
            conn.execute(text('TRUNCATE auth_events, auth_sessions, login_buckets, users, roles CASCADE'))
