from datetime import datetime, timezone
import hmac

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db
from .models import AuthSession, MfaCredential, User
from .schemas import AuthResponse, LoginRequest
from .security import can_activate, digest
from .service import authenticate, audit

router = APIRouter(prefix='/api/v1/auth')


def reply(status, state, message):
    return JSONResponse(status_code=status, content=AuthResponse(state=state, message=message).model_dump())


def trusted_origin(request):
    # Required even on login (login-CSRF); same-origin Vite proxy in development.
    return request.headers.get('origin') == get_settings().public_origin


@router.post('/login', response_model=AuthResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    settings = get_settings()
    if not trusted_origin(request):
        return reply(403, 'forbidden', 'Request could not be verified.')
    status, result, token = authenticate(db, settings, body.username, body.password.get_secret_value(),
                                       request.client.host if request.client else 'unknown',
                                       request.cookies.get(settings.cookie_name))
    pending = result.pop('_pending_token', None)
    response = JSONResponse(status_code=status, content=AuthResponse(**result).model_dump())
    if pending:
        response.set_cookie(settings.challenge_cookie_name, pending, httponly=True, secure=settings.cookie_secure,
                            samesite='strict', max_age=300, path='/')
    if token:
        response.set_cookie(settings.cookie_name, token, httponly=True, secure=settings.cookie_secure,
                            samesite='strict', max_age=settings.session_seconds, path='/')
    if status == 429:
        response.headers['Retry-After'] = str(settings.rate_window_seconds)
    return response


def current_session(request, db):
    token = request.cookies.get(get_settings().cookie_name)
    session = db.get(AuthSession, digest(token)) if token and len(token) <= 128 else None
    if session is None:
        return None, None
    if session.expires_at <= datetime.now(timezone.utc):
        return session, None
    user = db.get(User, session.user_id)
    # Gates are rechecked on every request, so changed policy invalidates old sessions.
    credential = db.get(MfaCredential, session.mfa_credential_id) if session.mfa_credential_id else None
    from .mfa_service import development_enabled
    mfa_verified = bool(user and credential and credential.user_id == user.id and development_enabled(get_settings(), user))
    if user is None or not can_activate(user, mfa_verified=mfa_verified):
        return None, None
    return session, user


@router.get('/session', response_model=AuthResponse)
def session_status(request: Request, db: Session = Depends(get_db)):
    session, user = current_session(request, db)
    if not user:
        if session is not None and session.expires_at <= datetime.now(timezone.utc):
            response = reply(401, 'session_expired', 'Your session has ended. Sign in again to continue.')
            response.delete_cookie(get_settings().cookie_name, path='/', secure=get_settings().cookie_secure,
                                   httponly=True, samesite='strict')
            return response
        return reply(401, 'unauthenticated', 'Authentication required.')
    return AuthResponse(state='authenticated', message='Authentication complete.')


@router.post('/logout', response_model=AuthResponse)
def logout(request: Request, db: Session = Depends(get_db)):
    session, user = current_session(request, db)
    if not user:
        return reply(401, 'unauthenticated', 'Authentication required.')
    supplied = request.headers.get('x-csrf-token', '')
    if not trusted_origin(request) or not hmac.compare_digest(session.csrf_hash, digest(supplied)):
        return reply(403, 'forbidden', 'Request could not be verified.')
    db.delete(session)
    audit(db, 'logout', '0' * 64, user)
    db.commit()
    response = reply(200, 'unauthenticated', 'Signed out.')
    response.delete_cookie(get_settings().cookie_name, path='/', secure=get_settings().cookie_secure,
                           httponly=True, samesite='strict')
    return response
