from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from . import mfa_service
from .config import get_settings
from .database import get_db
from .routes import reply, trusted_origin
from .schemas import AuthResponse, MfaVerifyRequest

router = APIRouter(prefix='/api/v1/auth/mfa')


def result_response(status, result):
    response = JSONResponse(status_code=status, content=AuthResponse(**result).model_dump())
    if result.get('retry_after_seconds'):
        response.headers['Retry-After'] = str(result['retry_after_seconds'])
    return response


@router.get('/challenge', response_model=AuthResponse)
def status(request: Request, db: Session = Depends(get_db)):
    settings = get_settings()
    raw = request.cookies.get(settings.challenge_cookie_name)
    status, result = mfa_service.inspect(db, settings, raw)
    if raw and len(raw) <= 128:
        result['csrf_token'] = mfa_service.csrf_for(settings, raw)
    return result_response(status, result)


@router.post('/verify', response_model=AuthResponse)
def verify(body: MfaVerifyRequest, request: Request, db: Session = Depends(get_db)):
    if not trusted_origin(request):
        return reply(403, 'forbidden', 'Request could not be verified.')
    settings = get_settings()
    status, result, token = mfa_service.verify(db, settings, request.cookies.get(settings.challenge_cookie_name),
        request.headers.get('x-csrf-token', ''), body.code.get_secret_value(), request.client.host if request.client else 'unknown')
    response = result_response(status, result)
    if token:
        response.set_cookie(settings.cookie_name, token, httponly=True, secure=settings.cookie_secure,
                            samesite='strict', max_age=settings.session_seconds, path='/')
        response.delete_cookie(settings.challenge_cookie_name, path='/', secure=settings.cookie_secure,
                               httponly=True, samesite='strict')
    return response


@router.post('/cancel', response_model=AuthResponse)
def cancel(request: Request, db: Session = Depends(get_db)):
    if not trusted_origin(request):
        return reply(403, 'forbidden', 'Request could not be verified.')
    settings = get_settings()
    status, result = mfa_service.cancel(db, settings, request.cookies.get(settings.challenge_cookie_name),
        request.headers.get('x-csrf-token', ''), request.client.host if request.client else 'unknown')
    response = result_response(status, result)
    if status == 200:
        response.delete_cookie(settings.challenge_cookie_name, path='/', secure=settings.cookie_secure,
                               httponly=True, samesite='strict')
    return response
