from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from . import password_service
from .config import get_settings
from .database import get_db
from .routes import reply, trusted_origin
from .schemas import AuthResponse, PasswordChangeRequest

router = APIRouter(prefix='/api/v1/auth/password')


@router.get('/challenge', response_model=AuthResponse)
def status(request: Request, db: Session = Depends(get_db)):
    settings = get_settings()
    status, result = password_service.inspect(db, settings, request.cookies.get(settings.password_cookie_name))
    return JSONResponse(status_code=status, content=AuthResponse(**result).model_dump())


@router.post('/change', response_model=AuthResponse)
def change(body: PasswordChangeRequest, request: Request, db: Session = Depends(get_db)):
    if not trusted_origin(request):
        return reply(403, 'forbidden', 'Request could not be verified.')
    settings = get_settings()
    status, result = password_service.change(db, settings, request.cookies.get(settings.password_cookie_name),
        request.headers.get('x-csrf-token', ''), body.new_password.get_secret_value(), body.confirmation.get_secret_value(),
        request.client.host if request.client else 'unknown')
    response = JSONResponse(status_code=status, content=AuthResponse(**result).model_dump())
    if result['state'] == 'password_changed':
        for name in (settings.password_cookie_name, settings.cookie_name):
            response.delete_cookie(name, path='/', secure=settings.cookie_secure, httponly=True, samesite='strict')
    if status == 429:
        response.headers['Retry-After'] = str(settings.rate_window_seconds)
    return response
