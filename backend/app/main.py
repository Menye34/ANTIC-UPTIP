import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException
from sqlalchemy.exc import SQLAlchemyError

from .config import get_settings
from .middleware import BodyLimitMiddleware
from .routes import reply, router


def create_app():
    get_settings()  # Fail closed at startup on missing/unsafe configuration.
    app = FastAPI(title='UPTIP Authentication', docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(router)
    from .password_routes import router as password_router
    app.include_router(password_router)
    app.add_middleware(BodyLimitMiddleware)

    @app.middleware('http')
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # FastAPI's default validation response includes submitted input; never echo passwords.
        return reply(422, 'invalid_request', 'Invalid authentication request.')

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        return reply(exc.status_code, 'invalid_request', 'Request could not be processed.')

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request, exc):
        logging.getLogger('uptip.auth').error('authentication_database_unavailable')
        return reply(503, 'unavailable', 'Sign-in is temporarily unavailable. Please try again.')

    return app
