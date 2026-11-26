"""Single-operator API-key and server-side inactivity-session authentication."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Cookie, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.secrets import verify_api_key
from app.db.session import get_db
from app.models.platform_setting import OperatorSession, PlatformApiKey
from app.models.user import User

API_KEY_HEADER = "X-API-Key"
CSRF_COOKIE_NAME = "vulnscanner_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# The browser session policy is a five-minute idle timeout.  This is deliberately
# separate from any future absolute session lifetime policy.
SESSION_IDLE_TIMEOUT_MINUTES = 5


@dataclass(frozen=True)
class AuthenticatedOperator:
    method: str
    session_id: uuid.UUID | None = None
    user_id: uuid.UUID | None = None
    role: str = "admin"
    password_change_required: bool = False

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def _unauthorized(detail: str = "Authentication required") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "ApiKey"},
    )


def _valid_api_key_shape(raw_key: str) -> bool:
    return 40 <= len(raw_key) <= 200 and raw_key.startswith("vsec_live_") and raw_key[10:].isalnum()


def authenticate_api_key(db: Session, raw_key: str | None) -> bool:
    if raw_key is None or not _valid_api_key_shape(raw_key):
        return False
    stored = db.get(PlatformApiKey, 1)
    if stored is None:
        return False
    return verify_api_key(raw_key, stored.key_hash, stored.hash_salt)


def _token_digest(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _csrf_matches(operator_session: OperatorSession, raw_csrf: str | None) -> bool:
    """Return whether a readable CSRF cookie matches this server-side session."""
    if not raw_csrf or not operator_session.csrf_digest:
        return False
    return hmac.compare_digest(operator_session.csrf_digest, _token_digest(raw_csrf))


def _rotate_csrf_token(operator_session: OperatorSession) -> str:
    """Create a fresh CSRF token and retain only its digest server-side."""
    raw_csrf = secrets.token_urlsafe(32)
    operator_session.csrf_digest = _token_digest(raw_csrf)
    return raw_csrf


def _session_timeout_minutes(db: Session) -> int:
    # Keep the existing persisted setting available to the settings UI, but do
    # not allow it to weaken the security policy for authenticated sessions.
    # Every session creation and authenticated request therefore uses exactly
    # five minutes of sliding idle time.
    return SESSION_IDLE_TIMEOUT_MINUTES


def create_operator_session(db: Session, raw_api_key: str) -> tuple[str, OperatorSession, int]:
    if not authenticate_api_key(db, raw_api_key):
        raise _unauthorized("Invalid API key")
    raw_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    timeout_minutes = _session_timeout_minutes(db)
    raw_csrf = secrets.token_urlsafe(32)
    operator_session = OperatorSession(
        token_digest=_token_digest(raw_token),
        csrf_digest=_token_digest(raw_csrf),
        created_at=now,
        last_activity_at=now,
        expires_at=now + timedelta(minutes=timeout_minutes),
    )
    db.add(operator_session)
    db.commit()
    db.refresh(operator_session)
    operator_session._raw_csrf_token = raw_csrf
    return raw_token, operator_session, timeout_minutes


def create_user_session(db: Session, user: User) -> tuple[str, OperatorSession, int]:
    raw_token = secrets.token_urlsafe(32)
    raw_csrf = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    timeout_minutes = _session_timeout_minutes(db)
    operator_session = OperatorSession(
        token_digest=_token_digest(raw_token),
        csrf_digest=_token_digest(raw_csrf),
        user_id=user.id,
        created_at=now,
        last_activity_at=now,
        expires_at=now + timedelta(minutes=timeout_minutes),
    )
    db.add(operator_session)
    db.commit()
    db.refresh(operator_session)
    operator_session._raw_csrf_token = raw_csrf
    return raw_token, operator_session, timeout_minutes


def set_session_cookie(
    response: Response, raw_token: str, timeout_minutes: int, raw_csrf: str | None = None,
) -> None:
    settings = get_settings()
    if raw_csrf is not None:
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=raw_csrf,
            max_age=timeout_minutes * 60,
            httponly=False,
            secure=settings.SESSION_COOKIE_SECURE,
            samesite="strict",
            path="/",
        )
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=timeout_minutes * 60,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        httponly=False,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


def revoke_all_sessions(db: Session) -> None:
    now = datetime.now(timezone.utc)
    db.execute(
        update(OperatorSession)
        .where(OperatorSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )


def revoke_user_sessions(
    db: Session,
    user_id: uuid.UUID,
    *,
    exclude_session_id: uuid.UUID | None = None,
) -> int:
    """Revoke every live session for one user without exposing bearer material."""
    now = datetime.now(timezone.utc)
    statement = (
        update(OperatorSession)
        .where(
            OperatorSession.user_id == user_id,
            OperatorSession.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    if exclude_session_id is not None:
        statement = statement.where(OperatorSession.id != exclude_session_id)
    result = db.execute(statement)
    return int(result.rowcount or 0)


def revoke_operator_session(db: Session, raw_token: str | None) -> None:
    if raw_token is None:
        return
    operator_session = db.scalar(
        select(OperatorSession).where(OperatorSession.token_digest == _token_digest(raw_token))
    )
    if operator_session is not None and operator_session.revoked_at is None:
        operator_session.revoked_at = datetime.now(timezone.utc)
        db.commit()


def require_authentication(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    api_key: str | None = Header(default=None, alias=API_KEY_HEADER),
    session_token: str | None = Cookie(default=None, alias=get_settings().SESSION_COOKIE_NAME),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE_NAME),
    csrf_token: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> AuthenticatedOperator:
    if api_key is not None:
        if authenticate_api_key(db, api_key):
            return AuthenticatedOperator(method="api_key", role="admin")
        raise _unauthorized("Invalid API key")

    if session_token is None:
        raise _unauthorized()

    digest = _token_digest(session_token)
    operator_session = db.scalar(
        select(OperatorSession).where(OperatorSession.token_digest == digest)
    )
    if operator_session is None or not hmac.compare_digest(operator_session.token_digest, digest):
        raise _unauthorized("Invalid session")
    if operator_session.revoked_at is not None:
        raise _unauthorized("Session revoked")

    now = datetime.now(timezone.utc)
    last_activity_at = operator_session.last_activity_at
    if last_activity_at.tzinfo is None:
        last_activity_at = last_activity_at.replace(tzinfo=timezone.utc)
    expires_at = operator_session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    idle_expired = now - last_activity_at >= timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES)
    if idle_expired or now >= expires_at:
        operator_session.revoked_at = now
        db.commit()
        raise _unauthorized("Session expired")

    is_safe_method = request.method.upper() in SAFE_METHODS
    if not is_safe_method:
        if not csrf_token or not csrf_cookie or not _csrf_matches(operator_session, csrf_cookie):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
        if not hmac.compare_digest(csrf_cookie, csrf_token):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")

    # A safe authenticated request is the recovery point for sessions created
    # before CSRF digests existed and for browsers that lost/staled the readable
    # token cookie.  The token is never returned in JSON; it is reissued only as
    # a same-site cookie after the HttpOnly session has been validated.
    csrf_to_set = csrf_cookie if _csrf_matches(operator_session, csrf_cookie) else None
    if csrf_to_set is None:
        csrf_to_set = _rotate_csrf_token(operator_session)

    role = "admin"
    password_change_required = False
    if operator_session.user_id is not None:
        user = db.get(User, operator_session.user_id)
        if user is None or not user.is_active:
            operator_session.revoked_at = now
            db.commit()
            raise _unauthorized("Account is disabled")
        role = user.role
        password_change_required = user.password_change_required
        allowed_during_forced_change = {
            "/api/v1/auth/session",
            "/api/v1/auth/change-password",
            "/api/v1/auth/logout",
        }
        if password_change_required and request.url.path not in allowed_during_forced_change:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Password change required",
            )

    timeout_minutes = _session_timeout_minutes(db)
    operator_session.last_activity_at = now
    operator_session.expires_at = now + timedelta(minutes=timeout_minutes)
    db.commit()
    set_session_cookie(response, session_token, timeout_minutes, csrf_to_set)
    return AuthenticatedOperator(
        method="session",
        session_id=operator_session.id,
        user_id=operator_session.user_id,
        role=role,
        password_change_required=password_change_required,
    )


def require_admin(operator: AuthenticatedOperator = Depends(require_authentication)) -> AuthenticatedOperator:
    if not operator.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator access required")
    return operator


def owner_is_accessible(operator: AuthenticatedOperator, owner_user_id: uuid.UUID | None) -> bool:
    """Legacy unowned rows are visible only to explicit administrators."""
    return operator.is_admin or (operator.user_id is not None and owner_user_id == operator.user_id)


def require_owner(operator: AuthenticatedOperator, owner_user_id: uuid.UUID | None) -> None:
    if not owner_is_accessible(operator, owner_user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
