"""Persistent user accounts plus the existing API-key/session authentication flow."""

from datetime import datetime, timezone

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.auth import (
    API_KEY_HEADER,
    AuthenticatedOperator,
    clear_session_cookie,
    create_operator_session,
    create_user_session,
    require_authentication,
    revoke_operator_session,
    revoke_user_sessions,
    set_session_cookie,
)
from app.core.config import get_settings
from app.core.audit import add_audit_event
from app.core.passwords import hash_password, verify_password
from app.db.session import get_db
from app.models.platform_setting import OperatorSession
from app.models.user import User
from app.schemas.admin import ChangePasswordRequest
from app.schemas.auth import LoginRequest, RegisterRequest, SessionResponse, UserResponse

router = APIRouter()


def _safe_user(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        full_name=user.full_name,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        credential_change_required=user.password_change_required,
    )


def _admin_profile() -> UserResponse:
    return UserResponse(
        id=None,
        full_name="Platform Administrator",
        username="platform-admin",
        email="",
        role="admin",
        is_active=True,
    )


def _authenticate_user_credentials(
    payload: LoginRequest,
    request: Request,
    db: Session,
    *,
    required_role: str,
    current_token: str | None = None,
    response: Response | None = None,
) -> User:
    """Verify a database account before any session is created."""
    administrator_only = required_role == "admin"
    login_scope = "administrator" if administrator_only else "account"
    user = db.scalar(
        select(User).where(or_(User.username == payload.identifier, User.email == payload.identifier))
    )
    if user is None or not verify_password(payload.password, user.password_hash):
        add_audit_event(
            db,
            "auth.login_failed",
            outcome="failure",
            resource_type="authentication",
            ip_address=request.client.host if request.client else None,
            metadata={
                "identifier": payload.identifier,
                "login_scope": login_scope,
            },
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username/email or password.")

    if not user.is_active:
        add_audit_event(
            db,
            "auth.login_failed",
            actor_user_id=user.id,
            outcome="failure",
            resource_type="user",
            resource_id=user.id,
            ip_address=request.client.host if request.client else None,
            metadata={
                "reason": "account_disabled",
                "login_scope": login_scope,
            },
        )
        db.commit()
        detail = "Administrator account is inactive." if administrator_only else "Invalid username/email or password."
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN if administrator_only else status.HTTP_401_UNAUTHORIZED, detail=detail)

    if user.role != required_role:
        # A rejected role-specific login must not leave a previously-issued
        # privileged browser session usable while the person is redirected to
        # the appropriate sign-in form.
        revoke_operator_session(db, current_token)
        if response is not None:
            clear_session_cookie(response)
        add_audit_event(
            db,
            "auth.login_failed",
            actor_user_id=user.id,
            outcome="failure",
            resource_type="user",
            resource_id=user.id,
            ip_address=request.client.host if request.client else None,
            metadata={
                "reason": "administrator_role_required" if administrator_only else "user_role_required",
                "login_scope": login_scope,
            },
        )
        db.commit()
        detail = (
            "Administrator privileges are required."
            if administrator_only
            else "Use the administrator sign-in form for this account."
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

    return user


def _create_database_session(
    user: User,
    response: Response,
    request: Request,
    current_token: str | None,
    db: Session,
    *,
    login_scope: str,
) -> SessionResponse:
    revoke_operator_session(db, current_token)
    raw_token, operator_session, timeout_minutes = create_user_session(db, user)
    user.last_login_at = datetime.now(timezone.utc)
    add_audit_event(
        db,
        "auth.login_succeeded",
        actor_user_id=user.id,
        resource_type="user",
        resource_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata={"login_scope": login_scope},
    )
    db.commit()
    set_session_cookie(
        response,
        raw_token,
        timeout_minutes,
        getattr(operator_session, "_raw_csrf_token", None),
    )
    return SessionResponse(
        authenticated=True,
        method="session",
        expires_at=operator_session.expires_at,
        user=_safe_user(user),
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> UserResponse:
    duplicate = db.scalar(
        select(User).where(or_(User.username == payload.username, User.email == payload.email))
    )
    if duplicate is not None:
        field = "username" if duplicate.username == payload.username else "email"
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"An account with that {field} already exists.")

    user = User(
        full_name=payload.full_name,
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role="user",
        is_active=True,
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
        add_audit_event(
            db,
            "user.registered",
            actor_user_id=user.id,
            resource_type="user",
            resource_id=user.id,
            metadata={"username": user.username},
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with that username or email already exists.") from None
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Account registration is temporarily unavailable.") from None
    return _safe_user(user)


@router.post("/login", response_model=SessionResponse)
def login(
    payload: LoginRequest,
    response: Response,
    request: Request,
    current_token: str | None = Cookie(default=None, alias=get_settings().SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> SessionResponse:
    user = _authenticate_user_credentials(
        payload,
        request,
        db,
        required_role="user",
        current_token=current_token,
        response=response,
    )
    return _create_database_session(
        user, response, request, current_token, db, login_scope="account",
    )


@router.post("/admin/login", response_model=SessionResponse)
def admin_login(
    payload: LoginRequest,
    response: Response,
    request: Request,
    current_token: str | None = Cookie(default=None, alias=get_settings().SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> SessionResponse:
    """Create a normal server-managed session only for an active database administrator."""
    user = _authenticate_user_credentials(
        payload,
        request,
        db,
        required_role="admin",
        current_token=current_token,
        response=response,
    )
    return _create_database_session(
        user, response, request, current_token, db, login_scope="administrator",
    )


@router.post("/session", response_model=SessionResponse)
def start_session(
    response: Response,
    api_key: str | None = Header(default=None, alias=API_KEY_HEADER),
    db: Session = Depends(get_db),
) -> SessionResponse:
    raw_token, operator_session, timeout_minutes = create_operator_session(db, api_key or "")
    set_session_cookie(
        response,
        raw_token,
        timeout_minutes,
        getattr(operator_session, "_raw_csrf_token", None),
    )
    return SessionResponse(
        authenticated=True,
        method="session",
        expires_at=operator_session.expires_at,
        user=_admin_profile(),
    )


@router.get("/session", response_model=SessionResponse)
def session_status(
    operator: AuthenticatedOperator = Depends(require_authentication),
    db: Session = Depends(get_db),
) -> SessionResponse:
    expires_at: datetime | None = None
    if operator.session_id is not None:
        operator_session = db.get(OperatorSession, operator.session_id)
        expires_at = operator_session.expires_at if operator_session else None
    user = db.get(User, operator.user_id) if operator.user_id else None
    return SessionResponse(
        authenticated=True,
        method=operator.method,
        expires_at=expires_at,
        user=_safe_user(user) if user else _admin_profile(),
    )


def _end_session(response: Response, session_token: str | None, db: Session) -> Response:
    revoke_operator_session(db, session_token)
    clear_session_cookie(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
def end_session(
    response: Response,
    session_token: str | None = Cookie(default=None, alias=get_settings().SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> Response:
    return _end_session(response, session_token, db)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    _operator: AuthenticatedOperator = Depends(require_authentication),
    session_token: str | None = Cookie(default=None, alias=get_settings().SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> Response:
    return _end_session(response, session_token, db)


@router.post("/change-password")
def change_password(
    payload: ChangePasswordRequest,
    response: Response,
    operator: AuthenticatedOperator = Depends(require_authentication),
    session_token: str | None = Cookie(default=None, alias=get_settings().SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    if operator.user_id is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="API-key administrators do not have a user password.")
    user = db.get(User, operator.user_id)
    if user is None or not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect.")
    user.password_hash = hash_password(payload.new_password)
    user.password_change_required = False
    user.version += 1
    revoke_user_sessions(db, user.id)
    add_audit_event(
        db,
        "credential.password_changed",
        actor_user_id=user.id,
        resource_type="user",
        resource_id=user.id,
    )
    db.commit()
    clear_session_cookie(response)
    return {"changed": True, "reauthentication_required": True}
