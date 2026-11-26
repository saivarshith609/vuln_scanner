"""Administrator-only local commands for VulnScanner."""

import argparse
import getpass
import secrets

from sqlalchemy import or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.audit import add_audit_event
from app.core.auth import revoke_all_sessions, revoke_user_sessions
from app.core.passwords import hash_password
from app.core.secrets import hash_api_key, masked_hint
from app.db.session import get_session_factory
from app.models.audit_log import AuditLog
from app.models.platform_setting import PlatformApiKey
from app.models.user import User
from app.schemas.auth import RegisterRequest, validate_password_policy


def create_initial_administrator(
    db: Session,
    *,
    full_name: str,
    username: str,
    email: str,
    password: str,
) -> User:
    """Create the first database administrator through a trusted local workflow."""
    try:
        validated = RegisterRequest(
            full_name=full_name,
            username=username,
            email=email,
            password=password,
            confirm_password=password,
        )
    except ValueError as exc:
        messages = []
        for error in getattr(exc, "errors", lambda: [])():
            message = str(error.get("msg", "Invalid account details."))
            messages.append(message.removeprefix("Value error, "))
        raise ValueError("; ".join(messages) or "Invalid administrator account details.") from None

    # Serialize concurrent local bootstrap attempts on PostgreSQL so the
    # audit-backed one-time check and account insert remain one transaction.
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": 0x56554C4E41444D49})

    duplicate = db.scalar(
        select(User).where(or_(User.username == validated.username, User.email == validated.email))
    )
    if duplicate is not None:
        field = "username" if duplicate.username == validated.username else "email"
        raise RuntimeError(f"An account with that {field} already exists")

    prior_cli_provisioning = db.scalar(
        select(AuditLog.id).where(AuditLog.event_type == "admin.account_provisioned").limit(1)
    )
    if prior_cli_provisioning is not None:
        raise RuntimeError(
            "The one-time create-admin bootstrap has already been used; create additional administrators through an authorized admin workflow"
        )

    user = User(
        full_name=validated.full_name,
        username=validated.username,
        email=validated.email,
        password_hash=hash_password(password),
        role="admin",
        is_active=True,
    )
    try:
        db.add(user)
        db.flush()
        add_audit_event(
            db,
            "admin.account_provisioned",
            resource_type="user",
            resource_id=user.id,
            metadata={"username": user.username, "source": "local_cli"},
        )
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise RuntimeError("An account with that username or email already exists") from None
    except Exception:
        db.rollback()
        raise
    return user


def reset_administrator_password(
    db: Session,
    *,
    identifier: str,
    password: str,
    confirmation: str,
) -> User:
    """Reset one existing database administrator through the trusted local CLI."""
    normalized_identifier = identifier.strip().lower()
    if not normalized_identifier:
        raise ValueError("An administrator username or email is required.")
    if password != confirmation:
        raise ValueError("Password confirmation does not match.")
    validated_password = validate_password_policy(password)

    user = db.scalar(
        select(User)
        .where(or_(User.username == normalized_identifier, User.email == normalized_identifier))
        .with_for_update()
    )
    if user is None:
        raise LookupError("No account matches the supplied administrator identifier.")
    if user.role != "admin":
        raise PermissionError("The supplied account is not an administrator.")

    try:
        user.password_hash = hash_password(validated_password)
        user.password_change_required = False
        user.version += 1
        sessions_revoked = revoke_user_sessions(db, user.id)
        add_audit_event(
            db,
            "admin.password_reset",
            resource_type="user",
            resource_id=user.id,
            metadata={
                "source": "local_cli",
                "username": user.username,
                "force_change_on_next_login": False,
                "sessions_revoked": sessions_revoked,
            },
        )
        db.commit()
        db.refresh(user)
    except Exception:
        db.rollback()
        raise
    return user


def provision_initial_api_key(db: Session) -> str:
    """Create the first API key, refusing to replace an existing verifier."""
    if db.get(PlatformApiKey, 1) is not None:
        raise RuntimeError("A platform API key already exists; regenerate it through the authenticated Settings API")
    raw_key = f"vsec_live_{secrets.token_hex(32)}"
    key_hash, salt = hash_api_key(raw_key)
    db.add(
        PlatformApiKey(
            id=1,
            key_hash=key_hash,
            hash_salt=salt,
            masked_hint=masked_hint(raw_key),
        )
    )
    db.commit()
    return raw_key


def rotate_platform_api_key(db: Session) -> str:
    """Rotate an existing platform key and revoke sessions atomically.

    The returned raw key exists only in process memory. Callers must not log or
    persist it and should disclose it only after this function returns.
    """
    record = db.get(PlatformApiKey, 1)
    if record is None:
        raise RuntimeError("No platform API key exists; run provision-api-key first")

    raw_key = f"vsec_live_{secrets.token_hex(32)}"
    try:
        key_hash, salt = hash_api_key(raw_key)
        record.key_hash = key_hash
        record.hash_salt = salt
        record.masked_hint = masked_hint(raw_key)
        revoke_all_sessions(db)
        db.commit()
    except Exception:
        db.rollback()
        raise

    return raw_key


def rotate_api_key_command() -> None:
    """Run the confirmed local administrative key-rotation workflow."""
    print("WARNING: This will replace the existing platform API key.")
    print("The old key will stop working and all existing operator sessions will be revoked.")
    print("Type ROTATE to continue, or anything else to cancel.")
    if input("Confirmation: ").strip() != "ROTATE":
        print("API-key rotation cancelled; no database changes were made.")
        return

    db = get_session_factory()()
    try:
        raw_key = rotate_platform_api_key(db)
        print("Platform API key rotated successfully. Existing sessions were revoked.")
        print("Copy this key now; it cannot be retrieved later:")
        print(raw_key)
    finally:
        db.close()


def create_admin_command() -> None:
    """Interactively create the first administrator without echoing credentials."""
    print("Create a dedicated VulnScanner database administrator.")
    print("This one-time bootstrap refuses to run after it has successfully created an account.")
    full_name = input("Full name: ").strip()
    username = input("Username: ").strip()
    email = input("Email: ").strip()
    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        print("Administrator was not created: password confirmation does not match.")
        return

    print(f"Requested administrator: {username.strip().lower()} ({email.strip().lower()})")
    if input("Type CREATE to continue: ").strip() != "CREATE":
        print("Administrator creation cancelled; no database changes were made.")
        return

    db = get_session_factory()()
    try:
        try:
            user = create_initial_administrator(
                db,
                full_name=full_name,
                username=username,
                email=email,
                password=password,
            )
        except (RuntimeError, ValueError) as exc:
            print(f"Administrator was not created: {exc}")
            raise SystemExit(1) from None
        print(f"Administrator account created for {user.username} ({user.email}).")
        print("The password was not printed or stored outside its Argon2id verifier.")
    finally:
        db.close()


def reset_admin_password_command(identifier: str) -> None:
    """Interactively replace one existing administrator's password."""
    normalized_identifier = identifier.strip().lower()
    confirmation_token = f"RESET {normalized_identifier}"
    print(f"This will replace the password for administrator identifier: {normalized_identifier}")
    print("The account, role, owned data, and audit history will be preserved.")
    if input(f"Type {confirmation_token} to continue: ").strip() != confirmation_token:
        print("Administrator password reset cancelled; no database changes were made.")
        return

    password = getpass.getpass("New password: ")
    password_confirmation = getpass.getpass("Confirm new password: ")
    db = get_session_factory()()
    try:
        try:
            user = reset_administrator_password(
                db,
                identifier=normalized_identifier,
                password=password,
                confirmation=password_confirmation,
            )
        except (LookupError, PermissionError, ValueError) as exc:
            print(f"Administrator password reset was not applied: {exc}")
            raise SystemExit(1) from None
        print(f"Administrator password reset successfully for {user.username}.")
        print("The new password was not printed or stored outside its Argon2id verifier.")
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="VulnScanner administrator commands")
    parser.add_argument("command", choices=["create-admin", "reset-admin-password", "provision-api-key", "rotate-api-key"])
    parser.add_argument("--identifier", help="Existing administrator username or email for reset-admin-password")
    args = parser.parse_args()
    if args.command == "create-admin":
        create_admin_command()
    elif args.command == "reset-admin-password":
        if not args.identifier:
            parser.error("reset-admin-password requires --identifier")
        reset_admin_password_command(args.identifier)
    elif args.command == "provision-api-key":
        db = get_session_factory()()
        try:
            raw_key = provision_initial_api_key(db)
            print("Initial API key created. Copy it now; it cannot be recovered:")
            print(raw_key)
        finally:
            db.close()
    elif args.command == "rotate-api-key":
        rotate_api_key_command()


if __name__ == "__main__":
    main()
