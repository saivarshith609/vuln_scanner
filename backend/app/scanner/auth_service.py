"""
VulnScanner — Database-backed authorized target service.

Provides :class:`DbTargetAuthService` which queries the
``authorized_targets`` table to validate persistent target scopes and provides
the explicit-confirmation policy for single-target on-demand scans.

This replaces the in-memory :class:`TargetValidator` for production
use — the in-memory validator still handles syntax checking, while this
service performs database look-ups for authorization.

Policy note on hostname ↔ IP equivalence
-----------------------------------------
A hostname is only authorized by an exact hostname entry in the table.
A hostname that resolves to an authorized IP is **not** considered
authorized, and vice versa, because DNS resolution is subject to
spoofing, TOCTOU races, and split-horizon DNS.  This policy is explicit
and intentional.  Future phases may relax it with documented rationale.
"""

from __future__ import annotations

import ipaddress
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.authorized_target import AuthorizedTarget
from app.scanner.target_validator import TargetValidator

logger = logging.getLogger(__name__)

_syntax = TargetValidator()  # stateless; only used for syntax checking


class TargetNotAuthorizedError(Exception):
    """Raised when the target is not in the enabled authorized-target list."""

    def __init__(self, target: str) -> None:
        super().__init__(
            f"Target {target!r} is not in the authorized allow-list. "
            "Add and enable it via /api/v1/authorized-targets before scanning."
        )
        self.target = target


class OnDemandAuthorizationRequiredError(Exception):
    """Raised when an on-demand request lacks the operator's confirmation."""

    def __init__(self) -> None:
        super().__init__(
            "On-demand scanning requires explicit confirmation that the operator "
            "owns the target or has permission to test it."
        )


def normalize_target(target: str, *, allow_network: bool = True) -> str:
    """Validate and canonicalize one IP, CIDR network, or hostname."""
    t = target.strip()
    if not _syntax.is_syntactically_valid(t):
        raise ValueError(
            f"Target {t!r} is not a valid IP address, CIDR range, or hostname."
        )

    try:
        return str(ipaddress.ip_address(t))
    except (TypeError, ValueError):
        pass

    try:
        network = ipaddress.ip_network(t, strict=False)
    except ValueError:
        return t.lower()

    if not allow_network:
        raise ValueError(
            "On-demand scans accept one IP address or hostname only. "
            "Authorize CIDR ranges persistently before scanning them."
        )
    return str(network)


def validate_on_demand_target(target: str, authorization_confirmed: bool) -> str:
    """Authorize one validated target for this request after explicit consent."""
    if not authorization_confirmed:
        raise OnDemandAuthorizationRequiredError()
    return normalize_target(target, allow_network=False)


def validate_on_demand_discovery_authorization(authorization_confirmed: bool) -> None:
    """Require an authenticated operator's explicit one-time scope confirmation."""
    if not authorization_confirmed:
        raise OnDemandAuthorizationRequiredError()


def validate_target_authorized(
    target: str,
    db: Session,
    owner_user_id=None,
    is_admin: bool = True,
) -> str:
    """
    Check that *target* is syntactically valid and explicitly authorized.

    Args:
        target: The raw target string from the scan request.
        db: An active SQLAlchemy session (request-scoped or task-scoped).

    Returns:
        The normalized (stripped) target string.

    Raises:
        ValueError: Syntactically invalid target.
        TargetNotAuthorizedError: Not in the enabled authorized-target list.
    """
    t = normalize_target(target)

    # Load all enabled entries from DB
    stmt = select(AuthorizedTarget).where(AuthorizedTarget.is_enabled.is_(True))
    if not is_admin:
        stmt = stmt.where(AuthorizedTarget.owner_user_id == owner_user_id)
    entries = db.scalars(stmt).all()

    for entry in entries:
        if _matches(t, entry.target.strip()):
            logger.debug("Target %r authorized via entry %r.", t, entry.target)
            return t

    raise TargetNotAuthorizedError(t)


def normalize_discovery_cidr(target: str, max_addresses: int) -> tuple[str, int]:
    """Normalize a CIDR and enforce the configured discovery size bound."""
    raw = target.strip()
    if "/" not in raw:
        raise ValueError("CIDR discovery requires a prefix, for example 192.168.1.0/24.")
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise ValueError(f"Target {raw!r} is not a valid IPv4 or IPv6 CIDR network.") from exc
    if network.num_addresses > max_addresses:
        raise ValueError(
            f"Discovery scope contains {network.num_addresses:,} addresses; "
            f"the configured maximum is {max_addresses:,}."
        )
    return str(network), network.num_addresses


def normalize_ip_range(
    start_ip: str,
    end_ip: str,
    max_addresses: int,
) -> tuple[str, str, str, int, list[str]]:
    """Validate an inclusive IP range and return safe Nmap CIDR arguments."""
    try:
        start = ipaddress.ip_address(start_ip.strip())
        end = ipaddress.ip_address(end_ip.strip())
    except ValueError as exc:
        raise ValueError("IP ranges require valid start and end IP addresses.") from exc
    if start.version != end.version:
        raise ValueError("Range start and end addresses must use the same IP family.")
    if int(start) > int(end):
        raise ValueError("Range start address must not exceed the end address.")
    address_count = int(end) - int(start) + 1
    if address_count > max_addresses:
        raise ValueError(
            f"Discovery range contains {address_count:,} addresses; "
            f"the configured maximum is {max_addresses:,}."
        )
    cidrs = [str(network) for network in ipaddress.summarize_address_range(start, end)]
    return f"{start}-{end}", str(start), str(end), address_count, cidrs


def validate_range_authorized(
    start_ip: str,
    end_ip: str,
    db: Session,
    owner_user_id=None,
    is_admin: bool = True,
) -> None:
    """Require one enabled authorized scope to contain the complete range."""
    start = ipaddress.ip_address(start_ip)
    end = ipaddress.ip_address(end_ip)
    stmt = select(AuthorizedTarget).where(AuthorizedTarget.is_enabled.is_(True))
    if not is_admin:
        stmt = stmt.where(AuthorizedTarget.owner_user_id == owner_user_id)
    for entry in db.scalars(stmt).all():
        try:
            network = ipaddress.ip_network(entry.target.strip(), strict=False)
        except ValueError:
            continue
        if network.version == start.version and start in network and end in network:
            return
    raise TargetNotAuthorizedError(f"{start}-{end}")


def target_is_authorized(
    target: str,
    db: Session,
    owner_user_id=None,
    is_admin: bool = True,
) -> bool:
    """Return authorization status without weakening the raising validator."""
    try:
        validate_target_authorized(target, db, owner_user_id, is_admin)
        return True
    except (TargetNotAuthorizedError, ValueError):
        return False


def target_is_within_discovery_scope(
    target: str,
    target_kind: str,
    scope: str,
    range_start: str | None = None,
    range_end: str | None = None,
) -> bool:
    """Return whether one discovered IP belongs to the recorded discovery scope."""
    try:
        address = ipaddress.ip_address(target)
        if target_kind == "cidr":
            return address in ipaddress.ip_network(scope, strict=False)
        if target_kind == "range" and range_start and range_end:
            start = ipaddress.ip_address(range_start)
            end = ipaddress.ip_address(range_end)
            return address.version == start.version == end.version and int(start) <= int(address) <= int(end)
    except ValueError:
        return False
    return False


def _matches(target: str, auth_entry: str) -> bool:
    """
    Return True if *target* is covered by *auth_entry*.

    Matching rules (explicit, documented):
    1. Exact case-insensitive string match.
    2. If *auth_entry* is a CIDR and *target* is an IP contained within it.

    Hostname ↔ IP cross-matching is deliberately NOT performed.
    """
    if target.lower() == auth_entry.lower():
        return True

    # CIDR containment — only for IP targets
    try:
        network = ipaddress.ip_network(auth_entry, strict=False)
        try:
            return ipaddress.ip_address(target) in network
        except ValueError:
            target_network = ipaddress.ip_network(target, strict=False)
            return target_network.subnet_of(network)
    except (TypeError, ValueError):
        pass

    return False
