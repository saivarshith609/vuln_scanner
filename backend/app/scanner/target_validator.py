"""
VulnScanner — Scan target validation.

Provides :class:`TargetValidator`, a whitelist-based guard that MUST be
called before any target is passed to Nmap.

Design goals
------------
* Zero network I/O — all validation is purely local.
* Explicit allow-listing — targets are rejected unless they have been
  previously authorised.  No wildcard defaults.
* Format validation — even authorised targets are checked to be
  syntactically valid IP addresses, CIDR ranges, or hostnames.

This module is intentionally free of FastAPI / SQLAlchemy imports.
"""

from __future__ import annotations

import ipaddress
import logging
import re

logger = logging.getLogger(__name__)

# RFC 1123 hostname regex — allows labels of 1–63 alphanumeric chars or
# hyphens, not starting/ending with a hyphen, separated by dots.
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
    r"|"
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)


class TargetValidator:
    """
    Validates and authorises scan targets.

    Only targets explicitly added to *allow_list* will pass
    :meth:`validate`.  This is the primary defence against scanning
    unauthorised systems.

    Args:
        allow_list: Initial set of pre-authorised targets (IPs, CIDRs,
            or hostnames).  Callers may also call :meth:`add` at runtime.

    Example::

        validator = TargetValidator(allow_list={"192.168.1.0/24", "app.internal"})
        validator.validate("192.168.1.50")   # OK — falls inside the /24
        validator.validate("10.0.0.1")       # raises TargetNotAuthorisedError
    """

    def __init__(self, allow_list: set[str] | None = None) -> None:
        self._allow_list: set[str] = set(allow_list or [])

    # ── Public API ────────────────────────────────────────────────────────────

    def add(self, target: str) -> None:
        """Add *target* to the authorised allow-list."""
        self._allow_list.add(target.strip())

    def is_syntactically_valid(self, target: str) -> bool:
        """
        Return ``True`` if *target* is a syntactically valid IP, CIDR,
        or hostname.

        Does NOT check authorisation — use :meth:`validate` for that.
        """
        t = target.strip()
        if not t:
            return False
        # Try plain IP
        try:
            ipaddress.ip_address(t)
            return True
        except ValueError:
            pass
        # Try CIDR network
        try:
            ipaddress.ip_network(t, strict=False)
            return True
        except ValueError:
            pass
        # Try hostname
        return bool(_HOSTNAME_RE.match(t))

    def is_authorised(self, target: str) -> bool:
        """
        Return ``True`` if *target* is covered by any entry in the
        allow-list.

        Matching rules:
        * Exact string match (case-insensitive for hostnames, exact for IPs).
        * If an allow-list entry is a CIDR range, any IP that falls inside
          the range is considered authorised.
        """
        t = target.strip()
        for entry in self._allow_list:
            entry = entry.strip()
            if entry.lower() == t.lower():
                return True
            # Check if entry is a network and target is an IP within it
            try:
                network = ipaddress.ip_network(entry, strict=False)
                addr = ipaddress.ip_address(t)
                if addr in network:
                    return True
            except ValueError:
                pass
        return False

    def validate(self, target: str) -> str:
        """
        Validate *target* and return its stripped, canonical form.

        Args:
            target: The target string to validate.

        Returns:
            The stripped target string.

        Raises:
            ValueError: If *target* is syntactically invalid.
            TargetNotAuthorisedError: If *target* is not in the allow-list.
        """
        from app.scanner.service import TargetNotAuthorisedError  # local import

        t = target.strip()
        if not self.is_syntactically_valid(t):
            raise ValueError(
                f"Target {t!r} is not a valid IP address, CIDR range, or hostname."
            )
        if not self.is_authorised(t):
            raise TargetNotAuthorisedError(t)
        logger.debug("Target %r validated and authorised.", t)
        return t

    @property
    def allow_list(self) -> frozenset[str]:
        """Read-only view of the current allow-list."""
        return frozenset(self._allow_list)
