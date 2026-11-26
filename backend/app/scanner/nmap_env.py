"""
VulnScanner — Nmap environment detection.

Probes the host for a working Nmap installation **without** running any
scan.  The only subprocess invoked is ``nmap --version``, which is
completely safe (no network traffic, no privilege escalation).

Usage::

    env = NmapEnvironment.detect()
    if env.is_available:
        print(env.version_string)

This module is intentionally free of FastAPI or SQLAlchemy imports so
that it can be exercised in unit tests without spinning up the full
application stack.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Well-known Windows installation locations ─────────────────────────────────
_WINDOWS_CANDIDATE_PATHS: list[str] = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]

# Timeout (seconds) for the version-check subprocess.
_VERSION_CHECK_TIMEOUT: int = 10


@dataclass(frozen=True)
class NmapEnvironment:
    """Immutable snapshot of the detected Nmap installation."""

    executable: str | None
    """Absolute path to the nmap binary, or ``None`` if not found."""

    version_string: str
    """The first line of ``nmap --version`` output, or an empty string."""

    is_available: bool
    """``True`` when the binary was found *and* the version check succeeded."""

    error: str
    """Human-readable error message when ``is_available`` is ``False``."""

    probe_candidates: list[str] = field(default_factory=list)
    """All locations that were checked, in order."""

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def detect(
        cls,
        extra_candidates: list[str] | None = None,
        timeout: int = _VERSION_CHECK_TIMEOUT,
    ) -> "NmapEnvironment":
        """Locate Nmap and verify it is executable.

        Search order:
        1. ``PATH`` (via :func:`shutil.which`).
        2. Known Windows installation directories.
        3. Any paths supplied via *extra_candidates*.

        Args:
            extra_candidates: Additional absolute paths to try.
            timeout: Seconds to wait for ``nmap --version`` before giving up.

        Returns:
            A populated :class:`NmapEnvironment` instance.
        """
        candidates: list[str] = []

        # 1. PATH lookup
        path_hit = shutil.which("nmap")
        if path_hit:
            candidates.append(path_hit)

        # 2. Hard-coded Windows locations
        for loc in _WINDOWS_CANDIDATE_PATHS:
            p = Path(loc)
            if p.is_file() and str(p) not in candidates:
                candidates.append(str(p))

        # 3. Caller-supplied extras
        for loc in extra_candidates or []:
            if loc not in candidates:
                candidates.append(loc)

        if not candidates:
            logger.warning("nmap not found in PATH or known installation locations.")
            return cls(
                executable=None,
                version_string="",
                is_available=False,
                error="nmap executable not found. Install Nmap from https://nmap.org/download.html",
                probe_candidates=candidates,
            )

        # Try each candidate in order
        for candidate in candidates:
            result = _run_version_check(candidate, timeout=timeout)
            if result is not None:
                first_line = result.splitlines()[0] if result.strip() else result
                logger.info("nmap available at %r — %s", candidate, first_line)
                return cls(
                    executable=candidate,
                    version_string=first_line,
                    is_available=True,
                    error="",
                    probe_candidates=candidates,
                )

        # All candidates failed
        error_msg = (
            f"nmap found at {candidates[0]!r} but version check failed. "
            "Ensure Nmap is correctly installed and the binary is not corrupted."
        )
        logger.error(error_msg)
        return cls(
            executable=candidates[0],
            version_string="",
            is_available=False,
            error=error_msg,
            probe_candidates=candidates,
        )

    def as_dict(self) -> dict[str, object]:
        """Serialisable summary suitable for API responses or logging."""
        return {
            "executable": self.executable,
            "version": self.version_string,
            "is_available": self.is_available,
            "error": self.error,
        }


# ── Internal helpers ──────────────────────────────────────────────────────────


def _run_version_check(executable: str, *, timeout: int) -> str | None:
    """Run ``<executable> --version`` safely.

    Uses an argument list (never ``shell=True``) to avoid shell injection.

    Returns:
        Combined stdout+stderr string on success, ``None`` on any failure.
    """
    try:
        proc = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            # Do NOT use shell=True — always pass an arg list.
            shell=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout
        # nmap sometimes writes version to stderr
        if proc.returncode == 0 and proc.stderr.strip():
            return proc.stderr
        logger.debug(
            "nmap version check returned code %d for %r",
            proc.returncode,
            executable,
        )
        return None
    except FileNotFoundError:
        logger.debug("Candidate %r does not exist.", executable)
        return None
    except PermissionError:
        logger.debug("Candidate %r is not executable (permission denied).", executable)
        return None
    except subprocess.TimeoutExpired:
        logger.warning("nmap --version timed out for %r after %ds.", executable, timeout)
        return None
    except OSError as exc:
        logger.debug("OSError running %r: %s", executable, exc)
        return None
