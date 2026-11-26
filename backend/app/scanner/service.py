"""
VulnScanner — Scanner service interface (Phase 4 design contract).

This module defines the *interface* that Phase 4's real scanner
implementation must satisfy.  No scan is actually launched here —
the concrete implementation will be wired in once Phase 4.2 begins.

Key design decisions
--------------------
* **Protocol-based interface** — :class:`ScannerService` is a
  ``typing.Protocol`` so the real and stub implementations are
  structurally typed without inheritance.
* **Background execution** — the ``launch`` method returns a
  :class:`ScanJob` handle rather than blocking.  The caller is
  responsible for integrating this with FastAPI's background-task
  machinery (e.g. ``asyncio`` + ``concurrent.futures``).
* **No fake data** — stub implementations raise ``NotImplementedError``
  so accidental use during testing is obvious.
* **XML output** — Nmap is always invoked with ``-oX -`` so that
  structured XML can be parsed; human-readable text is never relied on.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable


# ── Scan job lifecycle ────────────────────────────────────────────────────────


class JobStatus(str, Enum):
    """Mirrors the ``status`` column of the ``scans`` table."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanJob:
    """
    Handle returned by :meth:`ScannerService.launch`.

    The job ID is set to the database scan UUID so the backend can
    correlate progress updates back to the correct ``scans`` row.
    """

    scan_id: uuid.UUID
    """Database primary key of the associated ``scans`` row."""

    target: str
    """Normalised target that was validated before launch."""

    status: JobStatus = JobStatus.QUEUED
    """Current lifecycle state of the background job."""

    progress: int = 0
    """Integer 0–100 representing completion percentage."""

    error_message: str = ""
    """Non-empty when status is FAILED; describes what went wrong."""

    xml_output: str = ""
    """Raw Nmap XML (``-oX -``) captured from stdout on completion."""

    def is_terminal(self) -> bool:
        """Return True once the job can no longer transition to another state."""
        return self.status in (
            JobStatus.COMPLETED,
            JobStatus.FAILED,
            JobStatus.CANCELLED,
        )


# ── Scanner service protocol ──────────────────────────────────────────────────


@runtime_checkable
class ScannerService(Protocol):
    """
    Structural interface that every scanner backend must satisfy.

    Implementations
    ---------------
    * ``NmapScannerService`` (Phase 4.2) — real implementation using
      the located Nmap binary.
    * ``StubScannerService`` (Phase 4.1) — safe no-op used during
      environment-verification phase; raises ``NotImplementedError``
      if ``launch`` is called.

    Safety invariants
    -----------------
    * ``launch`` MUST validate the target against an authorised-target
      list before spawning any subprocess.
    * ``launch`` MUST enforce ``scan_timeout_seconds`` to prevent
      runaway processes.
    * No ``shell=True`` MAY be used anywhere in the subprocess call.
    * ``-oX -`` MUST be included in the Nmap argument list so output
      is always structured XML, never free-form text.
    * Aggressive flags (``-A``, ``--script vuln``, ``--script exploit``,
      etc.) are forbidden until explicitly reviewed and authorised.
    """

    def launch(
        self,
        scan_id: uuid.UUID,
        target: str,
        scan_type: str,
        *,
        scan_timeout_seconds: int = 300,
    ) -> ScanJob:
        """
        Validate *target*, build Nmap arguments, and start a background job.

        This method must NOT block — it should enqueue work and return
        a :class:`ScanJob` handle immediately.

        Args:
            scan_id: The UUID of the ``scans`` row to update.
            target: Validated IP address, hostname, or CIDR range.
            scan_type: One of the :class:`~app.schemas.scan.ScanType` values.
            scan_timeout_seconds: Hard upper bound for the Nmap subprocess.

        Returns:
            A :class:`ScanJob` in ``QUEUED`` status.

        Raises:
            TargetNotAuthorisedError: If *target* is not in the allow-list.
            NmapNotAvailableError: If no working Nmap binary was found.
        """
        ...

    def cancel(self, scan_id: uuid.UUID) -> None:
        """
        Request cancellation of a running job.

        Implementations should send SIGTERM (Unix) or TerminateProcess
        (Windows) to the underlying Nmap subprocess.  This method is
        idempotent — calling it on a terminal job must not raise.

        Args:
            scan_id: The UUID of the scan to cancel.
        """
        ...

    def get_job(self, scan_id: uuid.UUID) -> ScanJob | None:
        """
        Return the current in-memory state of a job, or ``None`` if unknown.

        Args:
            scan_id: The UUID of the scan to query.
        """
        ...


# ── Domain exceptions ─────────────────────────────────────────────────────────


class ScannerError(Exception):
    """Base class for all scanner-layer exceptions."""


class NmapNotAvailableError(ScannerError):
    """Raised when no working Nmap binary can be found on the host."""


class TargetNotAuthorisedError(ScannerError):
    """Raised when the requested target is not in the authorised allow-list."""

    def __init__(self, target: str) -> None:
        super().__init__(
            f"Target {target!r} is not in the authorised allow-list. "
            "Add it explicitly before scanning."
        )
        self.target = target


# ── Stub implementation (Phase 4.1 only) ─────────────────────────────────────


class StubScannerService:
    """
    Safe no-op scanner used during Phase 4.1 environment verification.

    * ``launch`` raises ``NotImplementedError`` — prevents accidental
      real scans during the verification phase.
    * ``cancel`` and ``get_job`` are no-ops.
    """

    def launch(
        self,
        scan_id: uuid.UUID,
        target: str,
        scan_type: str,
        *,
        scan_timeout_seconds: int = 300,
    ) -> ScanJob:
        raise NotImplementedError(
            "StubScannerService.launch() must not be called during "
            "Phase 4.1 environment verification. Implement NmapScannerService "
            "in Phase 4.2 before attempting real scans."
        )

    def cancel(self, scan_id: uuid.UUID) -> None:  # noqa: D401
        """No-op: no process to cancel during Phase 4.1."""

    def get_job(self, scan_id: uuid.UUID) -> ScanJob | None:  # noqa: D401
        """No-op: no in-flight jobs during Phase 4.1."""
        return None
