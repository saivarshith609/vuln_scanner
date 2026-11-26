"""
VulnScanner — Real Nmap scanning engine (Phase 4.2).

Architecture
------------
``NmapScannerService`` manages a registry of in-flight asyncio Tasks,
each running a single ``asyncio.create_subprocess_exec`` call.  This
gives us:

* Non-blocking event loop — subprocess is awaited in a dedicated Task.
* Direct process handle — cancellation sends SIGTERM/TerminateProcess
  directly to the Nmap PID without going through a thread pool.
* Independent DB sessions — each task opens its own session so that
  request-scoped sessions are never shared across threads or tasks.

Scan lifecycle
--------------
queued → running → {completed | failed | cancelled}

Safety invariants
-----------------
* ``shell=False`` everywhere — args passed as a list.
* Forbidden flag set is checked before launch; rejected with an exception.
* Output is bounded to ``max_output_bytes``; excess raises an error and
  marks the scan failed.
* Timeout is enforced via ``asyncio.wait_for``.
* On cancellation the process receives ``terminate()``; we then wait up
  to 5 s before calling ``kill()``.
* Cleanup of task registry entries happens in ``_finalize``.
* No automatic scan launch; the background task must be explicitly
  triggered by the route handler.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
import traceback
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.audit import add_audit_event
from app.db.session import get_session_factory
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.scan_result import ScanResult
from app.scanner.auth_service import OnDemandAuthorizationRequiredError, TargetNotAuthorizedError
from app.scanner.nmap_env import NmapEnvironment
from app.scanner.service import (
    JobStatus,
    NmapNotAvailableError,
    ScanJob,
    ScannerService,
    TargetNotAuthorisedError,
)
from app.scanner.xml_parser import (
    NmapXmlError,
    NmapXmlParseError,
    NmapXmlTooLargeError,
    parse_nmap_xml,
)

logger = logging.getLogger(__name__)

# ── Forbidden flag prefixes ───────────────────────────────────────────────────
_FORBIDDEN_FLAGS: frozenset[str] = frozenset(
    [
        "-A",           # Aggressive (OS, version, script, traceroute)
        "--script",     # NSE scripts (vuln, exploit, etc.)
        "-sU",          # UDP scan (requires root; not needed here)
        "-O",           # OS detection
        "--osscan",
        "-f",           # Fragment packets (evasion)
        "-D",           # Decoy (evasion)
        "--spoof",
        "--proxies",
        "--badsum",     # Invalid TCP/IP checksums
        "--data",       # Arbitrary payload
        "--script-args",
        "-iL",          # Input from file (could scan arbitrary targets)
        "--exclude-ports",  # Could hide errors
    ]
)

# Nmap argument profiles — immutable, no arbitrary user input accepted
_SCAN_PROFILES: dict[str, list[str]] = {
    "quick":    ["-sV", "-T3", "-F", "-oX", "-"],
    "network":  ["-sn", "-oX", "-"],
    "full":     ["-sV", "-T3", "-p-", "-oX", "-"],
    # These types queue/record as-is but we map to 'quick' for now
    "web":      ["-sV", "-T3", "-F", "-oX", "-"],
    "api":      ["-sV", "-T3", "-F", "-oX", "-"],
    "compliance": ["-sV", "-T3", "-F", "-oX", "-"],
}

_CANCEL_WAIT_SECONDS = 5


class ManagedProcess:
    """
    Unified process wrapper that provides an asynchronous interface
    for either an asyncio.subprocess.Process or a synchronous subprocess.Popen.

    Supports cancellation, timeout, output capture, and termination regardless
    of whether the underlying event loop implements async subprocess transports.
    """

    def __init__(self, proc: Any) -> None:
        self._proc = proc
        comm_fn = getattr(proc, "communicate", None)
        self._is_async = asyncio.iscoroutinefunction(comm_fn)

    @property
    def pid(self) -> int:
        return self._proc.pid

    @property
    def returncode(self) -> int | None:
        return self._proc.returncode

    async def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
        if self._is_async:
            if timeout is not None:
                return await asyncio.wait_for(self._proc.communicate(), timeout=timeout)
            return await self._proc.communicate()
        else:
            try:
                return await asyncio.to_thread(self._proc.communicate, timeout=timeout)
            except subprocess.TimeoutExpired:
                raise asyncio.TimeoutError()

    async def wait(self) -> int:
        wait_fn = getattr(self._proc, "wait", None)
        if wait_fn is None:
            return 0
        if self._is_async:
            res = wait_fn()
            if asyncio.iscoroutine(res):
                return await res
            return res
        else:
            return await asyncio.to_thread(wait_fn)

    def terminate(self) -> None:
        try:
            self._proc.terminate()
        except (ProcessLookupError, Exception):
            pass

    def kill(self) -> None:
        try:
            self._proc.kill()
        except (ProcessLookupError, Exception):
            pass


class NmapScannerService:
    """
    Production Nmap scanner.

    Maintains a dict of ``{scan_id: asyncio.Task}`` for in-flight scans.
    All public methods are safe to call from FastAPI route handlers on
    the event loop thread.
    """

    def __init__(self) -> None:
        self._tasks: dict[uuid.UUID, asyncio.Task[None] | asyncio.Future[None]] = {}
        self._env: NmapEnvironment | None = None
        self._semaphore: asyncio.Semaphore | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._max_concurrent = 1
        self._rate_limit_per_minute = 100
        self._dispatch_times: deque[float] = deque()
        self._rate_lock = asyncio.Lock()

    # ── Initialization ────────────────────────────────────────────────────

    def initialize(self) -> None:
        """
        Detect Nmap and create the concurrency semaphore.

        Must be called once at application startup (inside the event loop).
        """
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None

        settings = get_settings()
        extra = [settings.NMAP_EXECUTABLE] if settings.NMAP_EXECUTABLE else None
        self._env = NmapEnvironment.detect(extra_candidates=extra)
        max_concurrent = max(1, settings.NMAP_MAX_CONCURRENT)
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._max_concurrent = max_concurrent
        self._rate_limit_per_minute = 100
        self._dispatch_times.clear()
        self._rate_lock = asyncio.Lock()

        if self._env.is_available:
            logger.info(
                "NmapScannerService initialized: %s — %s",
                self._env.executable,
                self._env.version_string,
            )
        else:
            logger.warning(
                "NmapScannerService: nmap not available — %s", self._env.error
            )

    # ── Public interface ──────────────────────────────────────────────────

    def launch(
        self,
        scan_id: uuid.UUID,
        target: str,
        scan_type: str,
        *,
        scan_timeout_seconds: int | None = None,
        max_concurrent: int | None = None,
        rate_limit_per_minute: int | None = None,
        target_args: list[str] | None = None,
        recheck_authorization: bool = False,
    ) -> ScanJob:
        """
        Schedule a background scan Task.

        Args:
            scan_id: UUID of the already-persisted ``scans`` row.
            target: Pre-validated target string.
            scan_type: One of the ScanType enum values.
            scan_timeout_seconds: Override the global timeout.

        Returns:
            A :class:`ScanJob` in QUEUED status.

        Raises:
            NmapNotAvailableError: Nmap not found/executable.
            TargetNotAuthorisedError: Target not authorized (programming error
                — should have been checked before calling launch).
            ValueError: Invalid scan_type or forbidden flags.
            RuntimeError: Duplicate launch or semaphore not ready.
        """
        if self._env is None or self._semaphore is None:
            raise RuntimeError(
                "NmapScannerService.initialize() must be called before launch()."
            )

        if not self._env.is_available:
            raise NmapNotAvailableError(self._env.error)

        if scan_id in self._tasks:
            raise RuntimeError(
                f"Scan {scan_id} is already running. Duplicate launch prevented."
            )

        if max_concurrent is not None or rate_limit_per_minute is not None:
            self.configure_limits(
                max_concurrent or self._max_concurrent,
                rate_limit_per_minute or self._rate_limit_per_minute,
            )

        args = self._build_args(target, scan_type, target_args=target_args)
        settings = get_settings()
        timeout = scan_timeout_seconds or settings.NMAP_TIMEOUT_SECONDS

        job = ScanJob(scan_id=scan_id, target=target, status=JobStatus.QUEUED)

        coro = self._run_scan(scan_id, target, args, timeout, recheck_authorization)

        scheduled = False
        try:
            current_loop = asyncio.get_running_loop()
            if current_loop.is_running():
                task = current_loop.create_task(coro, name=f"scan-{scan_id}")
                self._tasks[scan_id] = task
                task.add_done_callback(lambda _: self._tasks.pop(scan_id, None))
                scheduled = True
        except RuntimeError:
            pass

        if not scheduled and self._loop is not None and self._loop.is_running():
            fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
            self._tasks[scan_id] = fut
            fut.add_done_callback(lambda _: self._tasks.pop(scan_id, None))
            scheduled = True

        if not scheduled:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    task = loop.create_task(coro, name=f"scan-{scan_id}")
                    self._tasks[scan_id] = task
                    task.add_done_callback(lambda _: self._tasks.pop(scan_id, None))
                    scheduled = True
                else:
                    coro.close()
            except RuntimeError:
                coro.close()

        logger.info("Scan %s queued for target %r (%s).", scan_id, target, scan_type)
        return job

    @property
    def nmap_available(self) -> bool:
        return bool(self._env and self._env.is_available)

    @property
    def runtime_max_concurrent(self) -> int:
        return self._max_concurrent

    @property
    def runtime_rate_limit_per_minute(self) -> int:
        return self._rate_limit_per_minute

    def configure_limits(self, max_concurrent: int, rate_limit_per_minute: int) -> bool:
        """Apply dispatch limits immediately when no scan is currently active."""
        normalized_concurrent = max(1, max_concurrent)
        self._rate_limit_per_minute = max(1, rate_limit_per_minute)
        if normalized_concurrent == self._max_concurrent:
            return True
        if any(not task.done() for task in self._tasks.values()):
            return False
        self._semaphore = asyncio.Semaphore(normalized_concurrent)
        self._max_concurrent = normalized_concurrent
        return True

    async def _wait_for_rate_slot(self) -> None:
        """Enforce the configured rolling one-minute scan dispatch limit."""
        loop = asyncio.get_running_loop()
        async with self._rate_lock:
            while True:
                now = loop.time()
                cutoff = now - 60.0
                while self._dispatch_times and self._dispatch_times[0] <= cutoff:
                    self._dispatch_times.popleft()
                if len(self._dispatch_times) < self._rate_limit_per_minute:
                    self._dispatch_times.append(now)
                    return
                await asyncio.sleep(max(0.01, self._dispatch_times[0] + 60.0 - now))

    def cancel(self, scan_id: uuid.UUID) -> None:
        """
        Request cancellation of a running scan Task.

        The asyncio Task is cancelled, which in turn triggers
        ``asyncio.CancelledError`` inside ``_run_scan``, where we
        terminate the subprocess and update the DB record.
        """
        task = self._tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            logger.info("Cancellation requested for scan %s.", scan_id)

    def get_job(self, scan_id: uuid.UUID) -> ScanJob | None:
        """Return a lightweight status snapshot; None if not tracked."""
        task = self._tasks.get(scan_id)
        if task is None:
            return None
        if task.done():
            return None
        return ScanJob(scan_id=scan_id, target="", status=JobStatus.RUNNING)

    async def shutdown(self) -> None:
        """
        Cancel all in-flight tasks and wait for them to finish.

        Call this from the FastAPI lifespan shutdown hook.
        """
        if not self._tasks:
            return
        logger.info("Shutting down — cancelling %d in-flight scan(s).", len(self._tasks))
        for task in list(self._tasks.values()):
            task.cancel()
        tasks_to_gather = [t for t in self._tasks.values() if isinstance(t, asyncio.Task)]
        if tasks_to_gather:
            await asyncio.gather(*tasks_to_gather, return_exceptions=True)
        self._tasks.clear()

    # ── Argument construction ─────────────────────────────────────────────

    def _build_args(
        self,
        target: str,
        scan_type: str,
        *,
        target_args: list[str] | None = None,
    ) -> list[str]:
        """Build the full argument list for Nmap."""
        if self._env is None:
            raise NmapNotAvailableError("Nmap scanner has not been initialized.")
        if not self._env.is_available or not self._env.executable:
            raise NmapNotAvailableError(self._env.error or "Nmap executable is unavailable.")
        executable = self._env.executable

        profile = _SCAN_PROFILES.get(scan_type.lower())
        if profile is None:
            raise ValueError(
                f"Unsupported scan_type {scan_type!r}. "
                f"Allowed: {sorted(_SCAN_PROFILES.keys())}"
            )

        # Sanity-check the profile itself (defense in depth)
        for flag in profile:
            for forbidden in _FORBIDDEN_FLAGS:
                if flag.startswith(forbidden):
                    raise ValueError(
                        f"Profile contains forbidden flag {flag!r}. "
                        "This is an internal configuration error."
                    )

        safe_targets = target_args or [target]
        if not safe_targets or any(not value or value.startswith("-") for value in safe_targets):
            raise ValueError("Discovery produced an invalid Nmap target argument.")
        return [executable] + profile + safe_targets

    async def _spawn_process(self, args: list[str]) -> ManagedProcess:
        """
        Launch the Nmap subprocess safely.

        Attempts asyncio.create_subprocess_exec first. If the running event loop
        does not implement subprocess transports (specifically WindowsSelectorEventLoopPolicy,
        which Uvicorn uses on Windows when --reload is active), it gracefully falls back
        to subprocess.Popen with thread-backed communicate() to ensure the scan runs.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            return ManagedProcess(proc)
        except NotImplementedError:
            logger.info(
                "Event loop does not support asynchronous subprocesses "
                "(e.g. WindowsSelectorEventLoop on Windows); using managed Popen."
            )
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
            return ManagedProcess(proc)

    # ── Background task ───────────────────────────────────────────────────

    async def _run_scan(
        self,
        scan_id: uuid.UUID,
        target: str,
        args: list[str],
        timeout_seconds: int,
        recheck_authorization: bool = False,
    ) -> None:
        """
        The actual coroutine that runs Nmap and persists results.

        Opens its own SQLAlchemy session — never reuses the request session.
        Handles: success, failure, timeout, cancellation.
        """
        settings = get_settings()
        assert self._semaphore is not None

        process: ManagedProcess | None = None
        session: Session | None = None

        try:
            # ── Wait for an open slot ─────────────────────────────────────
            async with self._semaphore:
                await self._wait_for_rate_slot()
                session = get_session_factory()()
                try:
                    if recheck_authorization:
                        await self._recheck_authorization(session, scan_id)
                    await self._mark_running(session, scan_id)
                except (TargetNotAuthorizedError, OnDemandAuthorizationRequiredError, ValueError) as exc:
                    await self._mark_failed(
                        session, scan_id,
                        f"Authorization recheck failed before launch: {exc}",
                    )
                    return
                except Exception as exc:
                    logger.error(
                        "DB error marking scan %s running: %s\n%s",
                        scan_id, exc, traceback.format_exc(),
                    )
                    raise

                # ── Launch Nmap ───────────────────────────────────────────
                logger.info(
                    "Launching Nmap for scan %s: %s",
                    scan_id,
                    " ".join(args),
                )
                process = await self._spawn_process(args)

                # ── Read output with timeout ──────────────────────────────
                try:
                    stdout_bytes, stderr_bytes = await process.communicate(
                        timeout=timeout_seconds,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "Scan %s timed out after %ds — terminating Nmap.",
                        scan_id,
                        timeout_seconds,
                    )
                    await _terminate_process(process)
                    await self._mark_failed(
                        session,
                        scan_id,
                        f"Scan timed out after {timeout_seconds} seconds.",
                    )
                    return

                # ── Check output size ────────────────────────────────────
                max_bytes = settings.NMAP_MAX_OUTPUT_BYTES
                if len(stdout_bytes) > max_bytes:
                    await self._mark_failed(
                        session,
                        scan_id,
                        f"Nmap XML output too large ({len(stdout_bytes):,} bytes, "
                        f"limit {max_bytes:,}).",
                    )
                    return

                # ── Non-zero exit code ───────────────────────────────────
                if process.returncode != 0:
                    stderr_text = stderr_bytes.decode("utf-8", errors="replace")[:500]
                    logger.warning(
                        "Scan %s nmap exited with code %d. stderr: %s",
                        scan_id,
                        process.returncode,
                        stderr_text,
                    )
                    partial_count = 0
                    if stdout_bytes.strip():
                        try:
                            partial_summary = parse_nmap_xml(stdout_bytes, max_bytes=max_bytes)
                            partial_count = len(partial_summary.hosts)
                            if partial_count:
                                await self._persist_results(
                                    session, scan_id, partial_summary,
                                    mark_completed=False, partial=True,
                                )
                        except NmapXmlError:
                            logger.info("Nmap failure output for scan %s was not parseable XML.", scan_id)
                    safe_stderr = " ".join(stderr_text.split())[:300]
                    detail = f"Nmap exited with code {process.returncode}."
                    if safe_stderr:
                        detail += f" {safe_stderr}"
                    elif not partial_count:
                        detail += " Check Nmap privileges and target reachability."
                    if partial_count:
                        detail += f" {partial_count} partial host result(s) were preserved."
                    await self._mark_failed(session, scan_id, detail)
                    return

                # ── Parse XML ────────────────────────────────────────────
                try:
                    summary = parse_nmap_xml(stdout_bytes, max_bytes=max_bytes)
                except (NmapXmlTooLargeError, NmapXmlParseError) as exc:
                    await self._mark_failed(session, scan_id, str(exc))
                    return
                except NmapXmlError as exc:
                    await self._mark_failed(session, scan_id, f"XML parse error: {exc}")
                    return

                # ── Persist results ──────────────────────────────────────
                await self._persist_results(session, scan_id, summary)

        except asyncio.CancelledError:
            logger.info("Scan %s task cancelled.", scan_id)
            if process and process.returncode is None:
                await _terminate_process(process)
            if session:
                try:
                    await self._mark_cancelled_sync(session, scan_id)
                except Exception as exc:
                    logger.error(
                        "DB error marking scan %s cancelled: %s\n%s",
                        scan_id, exc, traceback.format_exc(),
                    )
            raise  # re-raise so the Task is properly cancelled

        except Exception as exc:
            logger.error(
                "Unexpected error in scan %s: %s\n%s",
                scan_id, exc, traceback.format_exc(),
            )
            if process and process.returncode is None:
                await _terminate_process(process)
            if session:
                try:
                    await self._mark_failed(
                        session,
                        scan_id,
                        "An unexpected internal error occurred during scanning.",
                    )
                except Exception as db_exc:
                    logger.error(
                        "DB error recording failure for scan %s: %s\n%s",
                        scan_id, db_exc, traceback.format_exc(),
                    )
        finally:
            if session:
                try:
                    session.close()
                except Exception:
                    pass

    # ── DB helpers (all sync — called from async context via direct call) ─

    async def _mark_running(self, session: Session, scan_id: uuid.UUID) -> None:
        """Transition scan to 'running' in the database."""
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise LookupError(f"Scan {scan_id} not found in database.")
        if scan.status != "queued":
            raise RuntimeError(
                f"Cannot start scan {scan_id}: current status is {scan.status!r}."
            )
        scan.status = "running"
        scan.progress = 10
        scan.started_at = datetime.now(timezone.utc)
        session.commit()

    async def _recheck_authorization(self, session: Session, scan_id: uuid.UUID) -> None:
        """Recheck persistent scope authorization immediately before Nmap starts."""
        from app.scanner.auth_service import (
            OnDemandAuthorizationRequiredError,
            normalize_discovery_cidr,
            normalize_ip_range,
            validate_on_demand_discovery_authorization,
            validate_on_demand_target,
            validate_range_authorized,
            validate_target_authorized,
        )

        scan = session.get(Scan, scan_id)
        if scan is None:
            raise LookupError(f"Scan {scan_id} not found in database.")
        if scan.authorization_mode == "on_demand":
            if scan.operation == "discovery":
                validate_on_demand_discovery_authorization(scan.authorization_confirmed)
                settings = get_settings()
                if scan.target_kind == "cidr":
                    normalized, _count = normalize_discovery_cidr(
                        scan.target, settings.DISCOVERY_MAX_ADDRESSES,
                    )
                elif scan.target_kind == "range" and scan.range_start and scan.range_end:
                    normalized, _start, _end, _count, _args = normalize_ip_range(
                        scan.range_start, scan.range_end, settings.DISCOVERY_MAX_ADDRESSES,
                    )
                else:
                    raise ValueError("On-demand discovery scope metadata is incomplete.")
                if normalized != scan.target:
                    raise ValueError("On-demand discovery scope metadata is inconsistent.")
            else:
                validate_on_demand_target(scan.target, scan.authorization_confirmed)
            return
        is_admin = scan.owner_user_id is None
        if scan.target_kind == "range":
            if not scan.range_start or not scan.range_end:
                raise ValueError("Discovery range metadata is incomplete.")
            validate_range_authorized(
                scan.range_start, scan.range_end, session,
                scan.owner_user_id, is_admin,
            )
        else:
            validate_target_authorized(scan.target, session, scan.owner_user_id, is_admin)

    async def _mark_failed(
        self, session: Session, scan_id: uuid.UUID, reason: str
    ) -> None:
        """Transition scan to 'failed' and record a safe error message."""
        try:
            scan = session.get(Scan, scan_id)
            if scan is None:
                logger.error("_mark_failed: scan %s not found.", scan_id)
                return
            scan.status = "failed"
            scan.progress = 0
            scan.error_message = reason
            scan.completed_at = datetime.now(timezone.utc)
            add_audit_event(
                session, "scan.failed", actor_user_id=scan.owner_user_id,
                resource_type=scan.operation, resource_id=scan.id,
                metadata={"reason": reason},
            )
            session.commit()
            logger.info("Scan %s marked failed: %s", scan_id, reason)
        except Exception as exc:
            logger.error("DB error marking scan %s failed: %s", scan_id, exc)
            session.rollback()

    async def _mark_cancelled_sync(
        self, session: Session, scan_id: uuid.UUID
    ) -> None:
        """Mark the scan cancelled after subprocess termination is confirmed."""
        try:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return
            if scan.status not in ("running", "queued"):
                return  # Already in terminal state
            scan.status = "cancelled"
            scan.error_message = "Cancelled by operator."
            scan.completed_at = datetime.now(timezone.utc)
            add_audit_event(
                session, "scan.cancelled", actor_user_id=scan.owner_user_id,
                resource_type=scan.operation, resource_id=scan.id,
            )
            session.commit()
            logger.info("Scan %s marked cancelled.", scan_id)
        except Exception as exc:
            logger.error("DB error marking scan %s cancelled: %s", scan_id, exc)
            session.rollback()

    async def _persist_results(
        self,
        session: Session,
        scan_id: uuid.UUID,
        summary: "NmapScanSummary",  # noqa: F821
        *,
        mark_completed: bool = True,
        partial: bool = False,
    ) -> None:
        """Write parsed host/port discoveries to ``scan_results`` table."""
        from app.scanner.xml_parser import NmapScanSummary  # local import

        result_rows: list[ScanResult] = []

        for host in summary.hosts:
            if host.state != "up":
                # Still record the host as a host-only row
                result_rows.append(
                    ScanResult(
                        id=uuid.uuid4(),
                        scan_id=scan_id,
                        host_address=host.address,
                        host_state=host.state,
                        hostname=host.hostname,
                        mac_address=host.mac_address,
                        vendor=host.vendor,
                    )
                )
                continue

            if not host.ports:
                # Host up but no open ports (e.g. network discovery scan)
                result_rows.append(
                    ScanResult(
                        id=uuid.uuid4(),
                        scan_id=scan_id,
                        host_address=host.address,
                        host_state=host.state,
                        hostname=host.hostname,
                        mac_address=host.mac_address,
                        vendor=host.vendor,
                    )
                )
            else:
                for port in host.ports:
                    result_rows.append(
                        ScanResult(
                            id=uuid.uuid4(),
                            scan_id=scan_id,
                            host_address=host.address,
                            host_state=host.state,
                            hostname=host.hostname,
                            mac_address=host.mac_address,
                            vendor=host.vendor,
                            port=port.portid,
                            protocol=port.protocol,
                            port_state=port.state,
                            service_name=port.service_name,
                            service_product=port.service_product,
                            service_version=port.service_version,
                            service_extra_info=port.service_extra_info,
                        )
                    )

        try:
            for row in result_rows:
                session.add(row)

            # Mark scan complete
            scan = session.get(Scan, scan_id)
            if scan:
                scan.partial_results = partial
                if mark_completed:
                    scan.status = "completed"
                    scan.progress = 100
                    scan.completed_at = datetime.now(timezone.utc)
                    add_audit_event(
                        session, "scan.completed", actor_user_id=scan.owner_user_id,
                        resource_type=scan.operation, resource_id=scan.id,
                        metadata={"result_rows": len(result_rows), "partial": partial},
                    )

                # Associate scan with matching asset or auto-ingest discovered host
                target_hosts = [h.address for h in summary.hosts if h.address]
                # A normal single-host scan can safely associate its requested
                # host when Nmap returns no host element. A discovery scope
                # cannot: doing so would fabricate a CIDR/range as a discovered
                # device and falsely imply a response.
                if not target_hosts and scan.target and scan.operation != "discovery":
                    target_hosts = [scan.target]

                for host_addr in target_hosts:
                    existing_asset = session.scalar(
                        select(Asset).where(
                            func.lower(Asset.target) == host_addr.lower(),
                            Asset.owner_user_id == scan.owner_user_id,
                        )
                    )
                    now_utc = datetime.now(timezone.utc)
                    if existing_asset:
                        existing_asset.updated_at = now_utc
                        if scan.asset_id is None:
                            scan.asset_id = existing_asset.id
                    else:
                        host_obj = next((h for h in summary.hosts if h.address == host_addr), None)
                        h_name = (host_obj.hostname if host_obj else None) or f"Host ({host_addr})"
                        new_asset = Asset(
                            id=uuid.uuid4(),
                            owner_user_id=scan.owner_user_id,
                            name=h_name,
                            target=host_addr,
                            asset_type="server",
                            description=f"Auto-discovered via scan {scan_id}",
                            created_at=now_utc,
                            updated_at=now_utc,
                        )
                        session.add(new_asset)
                        session.flush()
                        if scan.asset_id is None:
                            scan.asset_id = new_asset.id

            session.commit()
            logger.info(
                "Scan %s completed — %d result row(s) persisted.",
                scan_id,
                len(result_rows),
            )
        except Exception as exc:
            logger.error("DB error persisting results for scan %s: %s", scan_id, exc)
            session.rollback()
            await self._mark_failed(session, scan_id, "Failed to persist scan results.")


# ── Process termination helper ────────────────────────────────────────────────


async def _terminate_process(
    process: ManagedProcess | asyncio.subprocess.Process | subprocess.Popen,
) -> None:
    """
    Gracefully terminate *process*.

    Sends ``terminate()`` (SIGTERM on Unix, TerminateProcess on Windows)
    then waits up to ``_CANCEL_WAIT_SECONDS`` before calling ``kill()``.
    """
    try:
        process.terminate()
    except (ProcessLookupError, Exception):
        return  # Already finished

    async def _safe_wait() -> int:
        wait_fn = getattr(process, "wait", None)
        if wait_fn is not None:
            res = wait_fn()
            if asyncio.iscoroutine(res):
                return await res
            return await asyncio.to_thread(wait_fn)
        return 0

    try:
        await asyncio.wait_for(_safe_wait(), timeout=_CANCEL_WAIT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning(
            "Process %s did not terminate after %ds — killing it.",
            process.pid,
            _CANCEL_WAIT_SECONDS,
        )
        try:
            process.kill()
        except (ProcessLookupError, Exception):
            pass
        try:
            await asyncio.wait_for(_safe_wait(), timeout=2)
        except asyncio.TimeoutError:
            logger.error("Process %s could not be killed.", process.pid)


# ── Singleton ─────────────────────────────────────────────────────────────────

# Module-level singleton — wired into the FastAPI lifespan
scanner_service = NmapScannerService()
