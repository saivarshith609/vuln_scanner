"""
VulnScanner — Phase 4.1 scanner unit tests.

Covers:
- NmapEnvironment.detect(): executable discovery, version-check success
  and failure, PATH vs. hard-coded-path resolution.
- _run_version_check(): timeout, permission-denied, FileNotFoundError,
  and successful parse.
- StubScannerService: launch() raises NotImplementedError; cancel/get_job
  are safe no-ops.
- TargetValidator: syntax checks, allow-listing, CIDR containment, and
  the validate() guard.

All subprocess calls are mocked — no real Nmap process is spawned.
"""

from __future__ import annotations

import subprocess
import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.nmap_env import NmapEnvironment, _run_version_check
from app.scanner.service import (
    JobStatus,
    NmapNotAvailableError,
    ScanJob,
    ScannerService,
    StubScannerService,
    TargetNotAuthorisedError,
)
from app.scanner.target_validator import TargetValidator

# ── Helpers ───────────────────────────────────────────────────────────────────

NMAP_VERSION_OUTPUT = (
    "Nmap version 7.99 ( https://nmap.org )\n"
    "Platform: i686-pc-windows-windows\n"
)


def _make_proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    """Return a mock CompletedProcess-like object."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


# ── NmapEnvironment tests ─────────────────────────────────────────────────────


class TestNmapEnvironmentDetect:
    """Tests for NmapEnvironment.detect()."""

    def test_detect_via_path(self) -> None:
        """detect() finds nmap in PATH and runs version check successfully."""
        with (
            patch("app.scanner.nmap_env.shutil.which", return_value="/usr/bin/nmap"),
            patch("app.scanner.nmap_env.Path.is_file", return_value=False),
            patch(
                "app.scanner.nmap_env._run_version_check",
                return_value=NMAP_VERSION_OUTPUT,
            ) as mock_check,
        ):
            env = NmapEnvironment.detect()

        assert env.is_available is True
        assert env.executable == "/usr/bin/nmap"
        assert "7.99" in env.version_string
        assert env.error == ""
        mock_check.assert_called_once_with("/usr/bin/nmap", timeout=10)

    def test_detect_via_windows_hardcoded_path(self) -> None:
        """detect() falls back to hard-coded Windows path when not in PATH."""
        with (
            patch("app.scanner.nmap_env.shutil.which", return_value=None),
            patch("app.scanner.nmap_env.Path.is_file", return_value=True),
            patch(
                "app.scanner.nmap_env._run_version_check",
                return_value=NMAP_VERSION_OUTPUT,
            ),
        ):
            env = NmapEnvironment.detect()

        assert env.is_available is True
        assert env.executable is not None
        assert "nmap" in env.executable.lower()

    def test_detect_not_found_returns_unavailable(self) -> None:
        """detect() returns is_available=False when nmap cannot be found anywhere."""
        with (
            patch("app.scanner.nmap_env.shutil.which", return_value=None),
            patch("app.scanner.nmap_env.Path.is_file", return_value=False),
        ):
            env = NmapEnvironment.detect()

        assert env.is_available is False
        assert env.executable is None
        assert "not found" in env.error.lower()
        assert env.version_string == ""

    def test_detect_binary_exists_but_version_check_fails(self) -> None:
        """detect() returns is_available=False when version check fails."""
        with (
            patch("app.scanner.nmap_env.shutil.which", return_value="/usr/bin/nmap"),
            patch("app.scanner.nmap_env.Path.is_file", return_value=False),
            patch("app.scanner.nmap_env._run_version_check", return_value=None),
        ):
            env = NmapEnvironment.detect()

        assert env.is_available is False
        assert env.executable == "/usr/bin/nmap"
        assert "version check failed" in env.error.lower()

    def test_detect_extra_candidates_are_tried(self) -> None:
        """detect() uses extra_candidates when standard paths yield nothing."""
        extra = "/opt/custom/nmap"
        with (
            patch("app.scanner.nmap_env.shutil.which", return_value=None),
            patch("app.scanner.nmap_env.Path.is_file", return_value=False),
            patch(
                "app.scanner.nmap_env._run_version_check",
                return_value=NMAP_VERSION_OUTPUT,
            ) as mock_check,
        ):
            env = NmapEnvironment.detect(extra_candidates=[extra])

        assert env.is_available is True
        assert env.executable == extra
        mock_check.assert_called_once_with(extra, timeout=10)

    def test_detect_as_dict_schema(self) -> None:
        """as_dict() contains the required keys."""
        with (
            patch("app.scanner.nmap_env.shutil.which", return_value=None),
            patch("app.scanner.nmap_env.Path.is_file", return_value=False),
        ):
            env = NmapEnvironment.detect()

        d = env.as_dict()
        assert set(d.keys()) == {"executable", "version", "is_available", "error"}

    def test_detect_first_candidate_succeeds_rest_skipped(self) -> None:
        """detect() stops at the first candidate that passes the version check."""
        call_count = 0

        def mock_check(exe: str, *, timeout: int) -> str | None:
            nonlocal call_count
            call_count += 1
            return NMAP_VERSION_OUTPUT  # always succeed

        with (
            patch("app.scanner.nmap_env.shutil.which", return_value="/a/nmap"),
            patch("app.scanner.nmap_env.Path.is_file", return_value=True),
            patch("app.scanner.nmap_env._run_version_check", side_effect=mock_check),
        ):
            NmapEnvironment.detect()

        # Should stop after the first successful candidate
        assert call_count == 1


# ── _run_version_check tests ──────────────────────────────────────────────────


class TestRunVersionCheck:
    """Tests for the _run_version_check() helper."""

    def test_success_returns_stdout(self) -> None:
        """Returns stdout content when returncode is 0 and stdout is non-empty."""
        proc = _make_proc(returncode=0, stdout=NMAP_VERSION_OUTPUT, stderr="")
        with patch("app.scanner.nmap_env.subprocess.run", return_value=proc):
            result = _run_version_check("/usr/bin/nmap", timeout=10)
        assert result == NMAP_VERSION_OUTPUT

    def test_success_uses_stderr_fallback(self) -> None:
        """Returns stderr when returncode is 0 but stdout is empty."""
        proc = _make_proc(returncode=0, stdout="", stderr=NMAP_VERSION_OUTPUT)
        with patch("app.scanner.nmap_env.subprocess.run", return_value=proc):
            result = _run_version_check("/usr/bin/nmap", timeout=10)
        assert result == NMAP_VERSION_OUTPUT

    def test_nonzero_returncode_returns_none(self) -> None:
        """Returns None when nmap exits with non-zero code."""
        proc = _make_proc(returncode=1, stdout="", stderr="error")
        with patch("app.scanner.nmap_env.subprocess.run", return_value=proc):
            result = _run_version_check("/usr/bin/nmap", timeout=10)
        assert result is None

    def test_file_not_found_returns_none(self) -> None:
        """Returns None when the executable does not exist."""
        with patch(
            "app.scanner.nmap_env.subprocess.run",
            side_effect=FileNotFoundError("No such file"),
        ):
            result = _run_version_check("/nonexistent/nmap", timeout=10)
        assert result is None

    def test_permission_error_returns_none(self) -> None:
        """Returns None when the executable is not runnable."""
        with patch(
            "app.scanner.nmap_env.subprocess.run",
            side_effect=PermissionError("Permission denied"),
        ):
            result = _run_version_check("/usr/bin/nmap", timeout=10)
        assert result is None

    def test_timeout_returns_none(self) -> None:
        """Returns None when the subprocess times out."""
        with patch(
            "app.scanner.nmap_env.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=10),
        ):
            result = _run_version_check("/usr/bin/nmap", timeout=10)
        assert result is None

    def test_oserror_returns_none(self) -> None:
        """Returns None on generic OSError (e.g., exec format error)."""
        with patch(
            "app.scanner.nmap_env.subprocess.run",
            side_effect=OSError("Exec format error"),
        ):
            result = _run_version_check("/bad/binary", timeout=10)
        assert result is None

    def test_uses_arg_list_not_shell(self) -> None:
        """subprocess.run is always called with shell=False and an arg list."""
        proc = _make_proc(returncode=0, stdout=NMAP_VERSION_OUTPUT)
        with patch("app.scanner.nmap_env.subprocess.run", return_value=proc) as mock_run:
            _run_version_check("/usr/bin/nmap", timeout=5)
            call_args = mock_run.call_args
            # First positional arg must be a list, not a string
            cmd = call_args.args[0]
            assert isinstance(cmd, list), "subprocess.run must receive a list, not a string"
            assert cmd == ["/usr/bin/nmap", "--version"]
            # shell=False must be explicit
            assert call_args.kwargs.get("shell") is False


# ── StubScannerService tests ──────────────────────────────────────────────────


class TestStubScannerService:
    """Tests for the Phase 4.1 stub implementation."""

    def test_launch_raises_not_implemented(self) -> None:
        """launch() must raise NotImplementedError during Phase 4.1."""
        stub = StubScannerService()
        with pytest.raises(NotImplementedError, match="Phase 4.1"):
            stub.launch(uuid.uuid4(), "192.168.1.1", "quick")

    def test_cancel_is_safe_noop(self) -> None:
        """cancel() must not raise for any scan ID."""
        stub = StubScannerService()
        stub.cancel(uuid.uuid4())  # should not raise

    def test_get_job_returns_none(self) -> None:
        """get_job() must return None for any scan ID."""
        stub = StubScannerService()
        assert stub.get_job(uuid.uuid4()) is None

    def test_stub_satisfies_scanner_service_protocol(self) -> None:
        """StubScannerService structurally satisfies the ScannerService protocol."""
        stub = StubScannerService()
        assert isinstance(stub, ScannerService)


# ── ScanJob tests ─────────────────────────────────────────────────────────────


class TestScanJob:
    """Tests for the ScanJob dataclass."""

    def test_default_status_is_queued(self) -> None:
        job = ScanJob(scan_id=uuid.uuid4(), target="10.0.0.1")
        assert job.status == JobStatus.QUEUED
        assert job.progress == 0
        assert job.is_terminal() is False

    def test_completed_is_terminal(self) -> None:
        job = ScanJob(scan_id=uuid.uuid4(), target="10.0.0.1", status=JobStatus.COMPLETED)
        assert job.is_terminal() is True

    def test_failed_is_terminal(self) -> None:
        job = ScanJob(scan_id=uuid.uuid4(), target="10.0.0.1", status=JobStatus.FAILED)
        assert job.is_terminal() is True

    def test_cancelled_is_terminal(self) -> None:
        job = ScanJob(scan_id=uuid.uuid4(), target="10.0.0.1", status=JobStatus.CANCELLED)
        assert job.is_terminal() is True

    def test_running_is_not_terminal(self) -> None:
        job = ScanJob(scan_id=uuid.uuid4(), target="10.0.0.1", status=JobStatus.RUNNING)
        assert job.is_terminal() is False


# ── TargetValidator tests ─────────────────────────────────────────────────────


class TestTargetValidator:
    """Tests for TargetValidator."""

    # -- Syntax checks --

    def test_valid_ipv4(self) -> None:
        v = TargetValidator()
        assert v.is_syntactically_valid("192.168.1.1") is True

    def test_valid_ipv6(self) -> None:
        v = TargetValidator()
        assert v.is_syntactically_valid("::1") is True

    def test_valid_cidr(self) -> None:
        v = TargetValidator()
        assert v.is_syntactically_valid("10.0.0.0/24") is True

    def test_valid_hostname(self) -> None:
        v = TargetValidator()
        assert v.is_syntactically_valid("app.example.com") is True

    def test_valid_single_label_hostname(self) -> None:
        v = TargetValidator()
        assert v.is_syntactically_valid("localhost") is True

    def test_invalid_empty_string(self) -> None:
        v = TargetValidator()
        assert v.is_syntactically_valid("") is False

    def test_invalid_with_spaces(self) -> None:
        v = TargetValidator()
        assert v.is_syntactically_valid("192.168.1.1 ; rm -rf /") is False

    def test_invalid_with_shell_metacharacters(self) -> None:
        v = TargetValidator()
        assert v.is_syntactically_valid("$(id)") is False

    def test_invalid_cidr_host_bits_set(self) -> None:
        # strict=False means 10.0.0.1/24 is network 10.0.0.0/24 — still valid
        v = TargetValidator()
        assert v.is_syntactically_valid("10.0.0.1/24") is True

    # -- Authorisation checks --

    def test_exact_ip_authorised(self) -> None:
        v = TargetValidator(allow_list={"192.168.1.50"})
        assert v.is_authorised("192.168.1.50") is True

    def test_ip_not_in_allowlist(self) -> None:
        v = TargetValidator(allow_list={"192.168.1.50"})
        assert v.is_authorised("10.0.0.1") is False

    def test_ip_within_cidr_block_is_authorised(self) -> None:
        v = TargetValidator(allow_list={"192.168.1.0/24"})
        assert v.is_authorised("192.168.1.100") is True

    def test_ip_outside_cidr_block_is_not_authorised(self) -> None:
        v = TargetValidator(allow_list={"192.168.1.0/24"})
        assert v.is_authorised("192.168.2.1") is False

    def test_hostname_case_insensitive_match(self) -> None:
        v = TargetValidator(allow_list={"App.Example.com"})
        assert v.is_authorised("app.example.com") is True

    def test_empty_allowlist_authorises_nothing(self) -> None:
        v = TargetValidator()
        assert v.is_authorised("192.168.1.1") is False

    def test_add_extends_allowlist(self) -> None:
        v = TargetValidator()
        v.add("10.10.10.10")
        assert v.is_authorised("10.10.10.10") is True

    # -- validate() integration --

    def test_validate_accepts_authorised_ip(self) -> None:
        v = TargetValidator(allow_list={"10.0.0.1"})
        assert v.validate("  10.0.0.1  ") == "10.0.0.1"

    def test_validate_raises_value_error_for_invalid_syntax(self) -> None:
        v = TargetValidator(allow_list={"$(evil)"})
        with pytest.raises(ValueError, match="not a valid"):
            v.validate("$(evil)")

    def test_validate_raises_target_not_authorised(self) -> None:
        v = TargetValidator(allow_list={"10.0.0.1"})
        with pytest.raises(TargetNotAuthorisedError) as exc_info:
            v.validate("10.0.0.2")
        assert "10.0.0.2" in str(exc_info.value)

    def test_allow_list_property_is_immutable(self) -> None:
        v = TargetValidator(allow_list={"1.1.1.1"})
        snapshot = v.allow_list
        v.add("2.2.2.2")
        # snapshot taken before add() must not contain the new entry
        assert "2.2.2.2" not in snapshot
        assert "2.2.2.2" in v.allow_list


# ── Exception hierarchy tests ─────────────────────────────────────────────────


class TestExceptions:
    def test_target_not_authorised_error_message(self) -> None:
        exc = TargetNotAuthorisedError("1.2.3.4")
        assert "1.2.3.4" in str(exc)
        assert exc.target == "1.2.3.4"

    def test_nmap_not_available_error_is_scanner_error(self) -> None:
        from app.scanner.service import ScannerError
        err = NmapNotAvailableError("nmap missing")
        assert isinstance(err, ScannerError)
