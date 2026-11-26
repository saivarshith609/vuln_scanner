"""Safe User-Agent parsing for informational login activity metadata."""

from __future__ import annotations

from dataclasses import dataclass
import re

LOGIN_ACTIVITY_RETENTION_DAYS = 90
_MAX_UA_LENGTH = 512


@dataclass(frozen=True)
class ClientDeviceInfo:
    browser_name: str
    browser_version: str | None
    operating_system: str
    os_version: str | None
    device_type: str


def _detect_browser(ua: str) -> tuple[str, str | None]:
    # Order matters: Edge/Opera include Chrome/Safari tokens; Chrome includes Safari.
    for pattern, name in (
        (r"(?:Edg|EdgA|EdgiOS|Edge)/(\d+)", "Edge"),
        (r"(?:OPR|Opera)/(\d+)", "Opera"),
        (r"(?:Firefox|FxiOS)/(\d+)", "Firefox"),
        (r"(?:Chrome|CriOS)/(\d+)", "Chrome"),
    ):
        match = re.search(pattern, ua)
        if match:
            return name, match.group(1)

    if "Safari/" in ua:
        version_match = re.search(r"Version/(\d+)", ua)
        return "Safari", version_match.group(1) if version_match else None

    return "Unknown", None


def _detect_os(ua: str) -> tuple[str, str | None]:
    if re.search(r"iPhone|iPad|iPod", ua):
        match = re.search(r"OS (\d+[._]\d+(?:[._]\d+)?)", ua)
        return "iOS", match.group(1).replace("_", ".") if match else None

    if "Android" in ua:
        match = re.search(r"Android (\d+(?:\.\d+)?)", ua)
        return "Android", match.group(1) if match else None

    if "Windows" in ua:
        match = re.search(r"Windows NT (\d+\.\d+)", ua)
        if match:
            nt_version = match.group(1)
            mapped = {"10.0": "10/11", "6.3": "8.1", "6.2": "8", "6.1": "7"}.get(nt_version, nt_version)
            return "Windows", mapped
        return "Windows", None

    if "Mac OS X" in ua or "Macintosh" in ua:
        match = re.search(r"Mac OS X (\d+[._]\d+(?:[._]\d+)?)", ua)
        return "macOS", match.group(1).replace("_", ".") if match else None

    if "Linux" in ua or "X11" in ua:
        return "Linux", None

    return "Unknown", None


def _detect_device_type(ua: str, operating_system: str) -> str:
    if "iPad" in ua or "Tablet" in ua or (operating_system == "Android" and "Mobile" not in ua):
        return "Tablet"
    if (
        "Mobile" in ua
        or "iPhone" in ua
        or "iPod" in ua
        or "CriOS" in ua
        or "FxiOS" in ua
        or operating_system in {"iOS", "Android"}
    ):
        return "Mobile"
    if operating_system in {"Windows", "macOS", "Linux"}:
        return "Desktop"
    return "Unknown"


def parse_user_agent(raw_user_agent: str | None) -> ClientDeviceInfo:
    """Parse browser, OS, and device category without storing raw headers."""
    if not raw_user_agent or not raw_user_agent.strip():
        return ClientDeviceInfo(
            browser_name="Unknown",
            browser_version=None,
            operating_system="Unknown",
            os_version=None,
            device_type="Unknown",
        )

    ua = raw_user_agent.strip()[:_MAX_UA_LENGTH]
    browser_name, browser_version = _detect_browser(ua)
    operating_system, os_version = _detect_os(ua)
    device_type = _detect_device_type(ua, operating_system)
    return ClientDeviceInfo(
        browser_name=browser_name,
        browser_version=browser_version,
        operating_system=operating_system,
        os_version=os_version,
        device_type=device_type,
    )
