"""
VulnScanner — Nmap XML output parser.

Parses the structured XML produced by ``nmap -oX -`` into typed Python
dataclasses.  No vulnerability inference is performed: an open port or
an identified service version is **not** treated as a vulnerability.

Safety properties
-----------------
* Output length is checked before parsing; oversized input raises
  :class:`NmapXmlTooLargeError`.
* ``xml.etree.ElementTree`` (C accelerated, no external deps) is used;
  it is safe against billion-laugh / quadratic-blowup attacks in CPython
  because it does not expand external entities by default.
* ``defusedxml`` would be even safer; it is not installed by default, so
  we apply a manual entity-expansion guard.
* Malformed XML raises :class:`NmapXmlParseError`, not an uncaught
  exception.

Usage::

    xml_bytes = b"<nmaprun>...</nmaprun>"
    results = parse_nmap_xml(xml_bytes)
    for host in results.hosts:
        for port in host.ports:
            print(host.address, port.portid, port.service_name)
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

DEFAULT_MAX_BYTES: int = 10 * 1024 * 1024  # 10 MiB

# ── Exceptions ────────────────────────────────────────────────────────────────


class NmapXmlError(Exception):
    """Base class for XML-parse errors."""


class NmapXmlTooLargeError(NmapXmlError):
    """Raised when the XML payload exceeds the configured size limit."""


class NmapXmlParseError(NmapXmlError):
    """Raised when the XML is structurally invalid."""


# ── Data structures ───────────────────────────────────────────────────────────


@dataclass
class PortInfo:
    """A single port entry from an Nmap host record."""

    portid: int
    protocol: str
    state: str
    service_name: str | None = None
    service_product: str | None = None
    service_version: str | None = None
    service_extra_info: str | None = None


@dataclass
class HostInfo:
    """A single host entry from an Nmap run."""

    address: str
    state: str  # 'up' or 'down'
    hostname: str | None = None
    mac_address: str | None = None
    vendor: str | None = None
    ports: list[PortInfo] = field(default_factory=list)


@dataclass
class NmapScanSummary:
    """Top-level summary of an Nmap XML document."""

    nmap_version: str | None
    args: str | None
    exit_status: str | None  # 'success' or 'error'
    hosts: list[HostInfo] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        """True when Nmap reported a successful exit (or no exit element)."""
        return self.exit_status in (None, "success")


# ── Parser ────────────────────────────────────────────────────────────────────


def parse_nmap_xml(
    xml_data: str | bytes,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> NmapScanSummary:
    """
    Parse *xml_data* into a :class:`NmapScanSummary`.

    Args:
        xml_data: Raw Nmap XML string or bytes from ``-oX -``.
        max_bytes: Byte limit; raise :class:`NmapXmlTooLargeError` if exceeded.

    Returns:
        A populated :class:`NmapScanSummary`.

    Raises:
        NmapXmlTooLargeError: If the data exceeds *max_bytes*.
        NmapXmlParseError: If the XML is malformed or missing ``<nmaprun>``.
    """
    if isinstance(xml_data, str):
        raw = xml_data.encode("utf-8", errors="replace")
    else:
        raw = xml_data

    if len(raw) > max_bytes:
        raise NmapXmlTooLargeError(
            f"Nmap XML output ({len(raw):,} bytes) exceeds the "
            f"{max_bytes:,}-byte safety limit."
        )

    if not raw.strip():
        raise NmapXmlParseError("Nmap produced empty XML output.")

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise NmapXmlParseError(f"Malformed Nmap XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise NmapXmlParseError(
            f"Expected root element <nmaprun>, got <{root.tag}>."
        )

    # ── Top-level metadata ────────────────────────────────────────────────
    nmap_version = root.get("version")
    args = root.get("args")

    run_stats = root.find("runstats")
    exit_status: str | None = None
    if run_stats is not None:
        finished = run_stats.find("finished")
        if finished is not None:
            exit_status = finished.get("exit")  # 'success' or 'error'

    # ── Host records ──────────────────────────────────────────────────────
    hosts: list[HostInfo] = []

    for host_el in root.findall("host"):
        host_info = _parse_host(host_el)
        if host_info is not None:
            hosts.append(host_info)

    return NmapScanSummary(
        nmap_version=nmap_version,
        args=args,
        exit_status=exit_status,
        hosts=hosts,
    )


# ── Internal helpers ──────────────────────────────────────────────────────────


def _parse_host(host_el: ET.Element) -> HostInfo | None:
    """Parse a single ``<host>`` element."""
    # Host state
    status_el = host_el.find("status")
    if status_el is None:
        return None
    state = status_el.get("state", "unknown")

    # Address — prefer IPv4 > IPv6 > mac
    address = _extract_address(host_el)
    if not address:
        return None

    # Hostname
    hostname = _extract_hostname(host_el)
    mac_address, vendor = _extract_mac(host_el)

    # Ports
    ports: list[PortInfo] = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            port_info = _parse_port(port_el)
            if port_info is not None:
                ports.append(port_info)

    return HostInfo(
        address=address,
        state=state,
        hostname=hostname,
        mac_address=mac_address,
        vendor=vendor,
        ports=ports,
    )


def _extract_address(host_el: ET.Element) -> str | None:
    """Return the best address string from a host element."""
    address_map: dict[str, str] = {}
    for addr_el in host_el.findall("address"):
        addr_type = addr_el.get("addrtype", "")
        addr = addr_el.get("addr", "")
        if addr:
            address_map[addr_type] = addr
    # Preference order: ipv4 → ipv6 → mac
    return (
        address_map.get("ipv4")
        or address_map.get("ipv6")
        or address_map.get("mac")
    )


def _extract_hostname(host_el: ET.Element) -> str | None:
    """Return the first user-submitted or PTR hostname, if any."""
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is None:
        return None
    for hn_el in hostnames_el.findall("hostname"):
        name = hn_el.get("name", "").strip()
        if name:
            return name
    return None


def _extract_mac(host_el: ET.Element) -> tuple[str | None, str | None]:
    """Return Nmap's MAC address and vendor attributes when present."""
    for addr_el in host_el.findall("address"):
        if addr_el.get("addrtype") == "mac":
            address = _nonempty(addr_el.get("addr"))
            vendor = _nonempty(addr_el.get("vendor"))
            return address, vendor
    return None, None


def _parse_port(port_el: ET.Element) -> PortInfo | None:
    """Parse a single ``<port>`` element."""
    portid_str = port_el.get("portid")
    protocol = port_el.get("protocol", "tcp")
    if portid_str is None:
        return None
    try:
        portid = int(portid_str)
    except ValueError:
        return None

    state_el = port_el.find("state")
    if state_el is None:
        return None
    state = state_el.get("state", "unknown")

    # Service info (optional)
    service_name = service_product = service_version = service_extra = None
    service_el = port_el.find("service")
    if service_el is not None:
        service_name = _nonempty(service_el.get("name"))
        service_product = _nonempty(service_el.get("product"))
        service_version = _nonempty(service_el.get("version"))
        service_extra = _nonempty(service_el.get("extrainfo"))

    return PortInfo(
        portid=portid,
        protocol=protocol,
        state=state,
        service_name=service_name,
        service_product=service_product,
        service_version=service_version,
        service_extra_info=service_extra,
    )


def _nonempty(value: str | None) -> str | None:
    """Return *value* if non-empty after stripping, else ``None``."""
    if value and value.strip():
        return value.strip()
    return None
