"""
VulnScanner — Scanner service package.

Phase 4 integration layer between the FastAPI backend and Nmap.
This package exposes:
  - NmapEnvironment: probe the host for the Nmap executable.
  - ScannerService: interface contract for future scan execution.
  - TargetValidator: whitelist-based target sanitisation.
"""
