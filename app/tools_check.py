"""Check external tool availability and versions for Nmap, Nuclei, osv-scanner."""

from __future__ import annotations

import subprocess
from typing import Any

from .scanners.tools import tool_path


def check_external_tools() -> dict[str, Any]:
    """Return status for each optional external scanner tool."""
    results: dict[str, Any] = {}

    # Nmap
    nmap_path = tool_path("nmap")
    nmap_version = None
    nmap_available = False
    try:
        if nmap_path:
            proc = subprocess.run(
                [str(nmap_path), "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in proc.stdout.splitlines() + proc.stderr.splitlines():
                if "version" in line.lower():
                    nmap_version = line.strip()
                    break
            nmap_available = proc.returncode == 0
        else:
            nmap_version = "Not installed"
    except Exception:
        pass
    results["nmap"] = {
        "available": nmap_available,
        "version": nmap_version,
        "outdated_warning": False,
    }

    # Nuclei
    nuclei_path = tool_path("nuclei")
    nuclei_version = None
    nuclei_available = False
    try:
        if nuclei_path:
            proc = subprocess.run(
                [str(nuclei_path), "-version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = (proc.stdout or "") + (proc.stderr or "")
            for line in output.splitlines():
                line_lower = line.lower()
                if "version" in line_lower:
                    nuclei_version = line.strip()
                    if line_lower.startswith("v"):
                        nuclei_version = line
                    break
                if "current version" in line_lower:
                    nuclei_version = line.strip()
            nuclei_available = proc.returncode == 0 or nuclei_version is not None
        else:
            nuclei_version = "Not installed"
    except Exception:
        pass
    results["nuclei"] = {
        "available": nuclei_available,
        "version": nuclei_version,
        "outdated_warning": False,
    }

    # osv-scanner (Google's CLI for supplemental OSV analysis)
    osv_path = tool_path("osv-scanner")
    osv_version = None
    osv_available = False
    try:
        if osv_path:
            proc = subprocess.run(
                [str(osv_path), "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = (proc.stdout or "")
            for line in output.splitlines():
                if "version" in line.lower() or "osv-scanner" in line.lower():
                    osv_version = line.strip()
                    break
            osv_available = proc.returncode == 0 or "osv-scanner" in (proc.stdout or "")
        else:
            osv_version = "Not installed"
    except Exception:
        pass
    results["osv-scanner"] = {
        "available": osv_available,
        "version": osv_version,
        "outdated_warning": False,
    }

    return results
