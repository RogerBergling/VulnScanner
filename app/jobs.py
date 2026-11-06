"""Background scan workers."""

from __future__ import annotations

import concurrent.futures

from .config import SCAN_WORKERS
from .scans import (
    execute_ad_import,
    execute_agent_result,
    execute_pingcastle_import,
    execute_satellite_result,
    execute_scan,
)

# One slot per independent server-side scan. SQLite WAL mode lets these workers
# persist results concurrently. Delegated agent scans are not submitted here;
# they stay in agent_jobs until the endpoint polls.
_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=SCAN_WORKERS, thread_name_prefix="vulnscan"
)


def submit_scan(scan_id: int, runtime_options: dict | None = None) -> None:
    _executor.submit(execute_scan, scan_id, runtime_options or {})


def submit_agent_result(scan_id: int, payload: dict, job_id: str | None = None) -> None:
    _executor.submit(execute_agent_result, scan_id, payload, job_id)


def submit_ad_import(scan_id: int, report: dict) -> None:
    _executor.submit(execute_ad_import, scan_id, report)


def submit_pingcastle_import(scan_id: int, xml_text: str) -> None:
    _executor.submit(execute_pingcastle_import, scan_id, xml_text)


def submit_satellite_result(scan_id: int, job_id: str, payload: dict) -> None:
    _executor.submit(execute_satellite_result, scan_id, job_id, payload)


def shutdown(wait: bool = False) -> None:
    _executor.shutdown(wait=wait, cancel_futures=True)
