"""Background scan workers."""

from __future__ import annotations

import concurrent.futures

from .scans import execute_ad_import, execute_agent_result, execute_scan

_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="vulnscan"
)


def submit_scan(scan_id: int, runtime_options: dict | None = None) -> None:
    _executor.submit(execute_scan, scan_id, runtime_options or {})


def submit_agent_result(scan_id: int, payload: dict, job_id: str | None = None) -> None:
    _executor.submit(execute_agent_result, scan_id, payload, job_id)


def submit_ad_import(scan_id: int, report: dict) -> None:
    _executor.submit(execute_ad_import, scan_id, report)


def shutdown(wait: bool = False) -> None:
    _executor.shutdown(wait=wait, cancel_futures=True)
