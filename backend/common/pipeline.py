from __future__ import annotations

import json
import time
import traceback
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from .net import Deadline
from .scoring import error_result
from .store import Store

SAFETY_MARGIN_SECONDS = 6.0   # chừa thời gian để ghi DynamoDB/S3 trước khi Lambda timeout
DEFAULT_BUDGET_SECONDS = 40.0


@dataclass
class Outcome:
    result: Dict[str, Any]
    cache_key: Optional[str] = None   # None => không ghi cache


def _is_cacheable(result: Dict[str, Any]) -> bool:
    # Không cache lỗi hoặc kết quả thiếu nguồn uy tín (thử lại sau có thể tốt hơn).
    return result.get('risk_level') != 'SCAN ERROR' and result.get('confidence') != 'LOW'


def process_event(event: Dict[str, Any], context: Any,
                  analyze: Callable[[Dict[str, Any], Deadline, Store], Outcome],
                  store: Optional[Store] = None) -> Dict[str, Any]:
    store = store or Store()
    for record in event.get('Records', []):
        try:
            body = json.loads(record.get('body') or '{}')
        except ValueError:
            print(f"Bỏ qua message hỏng: {record.get('messageId')}")
            continue
        job_id = body.get('job_id')
        if not job_id:
            continue
        if store.job_status(job_id) == 'COMPLETED':
            print(f'Job {job_id} đã hoàn tất trước đó, bỏ qua.')
            continue

        store.mark_processing(job_id)
        remaining = (context.get_remaining_time_in_millis() / 1000.0) if context else DEFAULT_BUDGET_SECONDS + SAFETY_MARGIN_SECONDS
        deadline = Deadline(max(5.0, remaining - SAFETY_MARGIN_SECONDS))

        try:
            outcome = analyze(body, deadline, store)
        except Exception as exc:  # noqa: BLE001 - mọi lỗi phân tích đều được ghi nhận thành SCAN ERROR
            print(f'Lỗi phân tích job {job_id}: {type(exc).__name__}: {exc}')
            traceback.print_exc()
            outcome = Outcome(error_result(f'{type(exc).__name__}: {exc}'))

        store.save_completed(job_id, outcome.result)
        if outcome.cache_key and _is_cacheable(outcome.result):
            store.cache_put(outcome.cache_key, job_id, outcome.result)
        store.save_log(job_id, outcome.result)
    return {'statusCode': 200}
