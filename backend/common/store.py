"""Lưu trữ kết quả: DynamoDB (jobs + cache) và S3 (audit log). boto3 được import lười."""
from __future__ import annotations

import json
import os
import time
from decimal import Decimal
from typing import Any, Dict, Optional

CACHE_TTL_SECONDS = 24 * 3600


def to_dynamo(obj: Any) -> Any:
    """DynamoDB (boto3 resource) không nhận float. Chuyển float -> Decimal."""
    return json.loads(json.dumps(obj, default=str), parse_float=Decimal)


def from_dynamo(obj: Any) -> Any:
    """Decimal -> int/float để json.dumps / so sánh bình thường."""
    if isinstance(obj, Decimal):
        return int(obj) if obj == obj.to_integral_value() else float(obj)
    if isinstance(obj, dict):
        return {k: from_dynamo(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [from_dynamo(v) for v in obj]
    return obj


class Store:
    def __init__(self, jobs_tbl=None, cache_tbl=None, s3=None, reports_bucket: Optional[str] = None):
        self._jobs, self._cache, self._s3 = jobs_tbl, cache_tbl, s3
        self.reports_bucket = reports_bucket if reports_bucket is not None else os.environ.get('REPORTS_BUCKET', '')

    # --- lazy clients -------------------------------------------------------
    @property
    def jobs(self):
        if self._jobs is None:
            import boto3
            self._jobs = boto3.resource('dynamodb').Table(os.environ.get('JOBS_TABLE', 'PhishingScanJobs'))
        return self._jobs

    @property
    def cache(self):
        if self._cache is None:
            import boto3
            self._cache = boto3.resource('dynamodb').Table(os.environ.get('CACHE_TABLE', 'PhishingScanCache'))
        return self._cache

    @property
    def s3(self):
        if self._s3 is None:
            import boto3
            self._s3 = boto3.client('s3')
        return self._s3

    # --- jobs -----------------------------------------------------------------
    def job_status(self, job_id: str) -> Optional[str]:
        item = self.jobs.get_item(Key={'job_id': job_id}).get('Item')
        return item.get('status') if item else None

    def mark_processing(self, job_id: str) -> None:
        self.jobs.update_item(
            Key={'job_id': job_id}, UpdateExpression='SET #s = :s',
            ExpressionAttributeNames={'#s': 'status'}, ExpressionAttributeValues={':s': 'PROCESSING'})

    def save_completed(self, job_id: str, result: Dict[str, Any]) -> None:
        self.jobs.update_item(
            Key={'job_id': job_id}, UpdateExpression='SET #s = :s, trust_score = :ts, #r = :r',
            ExpressionAttributeNames={'#s': 'status', '#r': 'result'},
            ExpressionAttributeValues={':s': 'COMPLETED', ':ts': int(result['trust_score']),
                                       ':r': to_dynamo(result)})

    # --- cache ----------------------------------------------------------------
    def cache_get(self, target_hash: str) -> Optional[Dict[str, Any]]:
        item = self.cache.get_item(Key={'target_hash': target_hash}).get('Item')
        if item and int(item.get('expires_at', 0)) > time.time():
            return from_dynamo(item.get('result'))
        return None

    def cache_put(self, target_hash: str, job_id: str, result: Dict[str, Any]) -> None:
        self.cache.put_item(Item={
            'target_hash': target_hash, 'job_id': job_id, 'result': to_dynamo(result),
            'expires_at': int(result.get('scanned_at', time.time())) + CACHE_TTL_SECONDS})

    # --- audit log --------------------------------------------------------------
    def save_log(self, job_id: str, result: Dict[str, Any]) -> None:
        if not self.reports_bucket:
            return
        try:
            self.s3.put_object(Bucket=self.reports_bucket, Key=f'logs/{job_id}.json',
                               Body=json.dumps(result, indent=2, default=str).encode(),
                               ContentType='application/json')
        except Exception as exc:  # log không được làm hỏng kết quả
            print(f'Cảnh báo: không lưu được log S3 cho job {job_id}: {exc}')
