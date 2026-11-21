from __future__ import annotations

import os
import threading
import time
from typing import Dict, Tuple

FAILURE_TTL_SECONDS = 120

_CACHE: Dict[str, Tuple[str, float]] = {}  
_LOCK = threading.Lock()
_client = None


def _get_client():
    global _client
    if _client is None:
        import boto3
        from botocore.config import Config
       
        _client = boto3.client('ssm', config=Config(connect_timeout=3, read_timeout=3,
                                                    retries={'max_attempts': 2}))
    return _client


def get_api_key(name: str) -> str:
    value = os.environ.get(name, '').strip()
    if value:
        return value
    prefix = os.environ.get('SSM_PREFIX', '').strip()
    if not prefix:
        return ''

    path = '/' + prefix.strip('/') + '/' + name
    with _LOCK:
        now = time.monotonic()
        hit = _CACHE.get(path)
        if hit and hit[1] > now:
            return hit[0]
        try:
            resp = _get_client().get_parameter(Name=path, WithDecryption=True)
            value = (resp['Parameter']['Value'] or '').strip()
            _CACHE[path] = (value, float('inf'))
            return value
        except Exception as exc:  
            code = getattr(exc, 'response', {}).get('Error', {}).get('Code') or type(exc).__name__
            print(f'[api_keys] không đọc được {path}: {code}')
            _CACHE[path] = ('', now + FAILURE_TTL_SECONDS)
            return ''
