from __future__ import annotations

import base64
import json
import os
import time
import urllib.parse
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .net import Deadline, http_json

VT_BASE = 'https://www.virustotal.com/api/v3'
VT_UPLOAD_LIMIT = 32 * 1024 * 1024  # giới hạn upload trực tiếp của VT API


def _env(name: str, default: str = '') -> str:
    return os.environ.get(name, default).strip()


def vt_api_keys() -> List[str]:
    keys: List[str] = []
    for raw in [_env('VT_API_KEY')] + _env('VT_BACKUP_API_KEYS').split(','):
        k = raw.strip()
        if k and k not in keys:
            keys.append(k)
    return keys


def _label(idx: int) -> str:
    return 'PRIMARY_KEY' if idx == 0 else f'BACKUP_KEY_{idx}'


def _unavailable(source: str, status: str, **extra: Any) -> Dict[str, Any]:
    out = {'source': source, 'ok': False, 'status': status,
           'malicious': 0, 'suspicious': 0}
    out.update(extra)
    return out


def _stats_result(source: str, status: str, stats: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
    out = {'source': source, 'ok': True, 'status': status,
           'malicious': int(stats.get('malicious', 0) or 0),
           'suspicious': int(stats.get('suspicious', 0) or 0),
           'harmless': int(stats.get('harmless', 0) or 0),
           'undetected': int(stats.get('undetected', 0) or 0)}
    out.update(extra)
    return out


# --------------------------------------------------------------------------- #
# VirusTotal
# --------------------------------------------------------------------------- #
def _vt_poll(analysis_id: str, headers: Dict[str, str], deadline: Deadline) -> Optional[Dict[str, Any]]:
    max_wait = float(_env('VT_POLL_MAX_WAIT', '12'))
    interval = float(_env('VT_POLL_INTERVAL', '4'))
    waited = 0.0
    while True:
        if deadline.remaining() < interval + 1 or waited >= max_wait:
            return None
        time.sleep(interval)
        waited += interval
        status, obj = http_json('GET', f'{VT_BASE}/analyses/{analysis_id}',
                                headers=headers, timeout=8, deadline=deadline)
        if status != 200 or not isinstance(obj, dict):
            return None
        attrs = (obj.get('data') or {}).get('attributes') or {}
        if attrs.get('status') == 'completed':
            return attrs.get('stats') or {}


def vt_lookup_url(url: str, deadline: Deadline) -> Dict[str, Any]:
    keys = vt_api_keys()
    if not keys:
        return _unavailable('virustotal', 'NO_API_KEY')
    url_id = base64.urlsafe_b64encode(url.encode('utf-8')).decode('ascii').strip('=')
    notes: List[str] = []
    for idx, key in enumerate(keys):
        headers = {'x-apikey': key}
        label = _label(idx)
        try:
            status, obj = http_json('GET', f'{VT_BASE}/urls/{url_id}', headers=headers,
                                    timeout=8, deadline=deadline)
            if status == 200 and isinstance(obj, dict):
                attrs = (obj.get('data') or {}).get('attributes') or {}
                stats = attrs.get('last_analysis_stats') or {}
                if stats:
                    return _stats_result('virustotal', 'FOUND', stats, api_key_used=label,
                                         categories=attrs.get('categories') or {},
                                         permalink=f'https://www.virustotal.com/gui/url/{url_id}')
            elif status == 404:
                body = urllib.parse.urlencode({'url': url}).encode()
                st2, post = http_json('POST', f'{VT_BASE}/urls', body=body, timeout=8, deadline=deadline,
                                      headers={**headers, 'Content-Type': 'application/x-www-form-urlencoded'})
                if st2 in (429, 401, 403):
                    notes.append(f'{label}: HTTP {st2}')
                    continue
                analysis_id = ((post or {}).get('data') or {}).get('id') if isinstance(post, dict) else None
                if st2 == 200 and analysis_id:
                    stats = _vt_poll(analysis_id, headers, deadline)
                    if stats is not None:
                        return _stats_result('virustotal', 'SUBMITTED_AND_SCANNED', stats, api_key_used=label,
                                             permalink=f'https://www.virustotal.com/gui/url/{url_id}')
                    return _unavailable('virustotal', 'SCAN_PENDING', api_key_used=label)
                notes.append(f'{label}: submit HTTP {st2}')
                continue
            elif status in (429, 401, 403):
                notes.append(f'{label}: HTTP {status}')
                continue
            else:
                notes.append(f'{label}: HTTP {status}')
                continue
        except (OSError, TimeoutError) as exc:
            notes.append(f'{label}: {type(exc).__name__}')
            continue
    return _unavailable('virustotal', 'UNAVAILABLE', notes=notes)


def vt_lookup_file(sha256: str, local_path: str, filename: str, size: int,
                   deadline: Deadline, *, allow_upload: Optional[bool] = None) -> Dict[str, Any]:
    keys = vt_api_keys()
    if not keys:
        return _unavailable('virustotal', 'NO_API_KEY')
    if allow_upload is None:
        allow_upload = _env('VT_UPLOAD_UNKNOWN_FILES', 'true').lower() == 'true'
    notes: List[str] = []
    for idx, key in enumerate(keys):
        headers = {'x-apikey': key}
        label = _label(idx)
        permalink = f'https://www.virustotal.com/gui/file/{sha256}'
        try:
            status, obj = http_json('GET', f'{VT_BASE}/files/{sha256}', headers=headers,
                                    timeout=10, deadline=deadline)
            if status == 200 and isinstance(obj, dict):
                attrs = (obj.get('data') or {}).get('attributes') or {}
                stats = attrs.get('last_analysis_stats') or {}
                label_ = ((attrs.get('popular_threat_classification') or {})
                          .get('suggested_threat_label') or '')
                return _stats_result('virustotal', 'FOUND', stats, api_key_used=label,
                                     threat_label=label_, permalink=permalink)
            if status == 404:
                if allow_upload and size <= VT_UPLOAD_LIMIT:
                    res = _vt_upload(local_path, filename, headers, label, permalink, deadline)
                    if res.get('quota'):
                        notes.append(f'{label}: upload quota')
                        continue
                    return res
                return _unavailable('virustotal', 'HASH_UNKNOWN', api_key_used=label, permalink=permalink)
            notes.append(f'{label}: HTTP {status}')
            continue
        except (OSError, TimeoutError) as exc:
            notes.append(f'{label}: {type(exc).__name__}')
            continue
    return _unavailable('virustotal', 'UNAVAILABLE', notes=notes)


def _vt_upload(local_path, filename, headers, label, permalink, deadline) -> Dict[str, Any]:
    boundary = f'----TrustCheck{uuid.uuid4().hex}'
    safe_name = filename.replace('"', '').replace('\r', '').replace('\n', '')
    with open(local_path, 'rb') as fh:
        data = fh.read()
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{safe_name}"\r\n'
            f'Content-Type: application/octet-stream\r\n\r\n').encode() + data + f'\r\n--{boundary}--\r\n'.encode()
    status, post = http_json('POST', f'{VT_BASE}/files', body=body, timeout=25, deadline=deadline,
                             headers={**headers, 'Content-Type': f'multipart/form-data; boundary={boundary}'})
    if status in (429, 401, 403):
        return {'quota': True}
    analysis_id = ((post or {}).get('data') or {}).get('id') if isinstance(post, dict) else None
    if status != 200 or not analysis_id:
        return _unavailable('virustotal', f'UPLOAD_HTTP_{status}', api_key_used=label)
    stats = _vt_poll(analysis_id, headers, deadline)
    if stats is None:
        return _unavailable('virustotal', 'SCAN_PENDING', api_key_used=label, permalink=permalink)
    return _stats_result('virustotal', 'UPLOADED_AND_SCANNED', stats, api_key_used=label, permalink=permalink)


# --------------------------------------------------------------------------- #
# Google Safe Browsing (Lookup API v4)
# --------------------------------------------------------------------------- #
def gsb_check(url: str, deadline: Deadline) -> Dict[str, Any]:
    key = _env('GSB_API_KEY')
    if not key:
        return _unavailable('safe_browsing', 'NO_API_KEY')
    payload = {
        'client': {'clientId': 'trustcheck', 'clientVersion': '2.0'},
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE',
                            'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}],
        },
    }
    try:
        status, obj = http_json(
            'POST', 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + urllib.parse.quote(key),
            headers={'Content-Type': 'application/json'}, body=json.dumps(payload).encode(),
            timeout=6, deadline=deadline)
    except (OSError, TimeoutError) as exc:
        return _unavailable('safe_browsing', 'UNAVAILABLE', error=type(exc).__name__)
    if status != 200 or not isinstance(obj, dict):
        return _unavailable('safe_browsing', f'HTTP_{status}')
    matches = obj.get('matches') or []
    types = sorted({m.get('threatType', '') for m in matches if m.get('threatType')})
    return {'source': 'safe_browsing', 'ok': True,
            'status': 'THREAT_FOUND' if matches else 'CLEAN',
            'malicious': 1 if matches else 0, 'suspicious': 0, 'threat_types': types}


# --------------------------------------------------------------------------- #
# abuse.ch: URLhaus & MalwareBazaar (cần Auth-Key)
# --------------------------------------------------------------------------- #
def urlhaus_check(url: str, deadline: Deadline) -> Dict[str, Any]:
    key = _env('ABUSECH_AUTH_KEY')
    if not key:
        return _unavailable('urlhaus', 'NO_API_KEY')
    try:
        status, obj = http_json('POST', 'https://urlhaus-api.abuse.ch/v1/url/', timeout=6, deadline=deadline,
                                headers={'Auth-Key': key,
                                         'Content-Type': 'application/x-www-form-urlencoded'},
                                body=urllib.parse.urlencode({'url': url}).encode())
    except (OSError, TimeoutError) as exc:
        return _unavailable('urlhaus', 'UNAVAILABLE', error=type(exc).__name__)
    if status != 200 or not isinstance(obj, dict):
        return _unavailable('urlhaus', f'HTTP_{status}')
    qs = obj.get('query_status')
    if qs == 'ok':
        return {'source': 'urlhaus', 'ok': True, 'status': 'LISTED', 'malicious': 1, 'suspicious': 0,
                'threat': obj.get('threat') or '', 'url_status': obj.get('url_status') or '',
                'tags': (obj.get('tags') or [])[:5]}
    if qs in ('no_results', 'invalid_url'):
        return {'source': 'urlhaus', 'ok': qs == 'no_results', 'status': 'NOT_LISTED',
                'malicious': 0, 'suspicious': 0}
    return _unavailable('urlhaus', f'QUERY_{qs}')


def malwarebazaar_check(sha256: str, deadline: Deadline) -> Dict[str, Any]:
    key = _env('ABUSECH_AUTH_KEY')
    if not key:
        return _unavailable('malwarebazaar', 'NO_API_KEY')
    try:
        status, obj = http_json('POST', 'https://mb-api.abuse.ch/api/v1/', timeout=8, deadline=deadline,
                                headers={'Auth-Key': key,
                                         'Content-Type': 'application/x-www-form-urlencoded'},
                                body=urllib.parse.urlencode({'query': 'get_info', 'hash': sha256}).encode())
    except (OSError, TimeoutError) as exc:
        return _unavailable('malwarebazaar', 'UNAVAILABLE', error=type(exc).__name__)
    if status != 200 or not isinstance(obj, dict):
        return _unavailable('malwarebazaar', f'HTTP_{status}')
    qs = obj.get('query_status')
    if qs == 'ok':
        sample = (obj.get('data') or [{}])[0]
        return {'source': 'malwarebazaar', 'ok': True, 'status': 'MALWARE_FOUND', 'malicious': 1,
                'suspicious': 0, 'signature': sample.get('signature') or '',
                'tags': (sample.get('tags') or [])[:5]}
    if qs == 'hash_not_found':
        return {'source': 'malwarebazaar', 'ok': True, 'status': 'NOT_LISTED', 'malicious': 0, 'suspicious': 0}
    return _unavailable('malwarebazaar', f'QUERY_{qs}')


# --------------------------------------------------------------------------- #
# Tuổi tên miền qua RDAP (thay cho WHOIS cổng 43: trả JSON, không cần thư viện ngoài)
# --------------------------------------------------------------------------- #
def rdap_domain_age(registrable_domain: str, deadline: Deadline) -> Dict[str, Any]:
    try:
        status, obj = http_json('GET', f'https://rdap.org/domain/{urllib.parse.quote(registrable_domain)}',
                                headers={'Accept': 'application/rdap+json'}, timeout=6, deadline=deadline)
    except (OSError, TimeoutError) as exc:
        return {'source': 'rdap', 'ok': False, 'status': 'UNAVAILABLE', 'error': type(exc).__name__}
    if status != 200 or not isinstance(obj, dict):
        # Nhiều TLD (đặc biệt ccTLD) không có RDAP công khai: không có dữ liệu, KHÔNG bị trừ điểm.
        return {'source': 'rdap', 'ok': False, 'status': f'HTTP_{status}'}
    created = None
    for ev in obj.get('events') or []:
        if ev.get('eventAction') == 'registration' and ev.get('eventDate'):
            created = ev['eventDate']
            break
    if not created:
        return {'source': 'rdap', 'ok': False, 'status': 'NO_REGISTRATION_EVENT'}
    try:
        dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age_days = max(0, (datetime.now(timezone.utc) - dt).days)
    except ValueError:
        return {'source': 'rdap', 'ok': False, 'status': 'BAD_DATE'}
    return {'source': 'rdap', 'ok': True, 'status': 'FOUND', 'created': created, 'age_days': age_days}
