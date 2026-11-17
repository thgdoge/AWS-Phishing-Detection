from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

USER_AGENT = 'TrustCheck-PhishingScanner/2.0'
BROWSER_UA = 'Mozilla/5.0 (compatible; TrustCheckBot/2.0)'

# Chỉ cho phép quét các cổng web phổ biến, tránh bị lợi dụng để dò cổng nội bộ.
ALLOWED_PORTS = {80, 443, 8080, 8443}
# Chỉ bật trong unit test (cho phép nối tới 127.0.0.1).
ALLOW_PRIVATE = False


class Deadline:
   
    def __init__(self, seconds: float):
        self._end = time.monotonic() + seconds

    def remaining(self) -> float:
        return max(0.0, self._end - time.monotonic())

    def expired(self) -> bool:
        return self.remaining() <= 0.2

    def timeout(self, cap: float) -> float:
        if self.expired():
            raise TimeoutError('Hết ngân sách thời gian của job')
        return max(0.5, min(cap, self.remaining()))


class BlockedTarget(Exception):


 def _parse_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode('utf-8', 'replace')) if raw else None
    except ValueError:
        return None


def http_json(method: str, url: str, *, headers: Optional[Dict[str, str]] = None,
              body: Optional[bytes] = None, timeout: float = 8.0,
              deadline: Optional[Deadline] = None) -> Tuple[int, Any]:
    t = deadline.timeout(timeout) if deadline else timeout
    hdrs = {'User-Agent': USER_AGENT, 'Accept': 'application/json'}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=t) as resp:
            return resp.status, _parse_json(resp.read(2_000_000))
    except urllib.error.HTTPError as err:
        try:
            return err.code, _parse_json(err.read(200_000))
        finally:
            err.close()


# --------------------------------------------------------------------------- #
# Theo dõi redirect an toàn
# --------------------------------------------------------------------------- #
def resolve_public_ip(host: str) -> str:
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    ips = []
    for info in infos:
        raw = info[4][0].split('%')[0]
        addr = ipaddress.ip_address(raw)
        check = addr.ipv4_mapped if addr.version == 6 and addr.ipv4_mapped else addr
        if not ALLOW_PRIVATE and not check.is_global:
            raise BlockedTarget(f'{host} -> {raw}')
        ips.append((addr.version, raw))
    if not ips:
        raise BlockedTarget(f'{host}: không phân giải được')
    ips.sort()  # ưu tiên IPv4 (Lambda thường không có IPv6 ra ngoài)
    return ips[0][1]


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, ip, **kw):
        super().__init__(host, **kw)
        self._pin_ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._pin_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, ip, **kw):
        super().__init__(host, **kw)
        self._pin_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pin_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


@dataclass
class ChainResult:
    hops: List[Dict[str, Any]] = field(default_factory=list)  # {'url', 'status'}
    final_url: str = ''
    final_status: Optional[int] = None
    body: str = ''
    error: Optional[str] = None
    ssl_error: Optional[str] = None
    blocked: Optional[str] = None

    @property
    def redirect_count(self) -> int:
        return sum(1 for h in self.hops if 300 <= (h.get('status') or 0) < 400)


def follow_redirects(url: str, deadline: Deadline, *, max_hops: int = 6,
                     per_request_timeout: float = 4.0, max_body: int = 150_000) -> ChainResult:
    result = ChainResult(final_url=url)
    current = url
    for _ in range(max_hops + 1):
        parts = urllib.parse.urlsplit(current)
        if parts.scheme not in ('http', 'https') or not parts.hostname:
            result.error = 'Địa chỉ không phải http/https'
            return result
        port = parts.port or (443 if parts.scheme == 'https' else 80)
        if not ALLOW_PRIVATE and port not in ALLOWED_PORTS:
            result.blocked = f'cổng {port} không được phép'
            return result
        try:
            ip = resolve_public_ip(parts.hostname)
        except BlockedTarget as exc:
            result.blocked = str(exc)
            return result
        except OSError as exc:
            result.error = f'DNS: {str(exc)[:80]}'
            return result

        try:
            timeout = deadline.timeout(per_request_timeout)
        except TimeoutError:
            result.error = 'Hết thời gian'
            return result
        conn_cls = _PinnedHTTPSConnection if parts.scheme == 'https' else _PinnedHTTPConnection
        conn = conn_cls(parts.hostname, ip, port=port, timeout=timeout)
        path = (parts.path or '/') + (('?' + parts.query) if parts.query else '')
        try:
            conn.request('GET', path, headers={
                'User-Agent': BROWSER_UA, 'Accept': 'text/html,*/*;q=0.5',
                'Accept-Encoding': 'identity', 'Connection': 'close'})
            resp = conn.getresponse()
            status = resp.status
            result.hops.append({'url': current, 'status': status})
            result.final_url, result.final_status = current, status
            location = resp.getheader('Location')
            if 300 <= status < 400 and location:
                current = urllib.parse.urljoin(current, location)
                continue
            ctype = (resp.getheader('Content-Type') or '').lower()
            if 'html' in ctype:
                result.body = resp.read(max_body).decode('utf-8', 'replace')
            return result
        except ssl.SSLError as exc:
            result.ssl_error = str(getattr(exc, 'reason', None) or exc)[:80]
            return result
        except (OSError, http.client.HTTPException) as exc:
            result.error = f'{type(exc).__name__}: {str(exc)[:80]}'
            return result
        finally:
            conn.close()
    result.error = 'Quá nhiều bước chuyển hướng'
    return result
