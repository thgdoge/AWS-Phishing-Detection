"""Detector cho Email.

Theo sơ đồ: Check SPF/DKIM/DMARC + Bóc tách URL/Attachment + NLP phát hiện lừa đảo.

* Nếu người dùng dán email có header (Authentication-Results, From, Reply-To...), ta parse
  header thật bằng thư viện ``email``. Nếu chỉ dán phần nội dung thì bỏ qua các kiểm tra
  header (không phạt vì thiếu dữ liệu).
* "NLP" ở đây là bộ luật ngôn ngữ (song ngữ Anh - Việt, có và không dấu). Giao diện
  ``analyze_text`` tách riêng để sau này có thể thay bằng mô hình (ví dụ Amazon Comprehend).
"""
from __future__ import annotations

import email
import email.policy
import email.utils
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple

from common.net import Deadline
from common.scoring import Finding, compute_score
from common.textnorm import fold, word_pattern

from .base import Analysis
from .domains import BRANDS, brand_impersonation, matches_suffix, normalize_host, registrable_domain
from .file import analyze_bytes, filename_findings
from .link import analyze_link

MAX_FULL_LINKS = 3
MAX_STATIC_LINKS = 7
MAX_ATTACHMENTS = 3
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024

URGENT_PHRASES = [
    # English
    'urgent', 'immediately', 'immediate action', 'act now', 'within 24 hours', 'within 48 hours',
    'account suspended', 'account will be suspended', 'account has been locked', 'account will be closed',
    'verify your account', 'confirm your identity', 'unusual activity', 'unauthorized login',
    'suspicious activity', 'security alert', 'password expired', 'click the link below',
    'final notice', 'last warning', 'failure to comply',
    # Tiếng Việt (đã bỏ dấu, vì văn bản đầu vào cũng được bỏ dấu trước khi so khớp)
    'khan cap', 'ngay lap tuc', 'trong vong 24 gio', 'trong 24 gio', 'trong 24h',
    'tai khoan se bi khoa', 'tai khoan cua ban se bi khoa', 'tai khoan bi khoa', 'bi tam khoa',
    'xac minh ngay', 'xac thuc ngay', 'xac nhan ngay', 'cap nhat thong tin', 'canh bao bao mat',
    'dang nhap bat thuong', 'giao dich bat thuong', 'thong bao cuoi cung',
]
CREDENTIAL_TERMS = [
    'password', 'mat khau', 'otp', 'ma otp', 'smart otp', 'ma xac thuc', 'pin', 'ma pin',
    'credit card', 'cvv', 'security code', 'the tin dung', 'so the', 'so tai khoan', 'cccd', 'cmnd',
    'ma bao mat',
]
CREDENTIAL_VERBS = [
    'enter', 'provide', 'send', 'confirm', 'verify', 'reply', 'submit', 'update', 'share',
    'nhap', 'cung cap', 'gui', 'xac nhan', 'xac minh', 'cap nhat', 'chia se', 'tra loi', 'dien',
]
LURE_PHRASES = [
    'you have won', 'you won', 'claim your prize', 'free gift', 'lottery', 'inheritance',
    'unclaimed funds', 'trung thuong', 'chuc mung ban da', 'ban da trung', 'nhan qua mien phi',
    'hoan tien ngay', 'nhan thuong',
]

# Dạng hiển thị có dấu cho các cụm tiếng Việt (so khớp dùng dạng không dấu).
PHRASE_DISPLAY = {
    'khan cap': 'khẩn cấp', 'ngay lap tuc': 'ngay lập tức', 'trong vong 24 gio': 'trong vòng 24 giờ',
    'trong 24 gio': 'trong 24 giờ', 'trong 24h': 'trong 24h',
    'tai khoan se bi khoa': 'tài khoản sẽ bị khóa', 'tai khoan cua ban se bi khoa': 'tài khoản của bạn sẽ bị khóa',
    'tai khoan bi khoa': 'tài khoản bị khóa', 'bi tam khoa': 'bị tạm khóa', 'xac minh ngay': 'xác minh ngay',
    'xac thuc ngay': 'xác thực ngay', 'xac nhan ngay': 'xác nhận ngay', 'cap nhat thong tin': 'cập nhật thông tin',
    'canh bao bao mat': 'cảnh báo bảo mật', 'dang nhap bat thuong': 'đăng nhập bất thường',
    'giao dich bat thuong': 'giao dịch bất thường', 'thong bao cuoi cung': 'thông báo cuối cùng',
    'trung thuong': 'trúng thưởng', 'chuc mung ban da': 'chúc mừng bạn đã', 'ban da trung': 'bạn đã trúng',
    'nhan qua mien phi': 'nhận quà miễn phí', 'hoan tien ngay': 'hoàn tiền ngay', 'nhan thuong': 'nhận thưởng',
}


def _show(phrases):
    return [PHRASE_DISPLAY.get(p, p) for p in phrases]


_URGENT_RE = [(p, word_pattern(p)) for p in URGENT_PHRASES]
_CRED_RE = [word_pattern(p) for p in CREDENTIAL_TERMS]
_VERB_RE = [word_pattern(p) for p in CREDENTIAL_VERBS]
_LURE_RE = [(p, word_pattern(p)) for p in LURE_PHRASES]
_BRAND_WORDS = [(b, word_pattern(b)) for b in BRANDS]

_HEADER_LINE = re.compile(
    r'^(from|to|cc|subject|date|received|return-path|reply-to|message-id|mime-version|'
    r'authentication-results|received-spf|dkim-signature|content-type|x-[a-z0-9-]+):', re.I)
_URL_RE = re.compile(r'(?:https?://|www\.)[^\s<>"\'\]\[]+', re.I)
_DOMAIN_IN_TEXT = re.compile(r'\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b', re.I)


# --------------------------------------------------------------------------- #
# Parse
# --------------------------------------------------------------------------- #
@dataclass
class ParsedEmail:
    has_headers: bool = False
    subject: str = ''
    from_name: str = ''
    from_addr: str = ''
    reply_to: str = ''
    return_path: str = ''
    auth_text: str = ''
    text: str = ''
    html_parts: List[str] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)


def looks_like_headers(raw: str) -> bool:
    head = raw.lstrip().replace('\r\n', '\n').split('\n\n', 1)[0][:8000]
    lines = [ln for ln in head.split('\n') if ln and not ln[0] in ' \t']
    return len(lines) >= 2 and all(_HEADER_LINE.match(ln) for ln in lines[:2])


def _addr_domain(addr: str) -> str:
    _, parsed = email.utils.parseaddr(addr or '')
    return normalize_host(parsed.rsplit('@', 1)[-1]) if '@' in parsed else ''


def parse_email(raw: str) -> ParsedEmail:
    p = ParsedEmail()
    if not looks_like_headers(raw):
        p.text = raw
        if re.search(r'<(a|html|body|div|p)\b', raw, re.I):
            p.html_parts.append(raw)
        p.auth_text = ' '.join(re.findall(r'\b(?:spf|dkim|dmarc)=\w+', raw, re.I))
        return p

    p.has_headers = True
    msg = email.message_from_string(raw, policy=email.policy.default)
    p.subject = str(msg.get('Subject', '') or '')
    p.from_name, from_addr = email.utils.parseaddr(str(msg.get('From', '') or ''))
    p.from_addr = from_addr
    p.reply_to = str(msg.get('Reply-To', '') or '')
    p.return_path = str(msg.get('Return-Path', '') or '')

    auth = [str(v) for v in msg.get_all('Authentication-Results', [])]
    for v in msg.get_all('Received-SPF', []):
        m = re.match(r'\s*(\w+)', str(v))
        if m:
            auth.append(f'spf={m.group(1).lower()}')
    p.auth_text = ' '.join(auth)

    texts: List[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        if fname or part.get_content_disposition() == 'attachment':
            data = part.get_payload(decode=True)
            p.attachments.append({'filename': str(fname or 'unnamed'), 'content_type': ctype,
                                  'data': data if isinstance(data, bytes) else None})
            continue
        if ctype in ('text/plain', 'text/html'):
            try:
                content = part.get_content()
            except (LookupError, UnicodeError, KeyError):
                payload = part.get_payload(decode=True) or b''
                content = payload.decode('utf-8', 'replace')
            (texts if ctype == 'text/plain' else p.html_parts).append(str(content))
    p.text = '\n'.join(texts)
    return p


class _HtmlExtract(HTMLParser):
    """Lấy chữ nhìn thấy được và các thẻ <a> (href + chữ hiển thị)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.chunks: List[str] = []
        self.anchors: List[Tuple[str, str]] = []
        self._skip = 0
        self._href: Optional[str] = None
        self._atext: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self._skip += 1
        elif tag == 'a':
            self._href = dict(attrs).get('href') or ''
            self._atext = []

    def handle_endtag(self, tag):
        if tag in ('script', 'style') and self._skip:
            self._skip -= 1
        elif tag == 'a' and self._href is not None:
            self.anchors.append((self._href, ' '.join(self._atext).strip()))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.chunks.append(data)
        if self._href is not None:
            self._atext.append(data.strip())


def extract_html(parts: List[str]) -> Tuple[str, List[Tuple[str, str]]]:
    texts, anchors = [], []
    for html in parts:
        ex = _HtmlExtract()
        try:
            ex.feed(html)
        except Exception:  # noqa: BLE001
            continue
        texts.append(' '.join(ex.chunks))
        anchors.extend(ex.anchors)
    return '\n'.join(texts), anchors


# --------------------------------------------------------------------------- #
# NLP theo luật
# --------------------------------------------------------------------------- #
def analyze_text(subject: str, body: str) -> Tuple[Dict[str, Any], List[Finding]]:
    text = fold(subject + '\n' + body)
    urgent = [p for p, rx in _URGENT_RE if rx.search(text)]
    lure = [p for p, rx in _LURE_RE if rx.search(text)]

    asks = False
    for rx in _CRED_RE:
        for m in rx.finditer(text):
            window = text[max(0, m.start() - 60): m.end() + 60]
            if any(v.search(window) for v in _VERB_RE):
                asks = True
                break
        if asks:
            break

    findings: List[Finding] = []
    if urgent:
        findings.append(Finding('URGENT_PHRASES', value=len(urgent), detail=', '.join(_show(urgent[:3]))))
    if asks:
        findings.append(Finding('CREDENTIAL_REQUEST'))
    if lure:
        findings.append(Finding('LURE_PHRASES', value=len(lure), detail=', '.join(_show(lure[:2]))))
    return {'urgent_phrases_found': urgent, 'asks_sensitive_credentials': asks,
            'lure_phrases_found': lure}, findings


# --------------------------------------------------------------------------- #
# Người gửi + xác thực
# --------------------------------------------------------------------------- #
def _auth_verdict(auth_text: str, mech: str) -> Optional[str]:
    results = {m.lower() for m in re.findall(rf'\b{mech}=(\w+)', auth_text, re.I)}
    if not results:
        return None
    if 'pass' in results:
        return 'pass'
    for bad in ('fail', 'softfail'):
        if bad in results:
            return bad
    return sorted(results)[0]


def analyze_sender(p: ParsedEmail) -> Tuple[Dict[str, Any], List[Finding]]:
    findings: List[Finding] = []
    spf, dkim, dmarc = (_auth_verdict(p.auth_text, m) for m in ('spf', 'dkim', 'dmarc'))
    info: Dict[str, Any] = {
        'spf_result': spf, 'dkim_result': dkim, 'dmarc_result': dmarc,
        'spf_fail_detected': spf in ('fail', 'softfail'),
        'dkim_fail_detected': dkim == 'fail',
        'dmarc_fail_detected': dmarc == 'fail',
    }
    if spf == 'fail':
        findings.append(Finding('SPF_FAIL'))
    elif spf == 'softfail':
        findings.append(Finding('SPF_SOFTFAIL'))
    if dkim == 'fail':
        findings.append(Finding('DKIM_FAIL'))
    if dmarc == 'fail':
        findings.append(Finding('DMARC_FAIL'))

    if not p.has_headers:
        info['headers_present'] = False
        return info, findings
    info['headers_present'] = True

    from_host = _addr_domain(p.from_addr) or normalize_host(p.from_addr.rsplit('@', 1)[-1])
    from_reg = registrable_domain(from_host) if from_host else ''
    info['sender_domain'] = from_host
    if from_host:
        brand = brand_impersonation(from_host)
        if brand:
            findings.append(Finding('SENDER_BRAND_MISMATCH', detail=brand))

    reply_host = _addr_domain(p.reply_to)
    if reply_host and from_reg and registrable_domain(reply_host) != from_reg:
        findings.append(Finding('REPLYTO_MISMATCH', detail=f'{from_reg} ≠ {registrable_domain(reply_host)}'))

    # Return-Path khác tên miền là bình thường với dịch vụ gửi mail hàng loạt khi SPF pass.
    rp_host = _addr_domain(p.return_path)
    if rp_host and from_reg and spf != 'pass' and registrable_domain(rp_host) != from_reg:
        findings.append(Finding('RETURNPATH_MISMATCH', detail=f'{from_reg} ≠ {registrable_domain(rp_host)}'))

    # Tên hiển thị giả danh: chứa một tên miền khác, hoặc chứa tên brand nhưng gửi từ domain lạ.
    name = p.from_name or ''
    spoof = None
    m = _DOMAIN_IN_TEXT.search(name)
    if m and from_reg and registrable_domain(m.group(1)) != from_reg:
        spoof = m.group(1).lower()
    if not spoof and from_host:
        folded = fold(name)
        for brand, rx in _BRAND_WORDS:
            if rx.search(folded) and not matches_suffix(from_host, BRANDS[brand]):
                spoof = brand
                break
    if spoof:
        findings.append(Finding('DISPLAY_NAME_SPOOF', detail=spoof))
    return info, findings


# --------------------------------------------------------------------------- #
# URL
# --------------------------------------------------------------------------- #
def extract_urls(text: str, anchors: List[Tuple[str, str]]) -> List[str]:
    found: List[str] = []

    def add(u: str):
        u = u.strip().rstrip('.,;:!?)\'"')
        if re.match(r'^(mailto|tel|sms|javascript):', u, re.I) or not u:
            return
        if u.lower().startswith('www.'):
            u = 'http://' + u
        if re.match(r'^https?://', u, re.I) and u not in found:
            found.append(u)

    for href, _ in anchors:
        add(href)
    for m in _URL_RE.finditer(text):
        add(m.group(0))
    return found


def link_text_mismatches(anchors: List[Tuple[str, str]]) -> List[str]:
    """Chữ hiển thị là một tên miền (vd. paypal.com) nhưng href trỏ tới tên miền khác."""
    out: List[str] = []
    for href, shown in anchors:
        m = _DOMAIN_IN_TEXT.search(shown or '')
        if not m or not re.match(r'^https?://', href or '', re.I):
            continue
        href_host = normalize_host(urllib.parse.urlsplit(href).hostname or '')
        shown_host = normalize_host(m.group(1))
        if href_host and registrable_domain(shown_host) != registrable_domain(href_host):
            out.append(f'{shown_host} → {href_host}')
    return out[:3]


# --------------------------------------------------------------------------- #
# Tổng hợp
# --------------------------------------------------------------------------- #
def _score_of(analysis: Analysis) -> Tuple[int, List[str]]:
    s = compute_score(analysis.findings, reputation_ok=analysis.reputation_ok,
                      reputation_needed=analysis.reputation_needed)
    return s.score, s.reasons


def analyze_email(raw: str, deadline: Deadline) -> Analysis:
    parsed = parse_email(raw)
    html_text, anchors = extract_html(parsed.html_parts)
    body = (parsed.text + '\n' + html_text).strip()

    text_info, findings = analyze_text(parsed.subject, body)
    sender_info, sender_findings = analyze_sender(parsed)
    findings += sender_findings

    mismatches = link_text_mismatches(anchors)
    if mismatches:
        findings.append(Finding('LINK_TEXT_MISMATCH', value=len(mismatches), detail='; '.join(mismatches[:2])))

    urls = extract_urls(body, anchors)
    full_urls, static_urls = urls[:MAX_FULL_LINKS], urls[MAX_FULL_LINKS:MAX_FULL_LINKS + MAX_STATIC_LINKS]

    link_rows: List[Dict[str, Any]] = []
    vt_scans: List[Dict[str, Any]] = []
    worst: Optional[Tuple[int, str, str]] = None   # (score, url, reason)
    rep_ok_values: List[int] = []
    max_mal = max_sus = 0

    def run(url: str, mode: str):
        try:
            return url, mode, analyze_link(url, deadline, mode=mode), None
        except ValueError as exc:
            return url, mode, None, str(exc)

    jobs = [(u, 'full') for u in full_urls] + [(u, 'static') for u in static_urls]
    if jobs:
        with ThreadPoolExecutor(max_workers=MAX_FULL_LINKS) as pool:
            results = list(pool.map(lambda j: run(*j), jobs))
        for url, mode, analysis, err in results:
            if analysis is None:
                link_rows.append({'url': url[:200], 'error': err})
                continue
            score, reasons = _score_of(analysis)
            link_rows.append({'url': url[:200], 'mode': mode, 'score': score, 'reasons': reasons[:3]})
            if mode == 'full':
                vt = analysis.details.get('virustotal_report', {})
                vt_scans.append({'url': url[:200], 'vt_result': vt})
                max_mal = max(max_mal, vt.get('malicious', 0))
                max_sus = max(max_sus, vt.get('suspicious', 0))
                rep_ok_values.append(analysis.reputation_ok)
            if worst is None or score < worst[0]:
                worst = (score, url, reasons[0] if reasons else '')
        if worst and worst[0] < 100:
            domain = registrable_domain(normalize_host(urllib.parse.urlsplit(worst[1]).hostname or ''))
            findings.append(Finding('EMAIL_LINK_RISK', value=100 - worst[0],
                                    detail=f'{domain}: {worst[2]}'.strip(': ')))

    # ---- tệp đính kèm ------------------------------------------------------------------
    att_rows: List[Dict[str, Any]] = []
    worst_att: Optional[Tuple[int, str, str]] = None
    for att in parsed.attachments[:MAX_ATTACHMENTS]:
        name, data = att['filename'], att.get('data')
        if data and len(data) <= MAX_ATTACHMENT_BYTES:
            try:
                a = analyze_bytes(data, name, deadline)
            except Exception as exc:  # noqa: BLE001
                att_rows.append({'filename': name, 'error': type(exc).__name__})
                continue
        else:
            a = Analysis({'filename': name}, filename_findings(name), 0, False)
        score, reasons = _score_of(a)
        att_rows.append({'filename': name, 'size': len(data) if data else None, 'score': score,
                         'sha256': a.details.get('sha256'), 'reasons': reasons[:3]})
        if worst_att is None or score < worst_att[0]:
            worst_att = (score, name, reasons[0] if reasons else '')
    if worst_att and worst_att[0] < 100:
        findings.append(Finding('EMAIL_ATTACHMENT_RISK', value=100 - worst_att[0],
                                detail=f'{worst_att[1]}: {worst_att[2]}'.strip(': ')))

    details: Dict[str, Any] = {
        'email_length_chars': len(raw),
        'subject': parsed.subject[:200],
        'extracted_urls_count': len(urls),
        'extracted_urls': [u[:200] for u in urls[:5]],
        'virustotal_link_scans': vt_scans,
        'max_malicious_detections': max_mal,
        'max_suspicious_detections': max_sus,
        'link_scans': link_rows,
        'link_text_mismatches': mismatches,
        'attachments': att_rows,
        **text_info, **sender_info,
    }
    needs_rep = bool(full_urls)
    reputation_ok = min(rep_ok_values) if rep_ok_values else 0
    return Analysis(details, findings, reputation_ok, needs_rep)
