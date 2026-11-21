from __future__ import annotations

import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from typing import Any, Callable, Dict, List, Optional, Tuple

from common.net import ChainResult, Deadline, follow_redirects
from common.reputation import gsb_check, rdap_domain_age, urlhaus_check, vt_lookup_url
from common.scoring import Finding

from .base import Analysis
from .domains import (FREE_HOSTING, SUSPICIOUS_TLDS, URL_SHORTENERS, brand_impersonation, is_ip_host,
                      is_trusted, matches_suffix, normalize_host, registrable_domain)

MAX_URL_CHARS = 4096

SUSPICIOUS_URL_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'security', 'secure', 'account', 'banking', 'support',
    'confirm', 'wallet', 'unlock', 'auth', 'credential', 'recover', 'password', 'billing',
    'payment', 'webscr', 'suspend',
]

THREAT_VI = {'SOCIAL_ENGINEERING': 'lừa đảo', 'MALWARE': 'mã độc',
             'UNWANTED_SOFTWARE': 'phần mềm không mong muốn',
             'POTENTIALLY_HARMFUL_APPLICATION': 'ứng dụng độc hại'}


LinkAnalysis = Analysis


def normalize_url(raw: str) -> str:
    url = (raw or '').strip()
    if not url:
        raise ValueError('Link rỗng')
    if len(url) > MAX_URL_CHARS:
        raise ValueError('Link quá dài')
    if re.search(r'\s', url):
        raise ValueError('Link chứa khoảng trắng')
    if re.match(r'^(javascript|data|vbscript|file|blob):', url, re.I):
        raise ValueError('Chỉ hỗ trợ link http/https')
    m = re.match(r'^([a-z][a-z0-9+.\-]*)://', url, re.I)
    if m and m.group(1).lower() not in ('http', 'https'):
        raise ValueError('Chỉ hỗ trợ link http/https')
    if not m:
        url = 'http://' + url
    return url


def static_analysis(url: str) -> Tuple[Dict[str, Any], List[Finding]]:
    try:
        parts = urllib.parse.urlsplit(url)
        host = normalize_host(parts.hostname or '')
        port = parts.port
    except ValueError:
        raise ValueError('Link không hợp lệ')
    if not host:
        raise ValueError('Link không có tên miền')

    findings: List[Finding] = []
    reg = registrable_domain(host)
    is_ip = is_ip_host(host)
    trusted = is_trusted(host)
    tld = '.' + host.rsplit('.', 1)[-1] if '.' in host else ''

    details: Dict[str, Any] = {
        'domain': host, 'registrable_domain': reg, 'uses_https': parts.scheme == 'https',
        'is_ip_address': is_ip, 'suspicious_tld': False, 'suspicious_keywords': [],
        'trusted_domain': trusted,
    }

    if parts.scheme != 'https':
        findings.append(Finding('NO_HTTPS'))
    if parts.username is not None:
        findings.append(Finding('USERINFO_AT'))
    if port is not None and port not in (80, 443):
        findings.append(Finding('NONSTANDARD_PORT', detail=str(port)))

    if is_ip:
        findings.append(Finding('IP_HOST'))
        return details, findings   

    if tld in SUSPICIOUS_TLDS:
        details['suspicious_tld'] = True
        findings.append(Finding('SUSPICIOUS_TLD', detail=tld))

    puny = [lbl for lbl in host.split('.') if lbl.startswith('xn--')]
    if puny:
        try:
            shown = host.encode('ascii').decode('idna')
        except UnicodeError:
            shown = puny[0]
        findings.append(Finding('PUNYCODE_IDN', detail=shown))

    if matches_suffix(host, URL_SHORTENERS):
        findings.append(Finding('URL_SHORTENER', detail=reg))
        details['is_shortener'] = True
    if matches_suffix(host, FREE_HOSTING):
        findings.append(Finding('FREE_HOSTING', detail=matches_suffix(host, FREE_HOSTING)))

    if not trusted:
        brand = brand_impersonation(host)
        if brand:
            findings.append(Finding('BRAND_IMPERSONATION', detail=brand))
            details['impersonated_brand'] = brand

        host_tokens = [t for t in re.split(r'[^a-z0-9]+', host) if t]
        path_tokens = [t for t in re.split(r'[^a-z0-9]+',
                                           urllib.parse.unquote(parts.path or '').lower()) if t]
        found = [kw for kw in SUSPICIOUS_URL_KEYWORDS
                 if kw in host_tokens or kw in path_tokens
                 or (len(kw) >= 6 and any(kw in t for t in host_tokens))]
        if found:
            details['suspicious_keywords'] = found
            findings.append(Finding('URL_KEYWORDS', value=len(found), detail=', '.join(found)))

        label = reg.split('.')[0]
        if label.count('-') >= 3:
            findings.append(Finding('MANY_HYPHENS'))
        if len(host.split('.')) - len(reg.split('.')) >= 3:
            findings.append(Finding('MANY_SUBDOMAINS'))
    return details, findings



class _FormScanner(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: List[Dict[str, Any]] = []
        self._cur: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag, attrs):
        a = {k: (v or '') for k, v in attrs}
        if tag == 'form':
            self._cur = {'action': a.get('action', ''), 'password': False}
            self.forms.append(self._cur)
        elif tag == 'input' and a.get('type', '').lower() == 'password':
            if self._cur is None:
                self._cur = {'action': '', 'password': True}
                self.forms.append(self._cur)
            else:
                self._cur['password'] = True

    def handle_endtag(self, tag):
        if tag == 'form':
            self._cur = None


def analyze_landing(body: str, final_url: str) -> Tuple[Dict[str, Any], List[Finding]]:
    """Tìm biểu mẫu đăng nhập trên trang đích và nơi nó gửi dữ liệu tới."""
    findings: List[Finding] = []
    scanner = _FormScanner()
    try:
        scanner.feed(body)
    except Exception:  # HTML hỏng không được làm hỏng job
        return {}, findings
    pw_forms = [f for f in scanner.forms if f['password']]
    info = {'has_password_form': bool(pw_forms), 'form_count': len(scanner.forms)}
    final_host = normalize_host(urllib.parse.urlsplit(final_url).hostname or '')
    if pw_forms and not is_trusted(final_host):
        findings.append(Finding('LANDING_PASSWORD_FORM'))
        for form in pw_forms:
            target = urllib.parse.urlsplit(urllib.parse.urljoin(final_url, form['action']))
            thost = normalize_host(target.hostname or '')
            if thost and registrable_domain(thost) != registrable_domain(final_host):
                info['form_action_host'] = thost
                findings.append(Finding('FORM_ACTION_EXTERNAL', detail=thost))
                break
    return info, findings



def _safe(fn: Callable, *args, source: str) -> Dict[str, Any]:
    try:
        return fn(*args)
    except Exception as exc: 
        return {'source': source, 'ok': False, 'status': 'ERROR', 'error': type(exc).__name__}


def analyze_link(raw_url: str, deadline: Deadline, *, mode: str = 'full') -> LinkAnalysis:
    """mode: 'static' (không mạng) | 'reputation' (VT/GSB/URLhaus) | 'full' (thêm RDAP, redirect, trang đích)."""
    url = normalize_url(raw_url)
    details, findings = static_analysis(url)
    details.update({'input_url': raw_url, 'normalized_url': url})
    host, reg = details['domain'], details['registrable_domain']
    if mode == 'static':
        return LinkAnalysis(details, findings, 0)

    full = mode == 'full'
    with ThreadPoolExecutor(max_workers=5) as pool:
        f_vt = pool.submit(_safe, vt_lookup_url, url, deadline, source='virustotal')
        f_gsb = pool.submit(_safe, gsb_check, url, deadline, source='safe_browsing')
        f_uh = pool.submit(_safe, urlhaus_check, url, deadline, source='urlhaus')
        f_chain = pool.submit(follow_redirects, url, deadline) if full else None
        f_rdap = (pool.submit(_safe, rdap_domain_age, reg, deadline, source='rdap')
                  if full and not details['is_ip_address'] and not details['trusted_domain'] else None)
        vt, gsb, uh = f_vt.result(), f_gsb.result(), f_uh.result()
        try:
            chain: Optional[ChainResult] = f_chain.result() if f_chain else None
        except Exception as exc:  # noqa: BLE001
            chain = ChainResult(final_url=url, error=type(exc).__name__)
        rdap = f_rdap.result() if f_rdap else None

    details['virustotal_report'] = vt
    details['safe_browsing'] = gsb
    details['urlhaus'] = uh
    if vt.get('malicious', 0) > 0:
        findings.append(Finding('VT_MALICIOUS', value=vt['malicious']))
    if vt.get('suspicious', 0) > 0:
        findings.append(Finding('VT_SUSPICIOUS', value=vt['suspicious']))
    if gsb.get('status') == 'THREAT_FOUND':
        types = ', '.join(THREAT_VI.get(t, t.lower()) for t in gsb.get('threat_types', []))
        findings.append(Finding('GSB_MATCH', detail=types or 'nguy hiểm'))
    if uh.get('status') == 'LISTED':
        findings.append(Finding('URLHAUS_LISTED', detail=uh.get('threat') or 'malware_download'))
    reputation_ok = sum(1 for r in (vt, gsb, uh) if r.get('ok'))

    
    if rdap:
        details['rdap'] = rdap
        if rdap.get('ok'):
            details['domain_age_days'] = rdap['age_days']
            findings.append(Finding('DOMAIN_NEW', value=rdap['age_days']))

    
    details.update({'redirection_count': 0, 'ssl_valid': False})
    if chain is not None:
        details['redirect_chain'] = [h['url'] for h in chain.hops][:8]
        details['final_url'] = chain.final_url
        details['redirection_count'] = chain.redirect_count
        if chain.blocked:
            details['fetch_blocked'] = chain.blocked
        if chain.error:
            details['fetch_error'] = chain.error
        if chain.ssl_error:
            details['ssl_error'] = chain.ssl_error
            findings.append(Finding('SSL_INVALID'))
        details['ssl_valid'] = (details['uses_https'] and not chain.ssl_error
                                and chain.final_status is not None)

        if chain.redirect_count >= 2:
            findings.append(Finding('REDIRECT_CHAIN', value=chain.redirect_count))

        final_host = normalize_host(urllib.parse.urlsplit(chain.final_url).hostname or '')
        final_reg = registrable_domain(final_host) if final_host else reg
        if final_host and final_reg != reg:
            if not details.get('is_shortener') and not is_trusted(final_host):
                findings.append(Finding('REDIRECT_CROSS_DOMAIN', detail=f'{reg} → {final_reg}'))
            
            try:
                _, final_findings = static_analysis(chain.final_url)
                have = {f.code for f in findings}
                findings.extend(f for f in final_findings if f.code not in have)
            except ValueError:
                pass
            final_gsb = _safe(gsb_check, chain.final_url, deadline, source='safe_browsing')
            if final_gsb.get('status') == 'THREAT_FOUND':
                details['final_url_safe_browsing'] = final_gsb
                types = ', '.join(THREAT_VI.get(t, t.lower()) for t in final_gsb.get('threat_types', []))
                findings.append(Finding('GSB_MATCH', detail=types or 'nguy hiểm'))

        if chain.body:
            landing, landing_findings = analyze_landing(chain.body, chain.final_url)
            details['landing'] = landing
            findings.extend(landing_findings)
    return LinkAnalysis(details, findings, reputation_ok)
