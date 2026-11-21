from __future__ import annotations

import re
import socket
from typing import Dict, Iterable, Optional, Set


MULTI_PART_SUFFIXES: Set[str] = {
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz',
    'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'com.cn', 'com.hk', 'com.sg', 'com.my',
    'com.br', 'com.mx', 'com.ar', 'com.tr', 'com.tw', 'co.in', 'co.id', 'co.za',
    'com.vn', 'net.vn', 'org.vn', 'edu.vn', 'gov.vn', 'ac.vn', 'info.vn', 'biz.vn',
}

BRANDS: Dict[str, Set[str]] = {
    'paypal': {'paypal.com', 'paypal.me'},
    'appleid': {'apple.com', 'icloud.com'},
    'apple': {'apple.com', 'icloud.com'},
    'icloud': {'apple.com', 'icloud.com'},
    'microsoft': {'microsoft.com', 'live.com', 'office.com', 'outlook.com', 'microsoftonline.com',
                  'office365.com', 'windows.com', 'azure.com', 'bing.com', 'sharepoint.com'},
    'office365': {'microsoft.com', 'office.com', 'microsoftonline.com', 'office365.com'},
    'outlook': {'microsoft.com', 'outlook.com', 'live.com', 'office.com'},
    'google': {'google.com', 'gmail.com', 'youtube.com', 'google.com.vn', 'goo.gl', 'gstatic.com'},
    'gmail': {'google.com', 'gmail.com'},
    'facebook': {'facebook.com', 'fb.com', 'meta.com', 'messenger.com'},
    'instagram': {'instagram.com', 'facebook.com'},
    'whatsapp': {'whatsapp.com', 'whatsapp.net'},
    'amazon': {'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp', 'amazonaws.com', 'aws.amazon.com'},
    'netflix': {'netflix.com'},
    'linkedin': {'linkedin.com'},
    'dropbox': {'dropbox.com'},
    'docusign': {'docusign.com', 'docusign.net'},
    'zoom': {'zoom.us'},
    'github': {'github.com'},
    'dhl': {'dhl.com', 'dhl.de'},
    'fedex': {'fedex.com'},
    'ups': {'ups.com'},
    'tiktok': {'tiktok.com'},
  
    'vietcombank': {'vietcombank.com.vn', 'vietcombank.com'},
    'vcb': {'vietcombank.com.vn', 'vietcombank.com'},
    'techcombank': {'techcombank.com.vn', 'techcombank.com'},
    'tcb': {'techcombank.com.vn', 'techcombank.com'},
    'bidv': {'bidv.com.vn', 'bidv.vn'},
    'vietinbank': {'vietinbank.vn', 'vietinbank.com.vn'},
    'agribank': {'agribank.com.vn'},
    'mbbank': {'mbbank.com.vn'},
    'acb': {'acb.com.vn'},
    'sacombank': {'sacombank.com.vn', 'sacombank.com'},
    'tpbank': {'tpb.vn', 'tpbank.com.vn'},
    'vpbank': {'vpbank.com.vn'},
    'momo': {'momo.vn', 'mservice.com.vn'},
    'zalopay': {'zalopay.vn'},
    'zalo': {'zalo.me', 'zaloapp.com', 'zalo.vn'},
    'shopee': {'shopee.vn', 'shopee.com', 'shopee.sg'},
    'lazada': {'lazada.vn', 'lazada.com'},
    'tiki': {'tiki.vn'},
    'viettel': {'viettel.vn', 'viettel.com.vn', 'viettelpost.vn'},
    'vnpt': {'vnpt.vn', 'vnpt.com.vn'},
    'mobifone': {'mobifone.vn'},
    'vnpost': {'vnpost.vn'},
    'ghn': {'ghn.vn'},
    'ghtk': {'ghtk.vn'},
    'vneid': {'gov.vn'},
}


TRUSTED_DOMAINS: Set[str] = set().union(*BRANDS.values()) | {
    'wikipedia.org', 'mozilla.org', 'cloudflare.com', 'stackoverflow.com', 'twitter.com', 'x.com',
    'reddit.com', 'yahoo.com', 'adobe.com', 'oracle.com', 'ibm.com', 'gov.vn', 'edu.vn',
}


FREE_HOSTING: Set[str] = {
    'sites.google.com', 'docs.google.com', 'forms.gle', 'drive.google.com', 'storage.googleapis.com',
    'github.io', 'blogspot.com', 'weebly.com', 'wixsite.com', 'notion.site', 'firebaseapp.com',
    'web.app', 'pages.dev', 'netlify.app', 'vercel.app', 'herokuapp.com', 'glitch.me', 'workers.dev',
    '000webhostapp.com', 'godaddysites.com', 'webflow.io', 'carrd.co', 'surge.sh', 'sharepoint.com',
}

URL_SHORTENERS: Set[str] = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
    'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc', 's.id', 'lnkd.in', 'bit.do', 'v.gd', 'shorte.st',
}

SUSPICIOUS_TLDS: Set[str] = {
    '.xyz', '.top', '.club', '.online', '.site', '.tk', '.ml', '.ga', '.cf', '.gq', '.work',
    '.click', '.link', '.buzz', '.icu', '.cyou', '.sbs', '.rest', '.monster', '.cam', '.loan',
    '.zip', '.mov', '.country', '.stream',
}

_LEET_L = str.maketrans({'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '$': 's'})
_LEET_I = str.maketrans({'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '$': 's'})


def normalize_host(host: str) -> str:
    return (host or '').strip().lower().rstrip('.')


def is_ip_host(host: str) -> bool:
    host = host.strip('[]')
    if ':' in host:  # IPv6
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except OSError:
            return False
    if not re.fullmatch(r'[0-9a-fx.]+', host, re.I) or not re.search(r'\d', host):
        return False
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def registrable_domain(host: str) -> str:
    host = normalize_host(host)
    if not host or is_ip_host(host):
        return host
    labels = host.split('.')
    if len(labels) <= 2:
        return host
    last2 = '.'.join(labels[-2:])
    return '.'.join(labels[-3:]) if last2 in MULTI_PART_SUFFIXES else last2


def matches_suffix(host: str, domains: Iterable[str]) -> Optional[str]:
    host = normalize_host(host)
    for d in domains:
        if host == d or host.endswith('.' + d):
            return d
    return None


def is_trusted(host: str) -> bool:
    if matches_suffix(host, FREE_HOSTING):
        return False
    return matches_suffix(host, TRUSTED_DOMAINS) is not None


def _token_variants(token: str) -> Set[str]:
    out = set()
    for tr in (None, _LEET_L, _LEET_I):
        t = token if tr is None else token.translate(tr)
        out.add(t)
        out.add(t.replace('rn', 'm').replace('vv', 'w'))
    return out


def brand_impersonation(host: str) -> Optional[str]:
    host = normalize_host(host)
    if not host or is_ip_host(host) or is_trusted(host):
        return None
    tokens = [t for t in re.split(r'[^a-z0-9$]+', host) if t]
    for brand, official in BRANDS.items():
        if matches_suffix(host, official):
            continue
        for tok in tokens:
            for var in _token_variants(tok):
                if var == brand or (len(brand) >= 5 and var.startswith(brand)) \
                        or (len(brand) >= 6 and brand in var):
                    return brand
    return None
