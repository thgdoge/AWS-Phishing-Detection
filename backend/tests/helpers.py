"""Hàm giả (fake) cho các nguồn bên ngoài, để test không cần mạng."""
import copy
from unittest import mock

OK_CLEAN = {'source': 'x', 'ok': True, 'status': 'CLEAN', 'malicious': 0, 'suspicious': 0}


def vt(malicious=0, suspicious=0, ok=True):
    return {'source': 'virustotal', 'ok': ok, 'status': 'FOUND' if ok else 'UNAVAILABLE',
            'malicious': malicious, 'suspicious': suspicious}


def gsb(threat=False):
    return {'source': 'safe_browsing', 'ok': True, 'status': 'THREAT_FOUND' if threat else 'CLEAN',
            'malicious': 1 if threat else 0, 'suspicious': 0,
            'threat_types': ['SOCIAL_ENGINEERING'] if threat else []}


def urlhaus(listed=False):
    return {'source': 'urlhaus', 'ok': True, 'status': 'LISTED' if listed else 'NOT_LISTED',
            'malicious': 1 if listed else 0, 'suspicious': 0, 'threat': 'malware_download' if listed else ''}


def patch_link_sources(vt_res=None, gsb_res=None, uh_res=None, chain=None, rdap=None):
    """Patch toàn bộ lời gọi mạng của detectors.link. Trả về list các patcher đã start."""
    from common.net import ChainResult
    chain = chain if chain is not None else ChainResult(final_url='', final_status=200)
    patches = [
        mock.patch('detectors.link.vt_lookup_url', return_value=vt_res or vt()),
        mock.patch('detectors.link.gsb_check', return_value=gsb_res or gsb()),
        mock.patch('detectors.link.urlhaus_check', return_value=uh_res or urlhaus()),
        mock.patch('detectors.link.follow_redirects', side_effect=lambda url, dl, **k: _with_final(chain, url)),
        mock.patch('detectors.link.rdap_domain_age',
                   return_value=rdap or {'source': 'rdap', 'ok': False, 'status': 'HTTP_404'}),
    ]
    for p in patches:
        p.start()
    return patches


def _with_final(template, url):
    chain = copy.deepcopy(template)   # mỗi lời gọi một bản sao: các link khác nhau không được dùng chung trạng thái
    if not chain.final_url:
        chain.final_url = url
        if not chain.hops:
            chain.hops = [{'url': url, 'status': chain.final_status or 200}]
    return chain


def stop(patches):
    for p in patches:
        p.stop()
