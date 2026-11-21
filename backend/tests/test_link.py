import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from common import net
from common.net import ChainResult, Deadline, follow_redirects
from common.scoring import compute_score
from detectors import domains
from detectors.link import analyze_landing, analyze_link, normalize_url, static_analysis
from tests import helpers


def codes(url):
    return {f.code for f in static_analysis(normalize_url(url))[1]}


class DomainTests(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(domains.registrable_domain('a.b.example.com'), 'example.com')
        self.assertEqual(domains.registrable_domain('login.shop.com.vn'), 'shop.com.vn')
        self.assertEqual(domains.registrable_domain('x.co.uk'), 'x.co.uk')

    def test_ip_variants(self):
        for h in ('192.168.1.1', '3232235777', '0xC0A80001', '[::1]'):
            self.assertTrue(domains.is_ip_host(h), h)
        for h in ('example.com', 'abc', 'bit.ly'):
            self.assertFalse(domains.is_ip_host(h), h)

    def test_brand_impersonation(self):
        for host in ('paypal-security-update-fake.com', 'paypa1.com', 'login.paypal.com.evil.xyz',
                     'vietcombank-login.top', 'rnicrosoft.com', 'secure-momo.vn.com'):
            self.assertIsNotNone(domains.brand_impersonation(host), host)

    def test_brand_no_false_positive(self):
        for host in ('paypal.com', 'www.paypal.com', 'mail.vietcombank.com.vn', 'pineapple.com',
                     'vneid.gov.vn', 'groups.example.org', 'docs.github.com'):
            self.assertIsNone(domains.brand_impersonation(host), host)

    def test_trusted_but_free_hosting_not_trusted(self):
        self.assertTrue(domains.is_trusted('www.google.com'))
        self.assertFalse(domains.is_trusted('docs.google.com'))
        self.assertFalse(domains.is_trusted('evil.github.io'))


class StaticTests(unittest.TestCase):
    def test_clean_trusted_url_has_no_findings(self):
        self.assertEqual(codes('https://accounts.google.com/signin/verify'), set())
        self.assertEqual(codes('https://www.paypal.com/myaccount/login'), set())

    def test_phishing_url(self):
        c = codes('http://paypal-security-update-fake.com/login')
        self.assertTrue({'NO_HTTPS', 'BRAND_IMPERSONATION', 'URL_KEYWORDS', 'MANY_HYPHENS'} <= c, c)

    def test_keywords_are_token_based(self):
        self.assertNotIn('URL_KEYWORDS', codes('https://author-blog.example.org/post'))
        self.assertIn('URL_KEYWORDS', codes('https://shop.example.org/update/password'))

    def test_ip_and_userinfo_and_port_and_tld_and_punycode(self):
        self.assertIn('IP_HOST', codes('http://192.168.0.1/login'))
        self.assertIn('IP_HOST', codes('http://3232235777/login'))
        self.assertIn('USERINFO_AT', codes('https://paypal.com@evil.example.net/'))
        self.assertIn('NONSTANDARD_PORT', codes('https://example.org:8444/'))
        self.assertIn('SUSPICIOUS_TLD', codes('https://example.xyz'))
        self.assertIn('PUNYCODE_IDN', codes('https://xn--pypal-4ve.com'))
        self.assertIn('URL_SHORTENER', codes('https://bit.ly/abc'))

    def test_normalize_rejects_bad_input(self):
        for bad in ('', '   ', 'javascript:alert(1)', 'ftp://x.com', 'a b.com', 'http://' + 'a' * 5000):
            with self.assertRaises(ValueError, msg=bad):
                normalize_url(bad)
        self.assertEqual(normalize_url('example.com'), 'http://example.com')


class AnalyzeLinkTests(unittest.TestCase):
    def run_link(self, url, **kw):
        patches = helpers.patch_link_sources(**kw)
        try:
            a = analyze_link(url, Deadline(20))
        finally:
            helpers.stop(patches)
        return a, compute_score(a.findings, reputation_ok=a.reputation_ok)

    def test_clean_site(self):
        a, s = self.run_link('https://www.example.org/')
        self.assertEqual(s.score, 100)
        self.assertEqual(s.confidence, 'HIGH')
        self.assertEqual(a.reputation_ok, 3)

    def test_virustotal_malicious_dominates(self):
        _, s = self.run_link('https://www.example.org/', vt_res=helpers.vt(malicious=6))
        self.assertLessEqual(s.score, 15)
        self.assertEqual(s.risk_level, 'DANGEROUS')

    def test_safe_browsing_forces_danger(self):
        _, s = self.run_link('https://www.example.org/', gsb_res=helpers.gsb(threat=True))
        self.assertLessEqual(s.score, 20)
        self.assertTrue(any('Safe Browsing' in r for r in s.reasons))

    def test_urlhaus(self):
        _, s = self.run_link('https://www.example.org/', uh_res=helpers.urlhaus(listed=True))
        self.assertLessEqual(s.score, 20)

    def test_unavailable_sources_are_not_treated_as_clean(self):
        unavailable = lambda src: {'source': src, 'ok': False, 'status': 'NO_API_KEY', 'malicious': 0, 'suspicious': 0}
        a, s = self.run_link('https://www.example.org/', vt_res=unavailable('vt'),
                             gsb_res=unavailable('gsb'), uh_res=unavailable('uh'))
        self.assertEqual(a.reputation_ok, 0)
        self.assertEqual(s.confidence, 'LOW')

    def test_new_domain(self):
        _, s = self.run_link('https://www.example.org/', rdap={'source': 'rdap', 'ok': True, 'age_days': 2})
        self.assertEqual(s.score, 65)

    def test_redirect_chain_and_cross_domain_and_final_url_checks(self):
        chain = ChainResult(
            hops=[{'url': 'https://ok.example.org/a', 'status': 302}, {'url': 'http://hop.example.net/b', 'status': 301},
                  {'url': 'http://paypal-login-verify.top/', 'status': 200}],
            final_url='http://paypal-login-verify.top/', final_status=200)
        a, s = self.run_link('https://ok.example.org/a', chain=chain)
        got = {f.code for f in a.findings}
        self.assertTrue({'REDIRECT_CHAIN', 'REDIRECT_CROSS_DOMAIN', 'BRAND_IMPERSONATION', 'SUSPICIOUS_TLD'} <= got, got)
        self.assertEqual(a.details['redirection_count'], 2)
        self.assertEqual(s.risk_level, 'DANGEROUS')

    def test_shortener_is_not_penalised_for_crossing_domain(self):
        chain = ChainResult(hops=[{'url': 'https://bit.ly/x', 'status': 301},
                                  {'url': 'https://www.example.org/', 'status': 200}],
                            final_url='https://www.example.org/', final_status=200)
        a, _ = self.run_link('https://bit.ly/x', chain=chain)
        got = {f.code for f in a.findings}
        self.assertIn('URL_SHORTENER', got)
        self.assertNotIn('REDIRECT_CROSS_DOMAIN', got)

    def test_ssl_error(self):
        chain = ChainResult(ssl_error='certificate verify failed')
        a, _ = self.run_link('https://www.example.org/', chain=chain)
        self.assertIn('SSL_INVALID', {f.code for f in a.findings})
        self.assertFalse(a.details['ssl_valid'])

    def test_landing_password_form(self):
        html = '<form action="https://collector.example.net/p"><input type="password" name="p"></form>'
        chain = ChainResult(final_status=200, body=html)
        a, _ = self.run_link('https://www.example.org/login-page', chain=chain)
        got = {f.code for f in a.findings}
        self.assertTrue({'LANDING_PASSWORD_FORM', 'FORM_ACTION_EXTERNAL'} <= got, got)

    def test_source_exception_does_not_crash(self):
        patches = helpers.patch_link_sources()
        try:
            with mock.patch('detectors.link.vt_lookup_url', side_effect=RuntimeError('boom')):
                a = analyze_link('https://www.example.org/', Deadline(20))
        finally:
            helpers.stop(patches)
        self.assertEqual(a.details['virustotal_report']['status'], 'ERROR')
        self.assertEqual(a.reputation_ok, 2)

    def test_static_mode_never_touches_network(self):
        with mock.patch('detectors.link.vt_lookup_url', side_effect=AssertionError('không được gọi mạng')):
            a = analyze_link('http://192.168.1.5/login', Deadline(5), mode='static')
        self.assertIn('IP_HOST', {f.code for f in a.findings})

    def test_landing_helper_trusted_domain_skipped(self):
        info, f = analyze_landing('<input type="password">', 'https://accounts.google.com/')
        self.assertTrue(info['has_password_form'])
        self.assertEqual(f, [])


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == '/a':
            self.send_response(302); self.send_header('Location', '/b'); self.end_headers()
        elif self.path == '/b':
            self.send_response(301); self.send_header('Location', '/c'); self.end_headers()
        elif self.path == '/loop':
            self.send_response(302); self.send_header('Location', '/loop'); self.end_headers()
        else:
            body = b'<html><form><input type="password"></form></html>'
            self.send_response(200); self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)


class RedirectFollowerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(('127.0.0.1', 0), _Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_private_addresses_blocked_by_default(self):
        res = follow_redirects(f'http://127.0.0.1:{self.port}/a', Deadline(10))
        self.assertTrue(res.blocked)
        self.assertEqual(res.hops, [])
        res = follow_redirects('http://169.254.169.254/latest/meta-data/', Deadline(10))
        self.assertTrue(res.blocked)
        res = follow_redirects('http://example.org:22/', Deadline(10))
        self.assertIn('cổng', res.blocked)

    def test_follows_chain_when_private_allowed(self):
        with mock.patch.object(net, 'ALLOW_PRIVATE', True):
            res = follow_redirects(f'http://127.0.0.1:{self.port}/a', Deadline(10))
        self.assertEqual([h['status'] for h in res.hops], [302, 301, 200])
        self.assertEqual(res.redirect_count, 2)
        self.assertTrue(res.final_url.endswith('/c'))
        self.assertIn('password', res.body)

    def test_redirect_loop_is_bounded(self):
        with mock.patch.object(net, 'ALLOW_PRIVATE', True):
            res = follow_redirects(f'http://127.0.0.1:{self.port}/loop', Deadline(10), max_hops=4)
        self.assertEqual(res.error, 'Quá nhiều bước chuyển hướng')
        self.assertEqual(len(res.hops), 5)

    def test_redirect_to_internal_target_is_blocked_midway(self):
        calls = {'n': 0}
        real = net.resolve_public_ip

        def fake_resolve(host):
            calls['n'] += 1
            if calls['n'] == 1:
                return '127.0.0.1'       
            return real(host)
        
        with mock.patch.object(net, 'resolve_public_ip', fake_resolve), \
                mock.patch.object(net, 'ALLOWED_PORTS', {self.port}):
            res = follow_redirects(f'http://localhost:{self.port}/a', Deadline(10))
        self.assertTrue(res.blocked)
        self.assertEqual(len(res.hops), 1)


if __name__ == '__main__':
    unittest.main()
