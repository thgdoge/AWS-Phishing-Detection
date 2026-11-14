import unittest
from email.message import EmailMessage
from unittest import mock

from common.net import Deadline
from common.scoring import compute_score
from detectors import email_msg as em
from tests import helpers


def run(raw, **kw):
    patches = helpers.patch_link_sources(**kw)
    try:
        with mock.patch('detectors.file.vt_lookup_file', return_value=helpers.vt(ok=False)), \
                mock.patch('detectors.file.malwarebazaar_check', return_value=helpers.OK_CLEAN), \
                mock.patch('detectors.file.run_clamav', return_value={'status': 'SKIPPED', 'infected': False}):
            a = em.analyze_email(raw, Deadline(20))
    finally:
        helpers.stop(patches)
    s = compute_score(a.findings, reputation_ok=a.reputation_ok, reputation_needed=a.reputation_needed)
    return a, s, {f.code for f in a.findings}


class TextTests(unittest.TestCase):
    def test_vietnamese_with_diacritics_is_detected(self):
        info, f = em.analyze_text('Cảnh báo bảo mật', 'Tài khoản của bạn sẽ bị khóa. Vui lòng xác minh ngay '
                                  'và nhập mật khẩu, mã OTP để tiếp tục.')
        self.assertTrue(info['asks_sensitive_credentials'])
        self.assertIn('xac minh ngay', info['urgent_phrases_found'])
        self.assertIn('canh bao bao mat', info['urgent_phrases_found'])

    def test_reason_shows_accented_phrase(self):
        _, f = em.analyze_text('', 'Cảnh báo bảo mật: hãy xác minh ngay')
        self.assertIn('cảnh báo bảo mật', f[0].detail)

    def test_unaccented_and_english(self):
        info, _ = em.analyze_text('', 'Please verify your account immediately. Enter your password below.')
        self.assertTrue(info['asks_sensitive_credentials'])
        self.assertIn('immediately', info['urgent_phrases_found'])

    def test_no_false_positive_pin_in_shipping(self):
        info, f = em.analyze_text('Your order', 'Your shipping update: the package is spinning through the hub. '
                                  'We will send tracking soon.')
        self.assertFalse(info['asks_sensitive_credentials'])
        self.assertEqual(f, [])

    def test_password_mention_without_request_is_ok(self):
        info, _ = em.analyze_text('', 'Your password was changed successfully on Monday.')
        self.assertFalse(info['asks_sensitive_credentials'])


class ParseTests(unittest.TestCase):
    RAW = ('From: "PayPal Support" <service@paypa1-secure.top>\n'
           'Reply-To: help@gmail-collector.net\n'
           'Return-Path: <bounce@mailer.example.net>\n'
           'Subject: Urgent: account suspended\n'
           'Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=paypa1-secure.top; '
           'dkim=none; dmarc=fail (p=none)\n'
           'Content-Type: text/plain; charset=utf-8\n\n'
           'Please verify your account at http://paypa1-secure.top/login now.\n')

    def test_header_detection(self):
        self.assertTrue(em.looks_like_headers(self.RAW))
        self.assertFalse(em.looks_like_headers('Xin chào,\nFrom: tôi nói rằng\n\nnội dung'))
        self.assertFalse(em.looks_like_headers('Chỉ có nội dung email thôi'))

    def test_full_phishing_email(self):
        a, s, got = run(self.RAW)
        expected = {'SPF_FAIL', 'DMARC_FAIL', 'REPLYTO_MISMATCH', 'RETURNPATH_MISMATCH', 'SENDER_BRAND_MISMATCH',
                    'DISPLAY_NAME_SPOOF', 'URGENT_PHRASES', 'EMAIL_LINK_RISK'}
        self.assertTrue(expected <= got, expected - got)
        self.assertEqual(s.risk_level, 'DANGEROUS')
        self.assertTrue(a.details['spf_fail_detected'])
        self.assertTrue(a.details['dmarc_fail_detected'])
        self.assertEqual(a.details['extracted_urls_count'], 1)

    def test_legit_email_with_passing_auth(self):
        raw = ('From: Google <no-reply@accounts.google.com>\nSubject: Security alert\n'
               'Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass\n'
               'Content-Type: text/plain\n\nA new sign-in was detected. Review at https://myaccount.google.com/\n')
        a, s, got = run(raw)
        self.assertNotIn('SPF_FAIL', got)
        self.assertNotIn('DISPLAY_NAME_SPOOF', got)
        self.assertNotIn('SENDER_BRAND_MISMATCH', got)
        self.assertGreaterEqual(s.score, 70)

    def test_dkim_fail_ignored_when_another_signature_passes(self):
        self.assertEqual(em._auth_verdict('dkim=pass; dkim=fail', 'dkim'), 'pass')
        self.assertEqual(em._auth_verdict('dkim=fail', 'dkim'), 'fail')
        self.assertIsNone(em._auth_verdict('spf=pass', 'dkim'))

    def test_body_only_email_skips_header_checks(self):
        a, s, got = run('Chào bạn, hãy xem tài liệu tại https://www.example.org/doc')
        self.assertFalse(a.details['headers_present'])
        self.assertFalse({'REPLYTO_MISMATCH', 'SPF_FAIL', 'DISPLAY_NAME_SPOOF'} & got)

    def test_pasted_authentication_results_without_full_headers(self):
        a, _, got = run('spf=fail dkim=fail dmarc=fail\n\nHello, click https://www.example.org/')
        self.assertTrue({'SPF_FAIL', 'DKIM_FAIL', 'DMARC_FAIL'} <= got)

    def test_text_only_email_confidence_medium_not_low(self):
        _, s, _ = run('Xin chào, hẹn gặp bạn vào thứ Hai nhé.')
        self.assertEqual(s.score, 100)
        self.assertEqual(s.confidence, 'MEDIUM')


class HtmlTests(unittest.TestCase):
    def test_link_text_mismatch(self):
        raw = ('From: a@example.org\nSubject: hi\nContent-Type: text/html; charset=utf-8\n\n'
               '<p>Click <a href="http://evil-login.top/x">https://www.paypal.com/security</a></p>')
        a, _, got = run(raw)
        self.assertIn('LINK_TEXT_MISMATCH', got)
        self.assertTrue(a.details['link_text_mismatches'])

    def test_matching_anchor_text_ok(self):
        anchors = [('https://www.example.org/a', 'www.example.org')]
        self.assertEqual(em.link_text_mismatches(anchors), [])

    def test_script_text_ignored(self):
        text, _ = em.extract_html(['<script>var a="verify your account";</script><p>Xin chào</p>'])
        self.assertNotIn('verify', text)

    def test_url_extraction(self):
        urls = em.extract_urls('See www.example.org/a, and (https://x.example.net/b). mailto:a@b.com',
                               [('https://x.example.net/b', 'b'), ('mailto:a@b.com', 'm')])
        self.assertEqual(urls, ['https://x.example.net/b', 'http://www.example.org/a'])


class AttachmentTests(unittest.TestCase):
    def make(self, filename, data):
        msg = EmailMessage()
        msg['From'] = 'a@example.org'
        msg['To'] = 'b@example.org'
        msg['Subject'] = 'Invoice'
        msg.set_content('Please see the attachment.')
        msg.add_attachment(data, maintype='application', subtype='octet-stream', filename=filename)
        return msg.as_string()

    def test_executable_disguised_as_pdf(self):
        raw = self.make('invoice.pdf', b'MZ' + b'\x90' * 200)
        a, s, got = run(raw)
        self.assertIn('EMAIL_ATTACHMENT_RISK', got)
        self.assertEqual(a.details['attachments'][0]['filename'], 'invoice.pdf')
        self.assertEqual(len(a.details['attachments'][0]['sha256']), 64)
        self.assertLess(s.score, 80)

    def test_double_extension_by_name_only(self):
        findings = {f.code for f in em.filename_findings('hoa_don.pdf.exe')}
        self.assertTrue({'DOUBLE_EXTENSION', 'HIGH_RISK_EXT'} <= findings)

    def test_harmless_attachment_no_risk(self):
        raw = self.make('notes.txt', b'hello world, nothing to see here')
        _, _, got = run(raw)
        self.assertNotIn('EMAIL_ATTACHMENT_RISK', got)


if __name__ == '__main__':
    unittest.main()
