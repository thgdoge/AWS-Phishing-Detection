from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from common.net import Deadline
from common.reputation import malwarebazaar_check, vt_lookup_file
from common.scoring import Finding

from .base import Analysis

SAMPLE_BYTES = 2 * 1024 * 1024

HIGH_RISK_EXTENSIONS: Set[str] = {
    '.exe', '.scr', '.vbs', '.vbe', '.bat', '.cmd', '.ps1', '.iso', '.img', '.vhd', '.lnk', '.hta',
    '.js', '.jse', '.wsf', '.jar', '.msi', '.msp', '.dll', '.reg', '.pif', '.com', '.cpl', '.chm',
}
EXEC_EXTENSIONS: Set[str] = {'.exe', '.dll', '.scr', '.sys', '.ocx', '.cpl', '.com', '.pif', '.bin',
                             '.elf', '.so', '.dylib', '.o', '.lnk', '.msi'}
DOC_LIKE_EXTENSIONS: Set[str] = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf',
                                 '.jpg', '.jpeg', '.png', '.gif', '.zip', '.rar', '.csv', '.mp3', '.mp4'}
OFFICE_OOXML: Set[str] = {'.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm'}
EXEC_IN_ARCHIVE: Set[str] = {'.exe', '.scr', '.vbs', '.vbe', '.js', '.jse', '.bat', '.cmd', '.ps1', '.hta',
                             '.lnk', '.msi', '.dll', '.jar', '.wsf', '.pif', '.com', '.cpl', '.iso', '.img'}
RLO_CHARS = '\u202a\u202b\u202d\u202e\u2066\u2067\u2068'

EXEC_TYPES = {'PE', 'ELF', 'MACHO', 'LNK'}
EXT_EXPECTED: Dict[str, Set[str]] = {
    '.pdf': {'PDF'}, '.png': {'PNG'}, '.jpg': {'JPEG'}, '.jpeg': {'JPEG'}, '.gif': {'GIF'},
    '.docx': {'ZIP'}, '.xlsx': {'ZIP'}, '.pptx': {'ZIP'}, '.docm': {'ZIP'}, '.xlsm': {'ZIP'}, '.pptm': {'ZIP'},
    '.zip': {'ZIP'}, '.jar': {'ZIP'}, '.apk': {'ZIP'},
    '.doc': {'OLE2', 'ZIP', 'RTF'}, '.xls': {'OLE2', 'ZIP'}, '.ppt': {'OLE2', 'ZIP'}, '.rtf': {'RTF'},
    '.exe': {'PE'}, '.dll': {'PE'}, '.scr': {'PE'}, '.msi': {'OLE2'}, '.lnk': {'LNK'},
    '.rar': {'RAR'}, '.7z': {'7Z'}, '.gz': {'GZIP'},
}
FORMAT_LABEL = {
    'PE': 'Windows_PE_Executable', 'ELF': 'ELF_Linux_Executable', 'MACHO': 'MachO_Executable',
    'LNK': 'Windows_Shortcut_LNK', 'PDF': 'PDF_Document', 'ZIP': 'ZIP_or_Office_OpenXML',
    'OLE2': 'OLE2_Legacy_Office_Document', 'PNG': 'PNG_Image', 'JPEG': 'JPEG_Image', 'GIF': 'GIF_Image',
    'RTF': 'RTF_Document', 'RAR': 'RAR_Archive', '7Z': '7Z_Archive', 'GZIP': 'GZIP_Archive',
    'HTML': 'HTML_Document', 'SHEBANG': 'Script_Shebang', 'UNKNOWN': 'Text_or_Generic_Binary',
}



@dataclass(frozen=True)
class YaraLite:
    name: str
    all_of: Tuple[bytes, ...] = ()
    any_of: Tuple[bytes, ...] = ()
    also_any: Tuple[bytes, ...] = ()
    skip_types: Tuple[str, ...] = ()   

    def matches(self, data: bytes, magic: str) -> bool:
        if magic in self.skip_types:
            return False
        return ((not self.all_of or all(s in data for s in self.all_of))
                and (not self.any_of or any(s in data for s in self.any_of))
                and (not self.also_any or any(s in data for s in self.also_any)))


YARA_LITE_RULES: List[YaraLite] = [
    YaraLite('PowerShell_Encoded_Command', all_of=(b'powershell',),
             any_of=(b'-encodedcommand', b'-enc ', b'-ec ')),
    YaraLite('Hidden_Window_Execution', all_of=(b'powershell',),
             any_of=(b'-windowstyle hidden', b'-w hidden')),
    YaraLite('Download_Cradle', any_of=(b'downloadstring', b'downloadfile', b'net.webclient',
                                        b'invoke-webrequest', b'start-bitstransfer'),
             also_any=(b'iex(', b'iex ', b'invoke-expression')),
    YaraLite('WScript_Shell_Exec', all_of=(b'wscript.shell',), any_of=(b'.run(', b'.run ', b'.exec(')),
    YaraLite('URLDownloadToFile_API', any_of=(b'urldownloadtofile',), skip_types=('PE',)),
    YaraLite('Shellcode_Loader_APIs', all_of=(b'virtualalloc',),
             any_of=(b'createthread', b'virtualprotect', b'writeprocessmemory'), skip_types=('PE', 'ELF')),
    YaraLite('Base64_Decode_Exec', all_of=(b'frombase64string',),
             any_of=(b'iex', b'invoke-expression', b'assembly]::load', b'reflection.assembly')),
    YaraLite('Office_AutoExec_Macro', any_of=(b'autoopen', b'auto_open', b'document_open', b'workbook_open'),
             also_any=(b'shell', b'createobject', b'wscript', b'powershell', b'cmd.exe', b'cmd /c')),
    YaraLite('JS_Obfuscated_Eval', all_of=(b'eval(',), any_of=(b'unescape(', b'atob(', b'fromcharcode(')),
    YaraLite('ADODB_Stream_Dropper', all_of=(b'adodb.stream',), any_of=(b'savetofile', b'.write')),
    YaraLite('Credential_Dumper_Strings', any_of=(b'sekurlsa', b'mimikatz'), skip_types=()),
]



def detect_magic(header: bytes, sample: bytes) -> str:
    if header.startswith(b'MZ'):
        return 'PE'
    if header.startswith(b'\x7fELF'):
        return 'ELF'
    if header[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
        return 'MACHO'
    if header.startswith(b'\x4c\x00\x00\x00\x01\x14\x02\x00'):
        return 'LNK'
    if b'%PDF' in sample[:1024]:
        return 'PDF'
    if header.startswith((b'PK\x03\x04', b'PK\x05\x06')):
        return 'ZIP'
    if header.startswith(b'\xd0\xcf\x11\xe0'):
        return 'OLE2'
    if header.startswith(b'\x89PNG'):
        return 'PNG'
    if header.startswith(b'\xff\xd8\xff'):
        return 'JPEG'
    if header.startswith((b'GIF87a', b'GIF89a')):
        return 'GIF'
    if header.startswith(b'{\\rtf'):
        return 'RTF'
    if header.startswith(b'Rar!\x1a\x07'):
        return 'RAR'
    if header.startswith(b'7z\xbc\xaf\x27\x1c'):
        return '7Z'
    if header.startswith(b'\x1f\x8b'):
        return 'GZIP'
    head = sample[:2048].lstrip(b'\xef\xbb\xbf \t\r\n').lower()
    if head.startswith((b'<!doctype html', b'<html', b'<head', b'<body', b'<script', b'<form')):
        return 'HTML'
    if header.startswith(b'#!'):
        return 'SHEBANG'
    return 'UNKNOWN'


def calculate_entropy(counts: Dict[int, int], total: int) -> float:
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c)


def _stream_scan(path: str) -> Dict[str, Any]:
    sha, md5 = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    counts: Counter = Counter()
    sample = bytearray()
    size = 0
    with open(path, 'rb') as fh:
        while chunk := fh.read(1 << 20):
            sha.update(chunk)
            md5.update(chunk)
            counts.update(chunk)      # Counter(bytes) chạy ở tốc độ C, nhanh hơn vòng for Python rất nhiều
            size += len(chunk)
            if len(sample) < SAMPLE_BYTES:
                sample += chunk[:SAMPLE_BYTES - len(sample)]
    return {'sha256': sha.hexdigest(), 'md5': md5.hexdigest(), 'size': size,
            'entropy': calculate_entropy(counts, size), 'sample': bytes(sample)}


def _file_contains(path: str, needle: bytes) -> bool:
    keep = len(needle) - 1
    tail = b''
    with open(path, 'rb') as fh:
        while chunk := fh.read(1 << 20):
            if needle in tail + chunk:
                return True
            tail = chunk[-keep:] if keep else b''
    return False


def filename_findings(filename: str) -> List[Finding]:
    name = os.path.basename(filename or '')
    lower = name.lower()
    ext = os.path.splitext(lower)[1]
    findings: List[Finding] = []
    if any(ch in name for ch in RLO_CHARS):
        findings.append(Finding('RLO_FILENAME'))
    parts = lower.rstrip().split('.')
    if len(parts) >= 3 and ext in HIGH_RISK_EXTENSIONS and ('.' + parts[-2].strip()) in DOC_LIKE_EXTENSIONS:
        findings.append(Finding('DOUBLE_EXTENSION', detail=name))
    if ext in HIGH_RISK_EXTENSIONS:
        findings.append(Finding('HIGH_RISK_EXT', detail=ext))
    return findings


def inspect_zip(path: str, ext: str) -> Tuple[Dict[str, Any], List[Finding]]:
    info: Dict[str, Any] = {'entries': 0, 'encrypted': False, 'executables': [],
                            'has_vba_project': False, 'remote_template': None}
    findings: List[Finding] = []
    try:
        with zipfile.ZipFile(path) as zf:
            entries = zf.infolist()[:1000]
            info['entries'] = len(entries)
            for e in entries:
                name = e.filename.lower()
                if e.flag_bits & 0x1:
                    info['encrypted'] = True
                    continue
                if os.path.splitext(name)[1] in EXEC_IN_ARCHIVE and ext not in OFFICE_OOXML:
                    info['executables'].append(e.filename)
                if name.endswith('vbaproject.bin'):
                    info['has_vba_project'] = True
                if name.endswith('.rels') and e.file_size <= 65536:
                    xml = zf.read(e)[:65536].decode('utf-8', 'replace')
                    for rel in re.findall(r'<Relationship\b[^>]*>', xml, re.I):
                        low = rel.lower()
                        if ('targetmode="external"' in low and 'target="http' in low
                                and re.search(r'attachedtemplate|oleobject|/frame|externallink', low)):
                            m = re.search(r'target="([^"]+)"', rel, re.I)
                            info['remote_template'] = (m.group(1) if m else '')[:200]
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
        info['unreadable'] = True
        return info, findings

    if info['executables']:
        shown = ', '.join(os.path.basename(n) for n in info['executables'][:3])
        findings.append(Finding('ARCHIVE_CONTAINS_EXECUTABLE', detail=shown))
    if info['encrypted'] and ext not in OFFICE_OOXML:
        findings.append(Finding('ARCHIVE_ENCRYPTED'))
    if info['has_vba_project']:
        findings.append(Finding('OFFICE_MACRO'))
    if info['remote_template']:
        findings.append(Finding('OFFICE_REMOTE_TEMPLATE'))
    return info, findings


def inspect_pdf(sample: bytes) -> List[Finding]:
    low = sample.lower()
    hits = []
    if b'/javascript' in low or re.search(rb'/js[\s<(/\[]', low):
        hits.append('JavaScript')
    if b'/launch' in low:
        hits.append('Launch')
    if b'/embeddedfile' in low and b'/openaction' in low:
        hits.append('EmbeddedFile+OpenAction')
    return [Finding('PDF_ACTIVE_CONTENT', detail=', '.join(hits))] if hits else []


def inspect_html(sample: bytes) -> List[Finding]:
    text = sample.decode('utf-8', 'replace').lower()
    if '<form' in text and re.search(r'<input[^>]+type\s*=\s*["\']?password', text):
        return [Finding('HTML_CREDENTIAL_FORM')]
    return []



def run_clamav(path: str, deadline: Deadline) -> Dict[str, Any]:
    exe = shutil.which('clamscan')
    if not exe:
        return {'status': 'SKIPPED', 'infected': False}
    try:
        res = subprocess.run([exe, '--no-summary', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, timeout=max(5.0, min(60.0, deadline.remaining() - 2)))
    except subprocess.TimeoutExpired:
        return {'status': 'TIMEOUT', 'infected': False}
    except OSError as exc:
        return {'status': f'ERROR ({type(exc).__name__})', 'infected': False}
    if res.returncode == 1:
        line = res.stdout.strip().splitlines()[0] if res.stdout.strip() else ''
        sig = line.split(':', 1)[-1].replace('FOUND', '').strip() or 'unknown'
        return {'status': 'INFECTED', 'infected': True, 'signature': sig}
    if res.returncode == 0:
        return {'status': 'CLEAN', 'infected': False}
    return {'status': f'ERROR (exit {res.returncode})', 'infected': False}



def _static_findings(path: str, filename: str, scan: Dict[str, Any], magic: str) -> Tuple[List[Finding], Dict[str, Any]]:
    ext = os.path.splitext(os.path.basename(filename).lower())[1]
    sample: bytes = scan['sample']
    findings = filename_findings(filename)
    extra: Dict[str, Any] = {}

 
    expected = EXT_EXPECTED.get(ext)
    if expected is not None and magic not in expected:
        if magic in EXEC_TYPES:
            findings.append(Finding('EXEC_DISGUISED', detail=ext))
        else:
            findings.append(Finding('MAGIC_MISMATCH', detail=f'{ext} ≠ {FORMAT_LABEL.get(magic, magic)}'))
    elif expected is None and ext and magic in EXEC_TYPES and ext not in EXEC_EXTENSIONS:
        findings.append(Finding('EXEC_DISGUISED', detail=ext))

 
    data = sample.lower()
    if magic not in ('PE', 'ELF', 'MACHO') and data.count(b'\x00') > len(data) * 0.3:
        data = data.replace(b'\x00', b'')
    matched = [r.name for r in YARA_LITE_RULES if r.matches(data, magic)]
    if matched:
        findings.append(Finding('YARA_MATCH', value=len(matched), detail=', '.join(matched)))


    if magic == 'ZIP':
        zinfo, zfind = inspect_zip(path, ext)
        extra['archive'] = {k: (v[:5] if isinstance(v, list) else v) for k, v in zinfo.items()}
        findings += zfind
    elif magic == 'OLE2' and _file_contains(path, '_VBA_PROJECT'.encode('utf-16-le')):
        findings.append(Finding('OFFICE_MACRO'))
    elif magic == 'PDF':
        findings += inspect_pdf(sample)
    elif magic == 'HTML' or ext in ('.html', '.htm', '.shtml', '.xhtml'):
        findings += inspect_html(sample)


    if scan['entropy'] > 7.5 and (ext in HIGH_RISK_EXTENSIONS or magic in EXEC_TYPES):
        findings.append(Finding('HIGH_ENTROPY', detail=f"{scan['entropy']:.2f}"))
    return findings, {'matched_yara_rules': matched, **extra}


def analyze_file(path: str, filename: str, deadline: Deadline, *, allow_upload: Optional[bool] = None) -> Analysis:
    filename = os.path.basename(filename)
    scan = _stream_scan(path)
    magic = detect_magic(scan['sample'][:16], scan['sample'])
    findings, extra = _static_findings(path, filename, scan, magic)

  
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_vt = pool.submit(_guard, vt_lookup_file, scan['sha256'], path, filename, scan['size'], deadline,
                           allow_upload=allow_upload, source='virustotal')
        f_mb = pool.submit(_guard, malwarebazaar_check, scan['sha256'], deadline, source='malwarebazaar')
        f_av = pool.submit(run_clamav, path, deadline)
        vt, mb, av = f_vt.result(), f_mb.result(), f_av.result()

    if vt.get('malicious', 0) > 0:
        findings.append(Finding('FILE_VT_MALICIOUS', value=vt['malicious']))
    if vt.get('suspicious', 0) > 0:
        findings.append(Finding('FILE_VT_SUSPICIOUS', value=vt['suspicious']))
    if mb.get('status') == 'MALWARE_FOUND':
        findings.append(Finding('MALWAREBAZAAR_HIT', detail=mb.get('signature') or 'unknown'))
    if av.get('infected'):
        findings.append(Finding('CLAMAV_INFECTED', detail=av.get('signature', '')))

    reputation_ok = sum(1 for r in (vt, mb) if r.get('ok')) + (1 if av.get('status') == 'CLEAN' else 0)
    details = {
        'filename': filename, 'file_size_bytes': scan['size'],
        'detected_format': FORMAT_LABEL.get(magic, magic),
        'sha256': scan['sha256'], 'md5': scan['md5'],
        'shannon_entropy': round(scan['entropy'], 3),
        'virustotal_report': vt, 'malwarebazaar': mb,
        'clamav_scan': av.get('status'),
        **extra,
    }
    return Analysis(details, findings, reputation_ok, True)


def _guard(fn, *args, source: str, **kw) -> Dict[str, Any]:
    try:
        return fn(*args, **kw)
    except Exception as exc:  
        return {'source': source, 'ok': False, 'status': 'ERROR', 'error': type(exc).__name__,
                'malicious': 0, 'suspicious': 0}


def analyze_bytes(data: bytes, filename: str, deadline: Deadline) -> Analysis:
    
    fd, path = tempfile.mkstemp(prefix='att_')
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
        return analyze_file(path, filename, deadline, allow_upload=False)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
