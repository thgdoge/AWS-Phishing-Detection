import hashlib
import json
import math
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')

JOBS_TABLE = os.environ.get('JOBS_TABLE', 'PhishingScanJobs')
CACHE_TABLE = os.environ.get('CACHE_TABLE', 'PhishingScanCache')
REPORTS_BUCKET = os.environ.get('REPORTS_BUCKET', '')

# Cau hinh VirusTotal API Key chinh va danh sach API Key du phong
VT_API_KEY = os.environ.get('VT_API_KEY', '')
VT_BACKUP_API_KEYS = os.environ.get('VT_BACKUP_API_KEYS', '')
VT_UPLOAD_UNKNOWN_FILES = os.environ.get('VT_UPLOAD_UNKNOWN_FILES', 'true').lower() == 'true'

jobs_tbl = dynamodb.Table(JOBS_TABLE)
cache_tbl = dynamodb.Table(CACHE_TABLE)

HIGH_RISK_EXTENSIONS = {
    '.exe', '.scr', '.vbs', '.bat', '.cmd', '.ps1', '.iso',
    '.lnk', '.hta', '.js', '.jar', '.msi', '.dll', '.reg',
}

STATIC_YARA_SIGNATURES = {
    'Suspicious_PowerShell_Encoded': b'powershell',
    'Hidden_Window_Execution': b'-windowstyle hidden',
    'Invoke_Expression_Eval': b'iex(',
    'Windows_Script_Host': b'wscript.shell',
    'AutoOpen_Office_Macro': b'autoopen',
    'Document_Open_Macro': b'document_open',
    'URLDownloadToFile_API': b'urldownloadtofile',
    'VirtualAlloc_Shellcode': b'virtualalloc',
    'Base64_FromBase64String': b'frombase64string',
}


def get_vt_api_keys():
    """Lay danh sach API Key theo thu tu uu tien: Key chinh -> Cac Key du phong."""
    keys = []
    if VT_API_KEY.strip():
        keys.append(VT_API_KEY.strip())
    if VT_BACKUP_API_KEYS.strip():
        for k in VT_BACKUP_API_KEYS.split(','):
            clean_k = k.strip()
            if clean_k and clean_k not in keys:
                keys.append(clean_k)
    return keys


def lambda_handler(event, context):
    """
    AWS Lambda Handler cho FileDetectWorker (Xu ly File tu phishing-file-queue).
    Ket hop VirusTotal File API v3 (kem API Key du phong), MalwareBazaar va Static Analysis.
    """
    for record in event.get('Records', []):
        job_id = None
        local_path = None
        try:
            body = json.loads(record.get('body', '{}'))
            job_id = body.get('job_id')
            bucket = body.get('s3_bucket')
            key = body.get('s3_key')

            if not job_id or not bucket or not key:
                continue

            # 1. Cap nhat trang thai PROCESSING
            jobs_tbl.update_item(
                Key={'job_id': job_id},
                UpdateExpression='SET #s = :s',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':s': 'PROCESSING'},
            )

            # 2. Cho file duoc Frontend upload xong len S3 (Tranh Race Condition 404)
            file_ready = wait_for_s3_object(bucket, key, max_wait_seconds=25)
            if not file_ready:
                raise FileNotFoundError(
                    f'Khong tim thay file tren S3 sau 25s: s3://{bucket}/{key}'
                )

            # 3. Tai file tu S3 ve thu muc tam /tmp cua Lambda
            local_filename = os.path.basename(key)
            local_path = f'/tmp/{job_id}_{local_filename}'
            s3.download_file(bucket, key, local_path)

            # 4. Phan tich File: Quet VirusTotal API (co Failover) + Phan tich tinh
            analysis_details = analyze_file(local_path, local_filename)
            file_hash = analysis_details.get('sha256')

            # 5. Scoring Engine: Tinh Trust Score (0 - 100)
            trust_score, risk_level = calculate_file_trust_score(analysis_details)

            scanned_at = int(time.time())
            final_result = {
                'trust_score': trust_score,
                'risk_level': risk_level,
                'details': analysis_details,
                'scanned_at': scanned_at,
            }

            # 6. Luu ket qua COMPLETED vao DynamoDB
            jobs_tbl.update_item(
                Key={'job_id': job_id},
                UpdateExpression='SET #s = :s, trust_score = :ts, #r = :r',
                ExpressionAttributeNames={'#s': 'status', '#r': 'result'},
                ExpressionAttributeValues={
                    ':s': 'COMPLETED',
                    ':ts': trust_score,
                    ':r': final_result,
                },
            )

            # 7. Luu Cache theo SHA-256 cua noi dung file that trong 24h
            if file_hash:
                cache_tbl.put_item(
                    Item={
                        'target_hash': file_hash,
                        'job_id': job_id,
                        'result': final_result,
                        'expires_at': scanned_at + 86400,
                    }
                )

            # 8. Luu log JSON len S3 (neu co REPORTS_BUCKET)
            if REPORTS_BUCKET:
                try:
                    s3.put_object(
                        Bucket=REPORTS_BUCKET,
                        Key=f'logs/{job_id}.json',
                        Body=json.dumps(final_result, indent=2),
                        ContentType='application/json',
                    )
                except Exception as s3_err:
                    print(f'Canh bao luu log S3: {str(s3_err)}')

        except Exception as e:
            print(f'Loi xu ly file job {job_id}: {str(e)}')
            if job_id:
                try:
                    jobs_tbl.update_item(
                        Key={'job_id': job_id},
                        UpdateExpression='SET #s = :s, trust_score = :ts, #r = :r',
                        ExpressionAttributeNames={'#s': 'status', '#r': 'result'},
                        ExpressionAttributeValues={
                            ':s': 'COMPLETED',
                            ':ts': 0,
                            ':r': {
                                'trust_score': 0,
                                'risk_level': 'SCAN ERROR',
                                'details': {'error': str(e)},
                                'scanned_at': int(time.time()),
                            },
                        },
                    )
                except Exception:
                    pass
            raise e
        finally:
            if local_path and os.path.exists(local_path):
                try:
                    os.remove(local_path)
                except Exception:
                    pass

    return {'statusCode': 200}


def wait_for_s3_object(bucket, key, max_wait_seconds=25):
    """Kiem tra lien tuc moi 2 giay cho den khi Frontend PUT xong file len S3."""
    elapsed = 0
    while elapsed < max_wait_seconds:
        try:
            s3.head_object(Bucket=bucket, Key=key)
            return True
        except ClientError:
            time.sleep(2)
            elapsed += 2
    return False


def query_virustotal_file(sha256_hash, local_path, filename, file_size):
    """
    Tra cuu File Hash (SHA-256) tren VirusTotal API v3 voi co che xoay vong API Key du phong.
    Neu file chua co tren VT (404) va dung luong < 30MB, ho tro upload file len VT.
    Neu tat ca key VT het quota (429), tu dong chuyen sang MalwareBazaar API (Abuse.ch).
    """
    api_keys = get_vt_api_keys()
    quota_errors = []

    for idx, api_key in enumerate(api_keys):
        key_label = 'PRIMARY_KEY' if idx == 0 else f'BACKUP_KEY_{idx}'
        headers = {
            'x-apikey': api_key,
            'Accept': 'application/json',
            'User-Agent': 'TrustCheck-PhishingScanner/2.0',
        }

        try:
            # Buoc 1: Tra cuu Hash SHA-256 tren VirusTotal
            req = urllib.request.Request(
                f'https://www.virustotal.com/api/v3/files/{sha256_hash}',
                headers=headers,
                method='GET',
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                attrs = data.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                threat_label = (
                    attrs.get('popular_threat_classification', {})
                    .get('suggested_threat_label', 'unknown')
                )
                return {
                    'scan_engine': 'VirusTotal API v3 (Hash Lookup)',
                    'api_key_used': key_label,
                    'status': 'FOUND',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'threat_label': threat_label,
                    'permalink': f'https://www.virustotal.com/gui/file/{sha256_hash}',
                }

        except urllib.error.HTTPError as http_err:
            # Neu Hash chua co trong DB cua VirusTotal (404)
            if http_err.code == 404:
                if VT_UPLOAD_UNKNOWN_FILES and file_size < 30 * 1024 * 1024:
                    upload_res = upload_file_to_virustotal(
                        local_path, filename, api_key, key_label, sha256_hash
                    )
                    if upload_res.get('quota_exceeded'):
                        quota_errors.append(f'{key_label}: Upload HTTP 429')
                        continue
                    return upload_res

                # Neu khong upload hoac file qua lon -> Kiem tra tiep tren MalwareBazaar
                mb_res = query_malwarebazaar_fallback(sha256_hash)
                mb_res['vt_note'] = f'Hash not found on VirusTotal ({key_label})'
                return mb_res

            # Neu API Key hien tai het Quota (429) hoac loi xac thuc (401/403) -> Thu Key du phong
            elif http_err.code in (429, 401, 403):
                quota_errors.append(f'{key_label}: HTTP {http_err.code} (Quota Exceeded)')
                print(f'Canh bao: {key_label} het quota ({http_err.code}), chuyen sang key du phong...')
                continue
            else:
                quota_errors.append(f'{key_label}: HTTP {http_err.code}')
                continue

        except Exception as err:
            quota_errors.append(f'{key_label}: {str(err)[:80]}')
            continue

    # LOP DU PHONG THU CAP: Goi API MalwareBazaar khi tat ca Key VirusTotal het quota
    fallback_res = query_malwarebazaar_fallback(sha256_hash)
    fallback_res['vt_failover_notes'] = quota_errors or ['No VT_API_KEY configured']
    return fallback_res


def upload_file_to_virustotal(local_path, filename, api_key, key_label, sha256_hash):
    """Upload file moi (<30MB) len VirusTotal API v3 bang multipart/form-data."""
    boundary = f'----TrustCheckBoundary{uuid.uuid4().hex}'
    try:
        with open(local_path, 'rb') as f:
            file_bytes = f.read()

        body = (
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f'Content-Type: application/octet-stream\r\n\r\n'
        ).encode('utf-8') + file_bytes + f'\r\n--{boundary}--\r\n'.encode('utf-8')

        headers = {
            'x-apikey': api_key,
            'Accept': 'application/json',
            'Content-Type': f'multipart/form-data; boundary={boundary}',
            'User-Agent': 'TrustCheck-PhishingScanner/2.0',
        }
        req = urllib.request.Request(
            'https://www.virustotal.com/api/v3/files',
            data=body,
            headers=headers,
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            post_json = json.loads(resp.read().decode('utf-8'))
            analysis_id = post_json.get('data', {}).get('id', '')

        # Cho 5 giay de VT khoi tao ket qua phan tich ban dau
        if analysis_id:
            time.sleep(5)
            ana_req = urllib.request.Request(
                f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                headers={'x-apikey': api_key, 'Accept': 'application/json'},
                method='GET',
            )
            with urllib.request.urlopen(ana_req, timeout=10) as ana_resp:
                ana_json = json.loads(ana_resp.read().decode('utf-8'))
                stats = ana_json.get('data', {}).get('attributes', {}).get('stats', {})
                return {
                    'scan_engine': 'VirusTotal API v3 (Direct File Upload)',
                    'api_key_used': key_label,
                    'status': 'UPLOADED_AND_SCANNED',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'permalink': f'https://www.virustotal.com/gui/file/{sha256_hash}',
                }
    except urllib.error.HTTPError as e:
        if e.code in (429, 401, 403):
            return {'quota_exceeded': True}
        return {
            'scan_engine': 'VirusTotal API v3',
            'api_key_used': key_label,
            'status': f'UPLOAD_HTTP_ERROR_{e.code}',
            'malicious': 0,
            'suspicious': 0,
        }
    except Exception as e:
        return {
            'scan_engine': 'VirusTotal API v3',
            'api_key_used': key_label,
            'status': 'UPLOAD_ERROR',
            'error': str(e)[:100],
            'malicious': 0,
            'suspicious': 0,
        }


def query_malwarebazaar_fallback(sha256_hash):
    """API Du phong thu cap: Tra cuu SHA-256 tren MalwareBazaar (Abuse.ch)."""
    try:
        post_data = urllib.parse.urlencode({
            'query': 'get_info',
            'hash': sha256_hash,
        }).encode('utf-8')
        req = urllib.request.Request(
            'https://mb-api.abuse.ch/api/v1/',
            data=post_data,
            headers={'User-Agent': 'TrustCheck-PhishingScanner/2.0'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('query_status') == 'ok':
                sample_info = (data.get('data') or [{}])[0]
                return {
                    'scan_engine': 'Backup API (Abuse.ch MalwareBazaar)',
                    'status': 'MALWARE_FOUND',
                    'malicious': 15,  # Xac nhan ma doc tren MalwareBazaar
                    'suspicious': 2,
                    'signature': sample_info.get('signature'),
                    'file_type': sample_info.get('file_type'),
                    'tags': sample_info.get('tags', []),
                }
            return {
                'scan_engine': 'Backup API (MalwareBazaar + Static YARA)',
                'status': 'HASH_UNKNOWN_ON_FALLBACK',
                'malicious': 0,
                'suspicious': 0,
            }
    except Exception as e:
        return {
            'scan_engine': 'Local Static + YARA Engine Fallback',
            'status': 'EXTERNAL_APIS_UNAVAILABLE',
            'malicious': 0,
            'suspicious': 0,
            'fallback_error': str(e)[:100],
        }


def analyze_file(local_path, filename):
    """Tinh SHA-256, quet VirusTotal API (kem API du phong) va Phan tich tinh (Static/YARA)."""
    file_size = os.path.getsize(local_path)
    _, ext = os.path.splitext(filename.lower())

    sha256_hasher = hashlib.sha256()
    md5_hasher = hashlib.md5()
    byte_counts = [0] * 256
    matched_signatures = []
    suspicious_flags = []

    with open(local_path, 'rb') as f:
        header_bytes = f.read(8)
        f.seek(0)
        content_sample = b''

        while chunk := f.read(65536):
            sha256_hasher.update(chunk)
            md5_hasher.update(chunk)
            for b in chunk:
                byte_counts[b] += 1
            if len(content_sample) < 1048576:
                content_sample += chunk

    sha256_hex = sha256_hasher.hexdigest()
    md5_hex = md5_hasher.hexdigest()

    # 1. Goi VirusTotal API v3 (kem Failover sang Backup Keys & MalwareBazaar)
    vt_report = query_virustotal_file(sha256_hex, local_path, filename, file_size)
    if vt_report.get('malicious', 0) > 0:
        suspicious_flags.append(
            f"VirusTotal/API phat hien {vt_report.get('malicious')} engines bao ma doc!"
        )

    # 2. Kiem tra Double Extension & Duoi file rui ro cao
    parts = filename.lower().split('.')
    if len(parts) >= 3 and f'.{parts[-1]}' in HIGH_RISK_EXTENSIONS:
        suspicious_flags.append(f'Phat hien Double Extension gia mao ({filename})')

    if ext in HIGH_RISK_EXTENSIONS:
        suspicious_flags.append(f'Duoi file thuc thi rui ro cao ({ext})')

    # 3. Phan tich Magic Bytes
    detected_magic = detect_magic_type(header_bytes)
    if detected_magic == 'Windows_PE_Executable' and ext not in {'.exe', '.dll', '.scr', '.msi'}:
        suspicious_flags.append(
            f'Gia mao dinh dang: File mang duoi {ext} nhung chua ma thuc thi Windows (MZ Header)!'
        )
    elif detected_magic == 'ELF_Linux_Executable' and ext not in {'.bin', '.elf'}:
        suspicious_flags.append(
            'Gia mao dinh dang: File chua ma thuc thi Linux (ELF Header)!'
        )

    # 4. Quet mau chu ky YARA-style tinh
    lower_sample = content_sample.lower()
    for rule_name, pattern in STATIC_YARA_SIGNATURES.items():
        if pattern in lower_sample:
            matched_signatures.append(rule_name)

    if matched_signatures:
        suspicious_flags.append(
            f"Phat hien {len(matched_signatures)} mau chu ky YARA dang ngo: {', '.join(matched_signatures)}"
        )

    # 5. Tinh Shannon Entropy
    entropy = calculate_entropy(byte_counts, file_size)
    if entropy > 7.5 and ext in HIGH_RISK_EXTENSIONS:
        suspicious_flags.append(
            f'Entropy rat cao ({entropy:.2f}/8.0) - Dau hieu file thuc thi bi nen/ma hoa (Packed)'
        )

    # 6. Quet ClamAV (neu co)
    clamav_status = run_clamav_if_available(local_path)
    if clamav_status.get('infected'):
        suspicious_flags.append(
            f"ClamAV phat hien ma doc: {clamav_status.get('signature')}"
        )

    return {
        'filename': filename,
        'file_size_bytes': file_size,
        'detected_format': detected_magic,
        'sha256': sha256_hex,
        'md5': md5_hex,
        'virustotal_report': vt_report,
        'shannon_entropy': round(entropy, 3),
        'matched_yara_rules': matched_signatures,
        'clamav_scan': clamav_status.get('status'),
        'suspicious_flags': suspicious_flags,
    }


def detect_magic_type(header):
    if header.startswith(b'MZ'):
        return 'Windows_PE_Executable'
    if header.startswith(b'\x7fELF'):
        return 'ELF_Linux_Executable'
    if header.startswith(b'%PDF'):
        return 'PDF_Document'
    if header.startswith(b'PK\x03\x04'):
        return 'ZIP_or_Office_OpenXML'
    if header.startswith(b'\xd0\xcf\x11\xe0'):
        return 'OLE2_Legacy_Office_Document'
    if header.startswith(b'\x89PNG'):
        return 'PNG_Image'
    if header.startswith(b'\xff\xd8\xff'):
        return 'JPEG_Image'
    return 'Text_or_Generic_Binary'


def calculate_entropy(byte_counts, total_size):
    if total_size == 0:
        return 0.0
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / total_size
            entropy -= p * math.log2(p)
    return entropy


def run_clamav_if_available(local_path):
    try:
        res = subprocess.run(
            ['clamscan', '--no-summary', local_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=90,
        )
        if res.returncode == 1:
            return {
                'status': 'INFECTED',
                'infected': True,
                'signature': res.stdout.strip(),
            }
        return {'status': 'CLEAN', 'infected': False}
    except FileNotFoundError:
        return {'status': 'SKIPPED (VirusTotal + YARA Engine Active)', 'infected': False}
    except Exception as e:
        return {'status': f'ERROR ({str(e)[:50]})', 'infected': False}


def calculate_file_trust_score(details):
    """Scoring Engine cho File: Tong hop ket qua VirusTotal API va Static Analysis (0 - 100)."""
    score = 100
    vt = details.get('virustotal_report', {})
    malicious = vt.get('malicious', 0)
    suspicious = vt.get('suspicious', 0)
    flags = details.get('suspicious_flags', [])
    yara_matches = details.get('matched_yara_rules', [])

    if details.get('clamav_scan') == 'INFECTED' or malicious >= 5:
        return 0, 'DANGEROUS (MALWARE DETECTED)'

    if malicious >= 2:
        score -= 70
    elif malicious == 1:
        score -= 40

    if suspicious > 0:
        score -= min(suspicious * 15, 30)

    if flags:
        score -= min(len(flags) * 25, 75)

    if yara_matches:
        score -= min(len(yara_matches) * 20, 50)

    score = max(0, min(100, score))

    if score >= 80:
        risk_level = 'SAFE (FILE AN TOAN)'
    elif score >= 50:
        risk_level = 'SUSPICIOUS (CANH BAO)'
    else:
        risk_level = 'DANGEROUS (MA DOC NGUY HIEM)'

    return score, risk_level