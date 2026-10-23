import base64
import hashlib
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import boto3

dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')

JOBS_TABLE = os.environ.get('JOBS_TABLE', 'PhishingScanJobs')
CACHE_TABLE = os.environ.get('CACHE_TABLE', 'PhishingScanCache')
REPORTS_BUCKET = os.environ.get('REPORTS_BUCKET', '')

# Cau hinh VirusTotal API Key chinh va danh sach API Key du phong (cach nhau boi dau phay)
VT_API_KEY = os.environ.get('VT_API_KEY', '')
VT_BACKUP_API_KEYS = os.environ.get('VT_BACKUP_API_KEYS', '')

jobs_tbl = dynamodb.Table(JOBS_TABLE)
cache_tbl = dynamodb.Table(CACHE_TABLE)

SUSPICIOUS_URL_KEYWORDS = [
    'login', 'verify', 'update', 'security', 'account', 'banking',
    'paypal', 'appleid', 'microsoft', 'support', 'confirm', 'wallet',
    'unlock', 'signin', 'auth', 'credential', 'recover',
]

SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.club', '.online', '.site', '.tk', '.ml',
    '.ga', '.cf', '.gq', '.work', '.click', '.link', '.buzz',
]

EMAIL_URGENT_PATTERNS = [
    'urgent', 'immediate action', 'account suspended', 'verify your account',
    'within 24 hours', 'unauthorized login', 'security alert',
    'confirm your identity', 'password expired', 'click the link below',
    'khan cap', 'khoa tai khoan', 'xac minh ngay', 'cap nhat thong tin',
]


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
    AWS Lambda Handler cho FastDetectWorker (Xu ly Link va Email tu phishing-fast-queue).
    Su dung VirusTotal API v3 ket hop xoay vong API Key du phong va Heuristic.
    """
    for record in event.get('Records', []):
        job_id = None
        try:
            body = json.loads(record.get('body', '{}'))
            job_id = body.get('job_id')
            input_type = body.get('type', 'link')
            payload = body.get('payload', '')
            target_hash = body.get('target_hash')

            if not job_id:
                continue

            # 1. Cap nhat trang thai PROCESSING
            jobs_tbl.update_item(
                Key={'job_id': job_id},
                UpdateExpression='SET #s = :s',
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={':s': 'PROCESSING'},
            )

            # 2. Phan tich theo loai input (Link hoac Email) voi VirusTotal API
            if input_type == 'link':
                analysis_details = analyze_link(payload)
            elif input_type == 'email':
                analysis_details = analyze_email(payload)
            else:
                analysis_details = {'error': f'Unsupported input type: {input_type}'}

            # 3. Tinh Trust Score (0 - 100) dua tren ket qua VirusTotal + Heuristic
            trust_score, risk_level = calculate_trust_score(
                input_type, analysis_details
            )

            scanned_at = int(time.time())
            final_result = {
                'trust_score': trust_score,
                'risk_level': risk_level,
                'details': analysis_details,
                'scanned_at': scanned_at,
            }

            # 4. Luu ket qua COMPLETED vao DynamoDB (PhishingScanJobs)
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

            # 5. Luu Cache ket qua trong 24h (PhishingScanCache)
            if not target_hash and payload:
                target_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()

            if target_hash:
                cache_tbl.put_item(
                    Item={
                        'target_hash': target_hash,
                        'job_id': job_id,
                        'result': final_result,
                        'expires_at': scanned_at + 86400,
                    }
                )

            # 6. Luu log JSON len S3 (neu co cau hinh REPORTS_BUCKET)
            if REPORTS_BUCKET:
                try:
                    s3.put_object(
                        Bucket=REPORTS_BUCKET,
                        Key=f'logs/{job_id}.json',
                        Body=json.dumps(final_result, indent=2),
                        ContentType='application/json',
                    )
                except Exception as s3_err:
                    print(f'Canh bao luu log S3 cho job {job_id}: {str(s3_err)}')

        except Exception as e:
            print(f"Loi xu ly job {record.get('messageId')}: {str(e)}")
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

    return {'statusCode': 200}


def query_virustotal_url(target_url):
    """
    Kiem tra URL tren VirusTotal API v3 voi co che xoay vong API Key du phong.
    Neu tat ca key VT het quota hoac khong co key, tu dong chuyen sang API du phong URLhaus.
    """
    api_keys = get_vt_api_keys()
    # VirusTotal v3 yeu cau URL ID la chuoi base64 urlsafe khong co dau '='
    url_id = base64.urlsafe_b64encode(target_url.encode('utf-8')).decode('utf-8').strip('=')
    quota_errors = []

    for idx, api_key in enumerate(api_keys):
        key_label = 'PRIMARY_KEY' if idx == 0 else f'BACKUP_KEY_{idx}'
        headers = {
            'x-apikey': api_key,
            'Accept': 'application/json',
            'User-Agent': 'TrustCheck-PhishingScanner/2.0',
        }

        try:
            # Buoc 1: Tra cuu bao cao URL co san tren VirusTotal
            req = urllib.request.Request(
                f'https://www.virustotal.com/api/v3/urls/{url_id}',
                headers=headers,
                method='GET',
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                attrs = data.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                return {
                    'scan_engine': 'VirusTotal API v3',
                    'api_key_used': key_label,
                    'status': 'FOUND',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'reputation': attrs.get('reputation', 0),
                    'categories': attrs.get('categories', {}),
                    'permalink': f'https://www.virustotal.com/gui/url/{url_id}',
                }

        except urllib.error.HTTPError as http_err:
            # Neu URL chua tung duoc quet tren VT (404), gui yeu cau POST de quet moi
            if http_err.code == 404:
                try:
                    post_data = urllib.parse.urlencode({'url': target_url}).encode('utf-8')
                    post_headers = headers.copy()
                    post_headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    post_req = urllib.request.Request(
                        'https://www.virustotal.com/api/v3/urls',
                        data=post_data,
                        headers=post_headers,
                        method='POST',
                    )
                    with urllib.request.urlopen(post_req, timeout=8) as post_resp:
                        post_json = json.loads(post_resp.read().decode('utf-8'))
                        analysis_id = post_json.get('data', {}).get('id', '')

                    # Cho ngan va lay ket qua phan tich
                    if analysis_id:
                        time.sleep(2)
                        ana_req = urllib.request.Request(
                            f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                            headers=headers,
                            method='GET',
                        )
                        with urllib.request.urlopen(ana_req, timeout=8) as ana_resp:
                            ana_json = json.loads(ana_resp.read().decode('utf-8'))
                            stats = ana_json.get('data', {}).get('attributes', {}).get('stats', {})
                            return {
                                'scan_engine': 'VirusTotal API v3 (Live Scan)',
                                'api_key_used': key_label,
                                'status': 'SUBMITTED_AND_SCANNED',
                                'malicious': stats.get('malicious', 0),
                                'suspicious': stats.get('suspicious', 0),
                                'harmless': stats.get('harmless', 0),
                                'undetected': stats.get('undetected', 0),
                                'permalink': f'https://www.virustotal.com/gui/url/{url_id}',
                            }
                except urllib.error.HTTPError as sub_err:
                    if sub_err.code in (429, 401, 403):
                        quota_errors.append(f'{key_label}: HTTP {sub_err.code}')
                        continue
                except Exception as sub_ex:
                    return {
                        'scan_engine': 'VirusTotal API v3',
                        'api_key_used': key_label,
                        'status': 'SUBMIT_ERROR',
                        'error': str(sub_ex)[:100],
                    }

            # Neu het Quota (429) hoac Key loi (401/403) -> Chuyen sang Key du phong tiep theo
            elif http_err.code in (429, 401, 403):
                quota_errors.append(f'{key_label}: HTTP {http_err.code} (Quota Exceeded/Auth Error)')
                print(f'Canh bao: {key_label} gap loi {http_err.code}, dang chuyen sang API du phong...')
                continue
            else:
                quota_errors.append(f'{key_label}: HTTP {http_err.code}')
                continue

        except Exception as err:
            quota_errors.append(f'{key_label}: {str(err)[:80]}')
            continue

    # LOP DU PHONG THU CAP: Goi API URLhaus (Abuse.ch) khi VirusTotal het quota hoac chua cau hinh Key
    fallback_res = query_urlhaus_fallback(target_url)
    fallback_res['vt_failover_notes'] = quota_errors or ['No VT_API_KEY configured']
    return fallback_res


def query_urlhaus_fallback(target_url):
    """API Du phong thu cap: Kiem tra URL tren co so du lieu ma doc URLhaus (Abuse.ch)."""
    try:
        post_data = urllib.parse.urlencode({'url': target_url}).encode('utf-8')
        req = urllib.request.Request(
            'https://urlhaus-api.abuse.ch/v1/url/',
            data=post_data,
            headers={'User-Agent': 'TrustCheck-PhishingScanner/2.0'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            query_status = data.get('query_status')
            if query_status == 'ok':
                return {
                    'scan_engine': 'Backup API (Abuse.ch URLhaus)',
                    'status': 'MALICIOUS_FOUND',
                    'malicious': 10,  # Quy doi tuong duong muc nguy hiem cao
                    'suspicious': 2,
                    'url_status': data.get('url_status'),
                    'threat': data.get('threat'),
                    'tags': data.get('tags', []),
                }
            return {
                'scan_engine': 'Backup API (Abuse.ch URLhaus + Heuristic)',
                'status': 'CLEAN_ON_FALLBACK',
                'malicious': 0,
                'suspicious': 0,
            }
    except Exception as e:
        return {
            'scan_engine': 'Local Heuristic Fallback Only',
            'status': 'EXTERNAL_APIS_UNAVAILABLE',
            'malicious': 0,
            'suspicious': 0,
            'fallback_error': str(e)[:100],
        }


def analyze_link(raw_url):
    """Phan tich URL ket hop VirusTotal API v3 (co Failover) va kiem tra Heuristic."""
    url = raw_url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urllib.parse.urlparse(url)
    domain = parsed.hostname or ''
    scheme = parsed.scheme.lower()

    # 1. Goi VirusTotal API (kem co che tu dong chuyen sang API du phong neu het quota)
    vt_report = query_virustotal_url(url)

    details = {
        'input_url': raw_url,
        'domain': domain,
        'uses_https': scheme == 'https',
        'virustotal_report': vt_report,
        'is_ip_address': False,
        'suspicious_tld': False,
        'suspicious_keywords': [],
        'ssl_valid': False,
        'risk_penalties': [],
    }

    if vt_report.get('malicious', 0) > 0:
        details['risk_penalties'].append(
            f"VirusTotal/API phat hien {vt_report.get('malicious')} canh bao doc hai"
        )

    # 2. Kiem tra bo sung Heuristic (IP, TLD, Keywords, SSL)
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        details['is_ip_address'] = True
        details['risk_penalties'].append('URL su dung truc tiep dia chi IP')

    lower_domain = domain.lower()
    for tld in SUSPICIOUS_TLDS:
        if lower_domain.endswith(tld):
            details['suspicious_tld'] = True
            details['risk_penalties'].append(f'Ten mien su dung TLD rui ro cao ({tld})')
            break

    lower_url = url.lower()
    for kw in SUSPICIOUS_URL_KEYWORDS:
        if kw in lower_url:
            details['suspicious_keywords'].append(kw)

    if scheme == 'https' and domain:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    if ssock.getpeercert():
                        details['ssl_valid'] = True
        except Exception as ssl_err:
            details['ssl_error'] = str(ssl_err)[:80]

    return details


def analyze_email(content):
    """
    Phan tich Email: Boc tach URL de quet bang VirusTotal API + Kiem tra SPF/DKIM/DMARC & NLP.
    """
    lower_content = content.lower()
    extracted_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)

    # Quet toi da 3 URL dau tien trong email qua VirusTotal API de tiet kiem quota va thoi gian
    url_vt_scans = []
    max_malicious_in_links = 0
    max_suspicious_in_links = 0

    for u in extracted_urls[:3]:
        clean_u = u if u.startswith(('http://', 'https://')) else 'http://' + u
        vt_res = query_virustotal_url(clean_u)
        max_malicious_in_links = max(max_malicious_in_links, vt_res.get('malicious', 0))
        max_suspicious_in_links = max(max_suspicious_in_links, vt_res.get('suspicious', 0))
        url_vt_scans.append({
            'url': clean_u,
            'vt_result': vt_res,
        })

    spf_fail = 'spf=fail' in lower_content or 'spf=softfail' in lower_content
    dkim_fail = 'dkim=fail' in lower_content
    dmarc_fail = 'dmarc=fail' in lower_content

    matched_phrases = [p for p in EMAIL_URGENT_PATTERNS if p in lower_content]
    asks_sensitive_info = any(
        w in lower_content
        for w in ['password', 'mat khau', 'otp', 'pin', 'credit card', 'cvv', 'so the']
    )

    return {
        'email_length_chars': len(content),
        'extracted_urls_count': len(extracted_urls),
        'extracted_urls': extracted_urls[:5],
        'virustotal_link_scans': url_vt_scans,
        'max_malicious_detections': max_malicious_in_links,
        'max_suspicious_detections': max_suspicious_in_links,
        'spf_fail_detected': spf_fail,
        'dkim_fail_detected': dkim_fail,
        'dmarc_fail_detected': dmarc_fail,
        'urgent_phrases_found': matched_phrases,
        'asks_sensitive_credentials': asks_sensitive_info,
    }


def calculate_trust_score(input_type, details):
    """Scoring Engine: Ket hop ket qua quet tu VirusTotal API va Heuristic (0 - 100)."""
    score = 100

    if input_type == 'link':
        vt = details.get('virustotal_report', {})
        malicious = vt.get('malicious', 0)
        suspicious = vt.get('suspicious', 0)

        # Trong so chinh tu VirusTotal API
        if malicious >= 5:
            score -= 85
        elif malicious >= 2:
            score -= 60
        elif malicious == 1:
            score -= 35

        if suspicious > 0:
            score -= min(suspicious * 15, 30)

        # Trong so bo tro tu Heuristic
        if not details.get('uses_https', False):
            score -= 10
        if details.get('is_ip_address', False):
            score -= 25
        if details.get('suspicious_tld', False):
            score -= 15
        kw_count = len(details.get('suspicious_keywords', []))
        score -= min(kw_count * 10, 30)

    elif input_type == 'email':
        malicious_links = details.get('max_malicious_detections', 0)
        suspicious_links = details.get('max_suspicious_detections', 0)

        # Neu link trong email bi VirusTotal gan co doc hai -> Tru diem nang
        if malicious_links >= 3:
            score -= 75
        elif malicious_links >= 1:
            score -= 45

        if suspicious_links > 0:
            score -= min(suspicious_links * 15, 25)

        if details.get('spf_fail_detected') or details.get('dkim_fail_detected'):
            score -= 25
        if details.get('dmarc_fail_detected'):
            score -= 15

        urgent_count = len(details.get('urgent_phrases_found', []))
        score -= min(urgent_count * 15, 40)

        if details.get('asks_sensitive_credentials'):
            score -= 25

    score = max(0, min(100, score))

    if score >= 80:
        risk_level = 'SAFE'
    elif score >= 50:
        risk_level = 'SUSPICIOUS'
    else:
        risk_level = 'DANGEROUS'

    return score, risk_level