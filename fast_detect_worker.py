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

jobs_tbl = dynamodb.Table(JOBS_TABLE)
cache_tbl = dynamodb.Table(CACHE_TABLE)

# Danh sach tu khoa gia mao pho bien trong URL va Email
SUSPICIOUS_URL_KEYWORDS = [
    'login',
    'verify',
    'update',
    'security',
    'account',
    'banking',
    'paypal',
    'appleid',
    'microsoft',
    'support',
    'confirm',
    'wallet',
    'unlock',
    'signin',
    'auth',
    'credential',
    'recover',
]

SUSPICIOUS_TLDS = [
    '.xyz',
    '.top',
    '.club',
    '.online',
    '.site',
    '.tk',
    '.ml',
    '.ga',
    '.cf',
    '.gq',
    '.work',
    '.click',
    '.link',
    '.buzz',
]

EMAIL_URGENT_PATTERNS = [
    'urgent',
    'immediate action',
    'account suspended',
    'verify your account',
    'within 24 hours',
    'unauthorized login',
    'security alert',
    'confirm your identity',
    'password expired',
    'click the link below',
    'khan cap',
    'khoa tai khoan',
    'xac minh ngay',
    'cap nhat thong tin',
]


def lambda_handler(event, context):
  """ AWS Lambda Handler cho FastDetectWorker (Xu ly Link va Email tu SQS).

  Luon dam bao cap nhat trang thai COMPLETED vao DynamoDB de Frontend khong bi
  treo o trang thai PENDING/PROCESSING.
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

      # 2. Phan tich chi tiet theo loai input (Link hoac Email)
      if input_type == 'link':
        analysis_details = analyze_link(payload)
      elif input_type == 'email':
        analysis_details = analyze_email(payload)
      else:
        analysis_details = {'error': f'Unsupported input type: {input_type}'}

      # 3. Scoring Engine: Tong hop trong so -> Tinh Trust Score (0 - 100)
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


def analyze_link(raw_url):
  """Phan tich URL: Kiem tra cau truc Domain, SSL/TLS, Redirect Chain va Tu khoa gia mao."""
  url = raw_url.strip()
  if not url.startswith(('http://', 'https://')):
    url = 'http://' + url

  parsed = urllib.parse.urlparse(url)
  domain = parsed.hostname or ''
  scheme = parsed.scheme.lower()

  details = {
      'input_url': raw_url,
      'domain': domain,
      'uses_https': scheme == 'https',
      'is_ip_address': False,
      'suspicious_tld': False,
      'suspicious_keywords': [],
      'redirect_chain': [],
      'redirection_count': 0,
      'ssl_valid': False,
      'risk_penalties': [],
  }

  # 1. Kiem tra xem domain co phai dia chi IP truc tiep khong
  if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
    details['is_ip_address'] = True
    details['risk_penalties'].append('URL su dung truc tiep dia chi IP (-35)')

  # 2. Kiem tra TLD rui ro cao
  lower_domain = domain.lower()
  for tld in SUSPICIOUS_TLDS:
    if lower_domain.endswith(tld):
      details['suspicious_tld'] = True
      details['risk_penalties'].append(
          f'Ten mien su dung duoi TLD rui ro cao ({tld}) (-20)'
      )
      break

  # 3. Kiem tra tu khoa nhay cam trong URL va so luong dau gach ngang (-)
  lower_url = url.lower()
  for kw in SUSPICIOUS_URL_KEYWORDS:
    if kw in lower_url:
      details['suspicious_keywords'].append(kw)

  if lower_domain.count('-') >= 2:
    details['risk_penalties'].append(
        f"Ten mien chua nhieu dau gach ngang ({lower_domain.count('-')}) (-15)"
    )

  # 4. Kiem tra chung chi SSL (neu dung HTTPS)
  if scheme == 'https' and domain:
    try:
      ctx = ssl.create_default_context()
      with socket.create_connection((domain, 443), timeout=4) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
          cert = ssock.getpeercert()
          if cert:
            details['ssl_valid'] = True
    except Exception as ssl_err:
      details['ssl_error'] = str(ssl_err)[:100]

  # 5. Kiem tra Redirect Chain va HTTP status
  try:
    req = urllib.request.Request(
        url,
        headers={
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishingScanner/1.0'
            )
        },
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
      final_url = resp.geturl()
      details['final_url'] = final_url
      details['http_status'] = resp.getcode()
      if final_url.rstrip('/') != url.rstrip('/'):
        details['redirection_count'] = 1
        details['redirect_chain'] = [url, final_url]
  except urllib.error.HTTPError as http_err:
    details['http_status'] = http_err.code
    details['fetch_note'] = f'HTTP {http_err.code}'
  except Exception as err:
    details['fetch_error'] = str(err)[:120]

  return details


def analyze_email(content):
  """Phan tich Email: Kiem tra Header SPF/DKIM/DMARC, boc tach URL va phan tich NLP Heuristic."""
  lower_content = content.lower()

  # 1. Boc tach tat ca URL co trong noi dung email
  extracted_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)

  # 2. Kiem tra dau hieu Header SPF / DKIM / DMARC
  spf_fail = 'spf=fail' in lower_content or 'spf=softfail' in lower_content
  dkim_fail = 'dkim=fail' in lower_content
  dmarc_fail = 'dmarc=fail' in lower_content

  # 3. Phan tich NLP Heuristic phat hien ngon ngu du do / khan cap
  matched_phrases = []
  for phrase in EMAIL_URGENT_PATTERNS:
    if phrase in lower_content:
      matched_phrases.append(phrase)

  # 4. Kiem tra yeu cau cung cap thong tin nhay cam
  asks_sensitive_info = any(
      w in lower_content
      for w in [
          'password',
          'mat khau',
          'otp',
          'pin',
          'credit card',
          'cvv',
          'so the',
      ]
  )

  return {
      'email_length_chars': len(content),
      'extracted_urls_count': len(extracted_urls),
      'extracted_urls': extracted_urls[:5],
      'spf_fail_detected': spf_fail,
      'dkim_fail_detected': dkim_fail,
      'dmarc_fail_detected': dmarc_fail,
      'urgent_phrases_found': matched_phrases,
      'asks_sensitive_credentials': asks_sensitive_info,
  }


def calculate_trust_score(input_type, details):
  """Scoring Engine: Tinh diem tin cay tu 0 (Nguy hiem nhat) den 100 (An toan nhat)."""
  score = 100

  if input_type == 'link':
    if not details.get('uses_https', False):
      score -= 15
    if details.get('is_ip_address', False):
      score -= 35
    if details.get('suspicious_tld', False):
      score -= 20

    kw_count = len(details.get('suspicious_keywords', []))
    score -= min(kw_count * 20, 60)

    domain = details.get('domain', '')
    if domain.count('-') >= 2:
      score -= 15

    if details.get('redirection_count', 0) > 0:
      score -= 15

    if 'fetch_error' in details:
      score -= 15

  elif input_type == 'email':
    if details.get('spf_fail_detected') or details.get('dkim_fail_detected'):
      score -= 30
    if details.get('dmarc_fail_detected'):
      score -= 20

    urgent_count = len(details.get('urgent_phrases_found', []))
    score -= min(urgent_count * 20, 50)

    if details.get('asks_sensitive_credentials'):
      score -= 25

    if details.get('extracted_urls_count', 0) > 0:
      score -= 10

  score = max(0, min(100, score))

  if score >= 80:
    risk_level = 'SAFE'
  elif score >= 50:
    risk_level = 'SUSPICIOUS'
  else:
    risk_level = 'DANGEROUS'

  return score, risk_level