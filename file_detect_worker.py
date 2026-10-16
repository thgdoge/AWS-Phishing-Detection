import hashlib
import json
import math
import os
import subprocess
import time
import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')

JOBS_TABLE = os.environ.get('JOBS_TABLE', 'PhishingScanJobs')
CACHE_TABLE = os.environ.get('CACHE_TABLE', 'PhishingScanCache')
REPORTS_BUCKET = os.environ.get('REPORTS_BUCKET', '')

jobs_tbl = dynamodb.Table(JOBS_TABLE)
cache_tbl = dynamodb.Table(CACHE_TABLE)

# Danh sach duoi file nguy co cao thuong dung phat tan ma doc
HIGH_RISK_EXTENSIONS = {
    '.exe',
    '.scr',
    '.vbs',
    '.bat',
    '.cmd',
    '.ps1',
    '.iso',
    '.lnk',
    '.hta',
    '.js',
    '.jar',
    '.msi',
    '.dll',
    '.reg',
}

# Mau chu ky YARA-style tinh (Static Signatures) phat hien script doc hai & macro
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


def lambda_handler(event, context):
  """ AWS Lambda Handler cho FileDetectWorker (Xu ly File tu phishing-file-queue).

  Bao gom co che doi file upload len S3 hoan tat (tranh loi 404 do race
  condition), tinh SHA-256, phan tich dinh dang tinh (Magic Bytes, Entropy, YARA
  patterns) va quet ClamAV (neu co).
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

      # 4. Phan tich File (SHA-256, Magic Header, YARA Signatures, Entropy, ClamAV)
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
      # Luon don dep file tam trong /tmp de khong bi day bo nho Lambda
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


def analyze_file(local_path, filename):
  """Phan tich tinh (Static Analysis) + YARA Signatures + ClamAV (neu co)."""
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
      # Giu lai 1MB dau tien de quet nhanh chu ky YARA
      if len(content_sample) < 1048576:
        content_sample += chunk

  # 1. Kiem tra Double Extension (VD: invoice.pdf.exe)
  parts = filename.lower().split('.')
  if len(parts) >= 3 and f'.{parts[-1]}' in HIGH_RISK_EXTENSIONS:
    suspicious_flags.append(f'Phat hien Double Extension gia mao ({filename})')

  # 2. Kiem tra duoi file thuc thi rui ro cao
  if ext in HIGH_RISK_EXTENSIONS:
    suspicious_flags.append(f'Duoi file thuc thi rui ro cao ({ext})')

  # 3. Phan tich Magic Bytes (Header that cua file so voi duoi file)
  detected_magic = detect_magic_type(header_bytes)
  if detected_magic == 'Windows_PE_Executable' and ext not in {
      '.exe',
      '.dll',
      '.scr',
      '.msi',
  }:
    suspicious_flags.append(
        f'Gia mao dinh dang: File mang duoi {ext} nhung chua ma thuc thi'
        ' Windows (MZ Header)!'
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
        f"Phat hien {len(matched_signatures)} mau chu ky dang ngo:"
        f" {', '.join(matched_signatures)}"
    )

  # 5. Tinh Shannon Entropy (0.0 -> 8.0) de phat hien ma doc bi nen/ma hoa (Packed Malware)
  entropy = calculate_entropy(byte_counts, file_size)
  if entropy > 7.5 and ext in HIGH_RISK_EXTENSIONS:
    suspicious_flags.append(
        f'Entropy rat cao ({entropy:.2f}/8.0) - Dau hieu file thuc thi bi'
        ' ma hoa/dong goi (Packed)'
    )

  # 6. Quet ClamAV (tu dong chay neu môi truong Lambda Container co cai clamscan)
  clamav_status = run_clamav_if_available(local_path)
  if clamav_status.get('infected'):
    suspicious_flags.append(
        f"ClamAV phat hien ma doc: {clamav_status.get('signature')}"
    )

  return {
      'filename': filename,
      'file_size_bytes': file_size,
      'detected_format': detected_magic,
      'sha256': sha256_hasher.hexdigest(),
      'md5': md5_hasher.hexdigest(),
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
  """Chay clamscan neu duoc trien khai tren Lambda Docker Image co ClamAV."""
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
    return {'status': 'SKIPPED (Static + YARA Engine Active)', 'infected': False}
  except Exception as e:
    return {'status': f'ERROR ({str(e)[:50]})', 'infected': False}


def calculate_file_trust_score(details):
  """Scoring Engine cho File: Quy doi cac dau hieu bat thuong ra Trust Score (0 - 100)."""
  score = 100
  flags = details.get('suspicious_flags', [])
  yara_matches = details.get('matched_yara_rules', [])

  if details.get('clamav_scan') == 'INFECTED':
    return 0, 'DANGEROUS (MALWARE DETECTED)'

  if flags:
    score -= min(len(flags) * 35, 85)

  if yara_matches:
    score -= min(len(yara_matches) * 25, 60)

  score = max(0, min(100, score))

  if score >= 80:
    risk_level = 'SAFE (FILE AN TOAN)'
  elif score >= 50:
    risk_level = 'SUSPICIOUS (CANH BAO)'
  else:
    risk_level = 'DANGEROUS (MA DOC NGUY HIEM)'

  return score, risk_level