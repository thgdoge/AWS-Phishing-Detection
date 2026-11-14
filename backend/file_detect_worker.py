import os
import tempfile
import time

from common.net import Deadline
from common.pipeline import Outcome, process_event
from common.scoring import build_result, compute_score
from detectors.file import analyze_file

MAX_FILE_BYTES = int(os.environ.get('MAX_FILE_BYTES', str(32 * 1024 * 1024)))
S3_WAIT_SECONDS = float(os.environ.get('S3_WAIT_SECONDS', '30'))


def wait_for_object(s3, bucket, key, deadline: Deadline):
    waited = 0.0
    while True:
        try:
            return s3.head_object(Bucket=bucket, Key=key)['ContentLength']
        except Exception as exc:  # noqa: BLE001 - botocore ClientError 404 khi chưa có
            code = getattr(exc, 'response', {}).get('Error', {}).get('Code', '')
            if code not in ('404', 'NoSuchKey', 'NotFound'):
                raise
        if waited >= S3_WAIT_SECONDS or deadline.remaining() < 4:
            raise FileNotFoundError('Không nhận được tệp tải lên (hết thời gian chờ)')
        time.sleep(2)
        waited += 2


def analyze(body, deadline, store):
    bucket, key, job_id = body.get('s3_bucket'), body.get('s3_key'), body.get('job_id')
    if not bucket or not key:
        raise ValueError('Thiếu thông tin S3')

    size = wait_for_object(store.s3, bucket, key, deadline)
    if size > MAX_FILE_BYTES:
        raise ValueError(f'Tệp quá lớn ({size} byte), giới hạn {MAX_FILE_BYTES} byte')

    filename = os.path.basename(key)
    local_path = os.path.join(tempfile.gettempdir(), f'{job_id}_{filename}')   # Lambda: /tmp
    try:
        store.s3.download_file(bucket, key, local_path)
        analysis = analyze_file(local_path, filename, deadline)
    finally:
        try:
            os.remove(local_path)
        except OSError:
            pass

    score = compute_score(analysis.findings, reputation_ok=analysis.reputation_ok,
                          reputation_needed=analysis.reputation_needed)
    # Cache theo SHA-256 NỘI DUNG (không phải tên file).
    return Outcome(build_result(score, analysis.details), cache_key=analysis.details['sha256'])


def lambda_handler(event, context):
    return process_event(event, context, analyze)
