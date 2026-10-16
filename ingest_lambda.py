import json
import os
import uuid
import time
import hashlib
import boto3

dynamodb = boto3.resource('dynamodb')
sqs = boto3.client('sqs')
s3 = boto3.client('s3')

JOBS_TABLE = os.environ.get('JOBS_TABLE', 'PhishingScanJobs')
CACHE_TABLE = os.environ.get('CACHE_TABLE', 'PhishingScanCache')
FAST_QUEUE_NAME = os.environ.get('FAST_QUEUE_NAME', 'phishing-fast-queue')
FILE_QUEUE_NAME = os.environ.get('FILE_QUEUE_NAME', 'phishing-file-queue')
RAW_BUCKET = os.environ.get('RAW_BUCKET', '')

jobs_tbl = dynamodb.Table(JOBS_TABLE)
cache_tbl = dynamodb.Table(CACHE_TABLE)

def lambda_handler(event, context):
    try:
        body = json.loads(event.get('body', '{}')) if isinstance(event.get('body'), str) else event.get('body', {})
        input_type = body.get('type')  # 'link', 'email', hoặc 'file'
        payload = body.get('payload', '') # url, raw text email, hoặc filename

        if not input_type or input_type not in ['link', 'email', 'file']:
            return response(400, {'error': 'invalid input'})

        now = int(time.time())
        target_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()

        # 1. Kiem tra Cache xem da quet trong 24h chua
        cache_item = cache_tbl.get_item(Key={'target_hash': target_hash}).get('Item')
        if cache_item and cache_item.get('expires_at', 0) > now:
            return response(200, {
                'job_id': cache_item.get('job_id'),
                'status': 'COMPLETED',
                'cached': True,
                'result': cache_item.get('result')
            })

        # 2. Sinh Job ID moi va ghi vao DynamoDB
        job_id = str(uuid.uuid4())
        expires_at = now + (7 * 86400) # Tu dong xoa sau 7 ngay
        jobs_tbl.put_item(Item={
            'job_id': job_id,
            'status': 'PENDING',
            'type': input_type,
            'target_hash': target_hash,
            'created_at': now,
            'expires_at': expires_at
        })

        # 3. Phan loai de day vao Queue tuong ung
        if input_type in ['link', 'email']:
            fast_queue_url = sqs.get_queue_url(QueueName=FAST_QUEUE_NAME)['QueueUrl']
            sqs.send_message(
                QueueUrl=fast_queue_url,
                MessageBody=json.dumps({
                    'job_id': job_id,
                    'type': input_type,
                    'payload': payload,
                    'target_hash': target_hash
                })
            )
            return response(200, {'job_id': job_id, 'status': 'PENDING'})

        elif input_type == 'file':
            # Tao Presigned URL de client upload file truc tiep len S3
            object_key = f"uploads/{job_id}/{payload}"
            presigned_url = s3.generate_presigned_url(
                'put_object',
                Params={'Bucket': RAW_BUCKET, 'Key': object_key},
                ExpiresIn=300 # URL co hieu luc trong 5 phut
            )
            # Day san message vao file queue de cho xu ly
            file_queue_url = sqs.get_queue_url(QueueName=FILE_QUEUE_NAME)['QueueUrl']
            sqs.send_message(
                QueueUrl=file_queue_url,
                MessageBody=json.dumps({
                    'job_id': job_id,
                    'type': 'file',
                    's3_bucket': RAW_BUCKET,
                    's3_key': object_key,
                    'target_hash': target_hash
                })
            )
            return response(200, {
                'job_id': job_id,
                'status': 'PENDING',
                'upload_url': presigned_url
            })

    except Exception as e:
        return response(500, {'error': str(e)})

def response(status_code, body):
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(body)
    }