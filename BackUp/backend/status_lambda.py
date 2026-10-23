import json
import os
import boto3

dynamodb = boto3.resource('dynamodb')
JOBS_TABLE = os.environ.get('JOBS_TABLE', 'PhishingScanJobs')
jobs_tbl = dynamodb.Table(JOBS_TABLE)

def lambda_handler(event, context):
    try:
        path_params = event.get('pathParameters', {}) or {}
        job_id = path_params.get('job_id')

        if not job_id:
            return response(400, {'error': 'missing job_id'})

        res = jobs_tbl.get_item(Key={'job_id': job_id})
        item = res.get('Item')

        if not item:
            return response(404, {'error': 'Job ID not found!'})

        return response(200, {
            'job_id': item.get('job_id'),
            'status': item.get('status'),
            'type': item.get('type'),
            'trust_score': item.get('trust_score'),
            'result': item.get('result')
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
        'body': json.dumps(body, default=str)
    }