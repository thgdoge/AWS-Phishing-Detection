import json
import os
import tempfile
import unittest
from decimal import Decimal
from unittest import mock

import fast_detect_worker
import file_detect_worker
from common import pipeline
from common.store import Store, from_dynamo, to_dynamo
from tests import helpers


def _reject_floats(obj):
    if isinstance(obj, float):
        raise TypeError('Float types are not supported. Use Decimal types instead.')
    if isinstance(obj, dict):
        [_reject_floats(v) for v in obj.values()]
    elif isinstance(obj, (list, tuple)):
        [_reject_floats(v) for v in obj]


class FakeTable:
    def __init__(self):
        self.items = {}
        self.fail_updates = False

    def get_item(self, Key):
        k = next(iter(Key.values()))
        return {'Item': self.items[k]} if k in self.items else {}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, ExpressionAttributeNames=None):
        if self.fail_updates:
            raise RuntimeError('DynamoDB down')
        _reject_floats(ExpressionAttributeValues)
        item = self.items.setdefault(next(iter(Key.values())), dict(Key))
        vals = ExpressionAttributeValues
        if ':ts' in vals:
            item.update(status=vals[':s'], trust_score=vals[':ts'], result=vals[':r'])
        else:
            item['status'] = vals[':s']

    def put_item(self, Item):
        _reject_floats(Item)
        self.items[Item['target_hash']] = Item


class FakeS3:
    def __init__(self, objects=None):
        self.objects, self.puts = objects or {}, []

    def put_object(self, **kw):
        self.puts.append(kw)

    def head_object(self, Bucket, Key):
        if Key not in self.objects:
            err = Exception('404')
            err.response = {'Error': {'Code': '404'}}
            raise err
        return {'ContentLength': len(self.objects[Key])}

    def download_file(self, Bucket, Key, path):
        with open(path, 'wb') as fh:
            fh.write(self.objects[Key])


class Ctx:
    def __init__(self, ms=50000):
        self.ms = ms

    def get_remaining_time_in_millis(self):
        return self.ms


def event(**body):
    return {'Records': [{'messageId': 'm1', 'body': json.dumps(body)}]}


def make_store(objects=None):
    return Store(jobs_tbl=FakeTable(), cache_tbl=FakeTable(), s3=FakeS3(objects), reports_bucket='reports')


class DynamoTests(unittest.TestCase):
    def test_float_conversion(self):
        data = {'entropy': 7.25, 'nested': [{'x': 0.5}], 'n': 3, 's': 'ok'}
        with self.assertRaises(TypeError):
            _reject_floats(data)            
        conv = to_dynamo(data)
        _reject_floats(conv)
        self.assertEqual(conv['entropy'], Decimal('7.25'))
        self.assertEqual(from_dynamo(conv), data)


class FastWorkerTests(unittest.TestCase):
    def run_worker(self, store, **body):
        patches = helpers.patch_link_sources()
        try:
            return pipeline.process_event(event(**body), Ctx(), fast_detect_worker.analyze, store)
        finally:
            helpers.stop(patches)

    def test_link_job_completes_and_caches(self):
        store = make_store()
        store.jobs.items['j1'] = {'job_id': 'j1', 'status': 'PENDING'}
        self.run_worker(store, job_id='j1', type='link', payload='https://www.example.org/', target_hash='h1')
        item = store.jobs.items['j1']
        self.assertEqual(item['status'], 'COMPLETED')
        self.assertEqual(item['trust_score'], 100)
        self.assertEqual(item['result']['risk_level'], 'SAFE')
        self.assertIn('h1', store.cache.items)
        self.assertEqual(store.s3.puts[0]['Key'], 'logs/j1.json')

    def test_failed_scan_is_marked_not_raised_and_not_cached(self):
        store = make_store()
        self.run_worker(store, job_id='j2', type='link', payload='javascript:alert(1)', target_hash='h2')
        item = store.jobs.items['j2']
        self.assertEqual(item['status'], 'COMPLETED')
        self.assertTrue(item['result']['risk_level'].startswith('SCAN ERROR'))
        self.assertNotIn('h2', store.cache.items)

    def test_unknown_type_is_error_result(self):
        store = make_store()
        self.run_worker(store, job_id='j3', type='sms', payload='x', target_hash='h3')
        self.assertTrue(store.jobs.items['j3']['result']['risk_level'].startswith('SCAN ERROR'))

    def test_low_confidence_results_are_not_cached(self):
        store = make_store()
        unavailable = {'source': 's', 'ok': False, 'status': 'NO_API_KEY', 'malicious': 0, 'suspicious': 0}
        patches = helpers.patch_link_sources(vt_res=unavailable, gsb_res=unavailable, uh_res=unavailable)
        try:
            pipeline.process_event(event(job_id='j4', type='link', payload='https://www.example.org/',
                                         target_hash='h4'), Ctx(), fast_detect_worker.analyze, store)
        finally:
            helpers.stop(patches)
        self.assertEqual(store.jobs.items['j4']['result']['confidence'], 'LOW')
        self.assertNotIn('h4', store.cache.items)

    def test_redelivered_completed_job_is_skipped(self):
        store = make_store()
        store.jobs.items['j5'] = {'job_id': 'j5', 'status': 'COMPLETED', 'trust_score': 42}
        with mock.patch('detectors.link.analyze_link', side_effect=AssertionError('không được chạy lại')):
            self.run_worker(store, job_id='j5', type='link', payload='https://www.example.org/', target_hash='h5')
        self.assertEqual(store.jobs.items['j5']['trust_score'], 42)

    def test_persistence_failure_propagates_so_sqs_retries(self):
        store = make_store()
        store.jobs.fail_updates = True
        with self.assertRaises(RuntimeError):
            self.run_worker(store, job_id='j6', type='link', payload='https://www.example.org/', target_hash='h6')

    def test_malformed_message_is_skipped(self):
        store = make_store()
        out = pipeline.process_event({'Records': [{'messageId': 'x', 'body': 'not json'},
                                                  {'messageId': 'y', 'body': '{}'}]},
                                     Ctx(), fast_detect_worker.analyze, store)
        self.assertEqual(out['statusCode'], 200)

    def test_email_job_end_to_end(self):
        store = make_store()
        raw = ('From: "PayPal" <x@paypa1-secure.top>\nSubject: Urgent\nAuthentication-Results: m; spf=fail\n'
               'Content-Type: text/plain\n\nVerify your account at http://paypa1-secure.top/login immediately.')
        self.run_worker(store, job_id='j7', type='email', payload=raw, target_hash='h7')
        result = store.jobs.items['j7']['result']
        self.assertEqual(result['risk_level'], 'DANGEROUS')
        self.assertTrue(result['reasons'])


class FileWorkerTests(unittest.TestCase):
    def run_file(self, store, key, **kw):
        with mock.patch('detectors.file.vt_lookup_file', return_value=helpers.vt()), \
                mock.patch('detectors.file.malwarebazaar_check', return_value=helpers.OK_CLEAN), \
                mock.patch('detectors.file.run_clamav', return_value={'status': 'CLEAN', 'infected': False}):
            pipeline.process_event(event(job_id='f1', s3_bucket='raw', s3_key=key, target_hash='fh'),
                                   Ctx(), file_detect_worker.analyze, store)

    def test_file_job_saves_float_details_and_caches_by_content_hash(self):
        store = make_store({'uploads/f1/invoice.pdf': b'MZ' + b'\x90' * 500})
        self.run_file(store, 'uploads/f1/invoice.pdf')
        item = store.jobs.items['f1']
        self.assertEqual(item['status'], 'COMPLETED')
        self.assertIsInstance(item['result']['details']['shannon_entropy'], Decimal)
        self.assertIn('EXEC_DISGUISED', [s['code'] for s in item['result']['signals']])
        sha = from_dynamo(item['result'])['details']['sha256']
        self.assertIn(sha, store.cache.items)
        self.assertNotIn('fh', store.cache.items)
        self.assertEqual([f for f in os.listdir(tempfile.gettempdir()) if f.startswith('f1_')], [])

    def test_missing_upload_becomes_scan_error(self):
        store = make_store({})
        with mock.patch.object(file_detect_worker, 'S3_WAIT_SECONDS', 0):
            self.run_file(store, 'uploads/f1/never.pdf')
        self.assertTrue(store.jobs.items['f1']['result']['risk_level'].startswith('SCAN ERROR'))

    def test_oversized_file_rejected(self):
        store = make_store({'uploads/f1/big.bin': b'x' * 100})
        with mock.patch.object(file_detect_worker, 'MAX_FILE_BYTES', 10):
            self.run_file(store, 'uploads/f1/big.bin')
        self.assertTrue(store.jobs.items['f1']['result']['risk_level'].startswith('SCAN ERROR'))


if __name__ == '__main__':
    unittest.main()
