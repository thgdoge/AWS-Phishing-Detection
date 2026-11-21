import io
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

from common import api_keys, reputation


class FakeSSM:
    

    def __init__(self, params=None, error_code=None):
        self.params, self.error_code, self.calls = params or {}, error_code, []

    def get_parameter(self, Name, WithDecryption):
        self.calls.append((Name, WithDecryption))
        if self.error_code:
            err = Exception('boom')
            err.response = {'Error': {'Code': self.error_code}}
            raise err
        if Name not in self.params:
            err = Exception('nf')
            err.response = {'Error': {'Code': 'ParameterNotFound'}}
            raise err
        return {'Parameter': {'Name': Name, 'Value': self.params[Name]}}


class ApiKeyTests(unittest.TestCase):
    def setUp(self):
        api_keys._CACHE.clear()
        self.env = mock.patch.dict(os.environ, {}, clear=False)
        self.env.start()
        for k in ('VT_API_KEY', 'VT_BACKUP_API_KEYS', 'GSB_API_KEY', 'ABUSECH_AUTH_KEY', 'SSM_PREFIX'):
            os.environ.pop(k, None)

    def tearDown(self):
        self.env.stop()
        api_keys._client = None
        api_keys._CACHE.clear()

    def use(self, fake):
        api_keys._client = fake
        return fake

    def test_env_var_wins_and_ssm_not_called(self):
        fake = self.use(FakeSSM({'/phishing/VT_API_KEY': 'from-ssm'}))
        os.environ.update({'VT_API_KEY': 'from-env', 'SSM_PREFIX': '/phishing'})
        self.assertEqual(api_keys.get_api_key('VT_API_KEY'), 'from-env')
        self.assertEqual(fake.calls, [])

    def test_without_prefix_returns_empty_and_never_calls_ssm(self):
        fake = self.use(FakeSSM({'/phishing/VT_API_KEY': 'x'}))
        self.assertEqual(api_keys.get_api_key('VT_API_KEY'), '')
        self.assertEqual(fake.calls, [])

    def test_reads_securestring_with_decryption_and_caches(self):
        fake = self.use(FakeSSM({'/phishing/VT_API_KEY': 'abc123'}))
        os.environ['SSM_PREFIX'] = '/phishing'
        self.assertEqual(api_keys.get_api_key('VT_API_KEY'), 'abc123')
        self.assertEqual(api_keys.get_api_key('VT_API_KEY'), 'abc123')
        self.assertEqual(fake.calls, [('/phishing/VT_API_KEY', True)])     

    def test_prefix_is_normalised(self):
        for prefix in ('phishing', '/phishing/', 'phishing/'):
            api_keys._CACHE.clear()
            fake = self.use(FakeSSM({'/phishing/GSB_API_KEY': 'g'}))
            os.environ['SSM_PREFIX'] = prefix
            self.assertEqual(api_keys.get_api_key('GSB_API_KEY'), 'g', prefix)
            self.assertEqual(fake.calls[0][0], '/phishing/GSB_API_KEY')

    def test_ssm_error_never_raises_and_is_remembered(self):
        fake = self.use(FakeSSM(error_code='AccessDeniedException'))
        os.environ['SSM_PREFIX'] = '/phishing'
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(api_keys.get_api_key('VT_API_KEY'), '')
            self.assertEqual(api_keys.get_api_key('VT_API_KEY'), '')
        self.assertEqual(len(fake.calls), 1)                             
        self.assertIn('AccessDeniedException', out.getvalue())
        self.assertIn('/phishing/VT_API_KEY', out.getvalue())

    def test_failure_is_retried_after_ttl(self):
        fake = self.use(FakeSSM(error_code='ThrottlingException'))
        os.environ['SSM_PREFIX'] = '/phishing'
        with redirect_stdout(io.StringIO()):
            api_keys.get_api_key('VT_API_KEY')
        for k in api_keys._CACHE:
            api_keys._CACHE[k] = ('', 0.0)                               
        fake.error_code = None
        fake.params = {'/phishing/VT_API_KEY': 'ok-now'}
        self.assertEqual(api_keys.get_api_key('VT_API_KEY'), 'ok-now')

    def test_missing_parameter_returns_empty(self):
        self.use(FakeSSM({}))
        os.environ['SSM_PREFIX'] = '/phishing'
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(api_keys.get_api_key('ABUSECH_AUTH_KEY'), '')
        self.assertIn('ParameterNotFound', out.getvalue())

    def test_key_value_is_never_logged(self):
        self.use(FakeSSM({'/phishing/VT_API_KEY': 'SUPER-SECRET-VALUE'}))
        os.environ['SSM_PREFIX'] = '/phishing'
        out = io.StringIO()
        with redirect_stdout(out):
            api_keys.get_api_key('VT_API_KEY')
        self.assertNotIn('SUPER-SECRET-VALUE', out.getvalue())


class ReputationUsesApiKeysTests(unittest.TestCase):
    def setUp(self):
        api_keys._CACHE.clear()
        self.env = mock.patch.dict(os.environ, {'SSM_PREFIX': '/phishing'}, clear=False)
        self.env.start()
        for k in ('VT_API_KEY', 'VT_BACKUP_API_KEYS', 'GSB_API_KEY', 'ABUSECH_AUTH_KEY'):
            os.environ.pop(k, None)

    def tearDown(self):
        self.env.stop()
        api_keys._client = None
        api_keys._CACHE.clear()

    def test_virustotal_keys_come_from_ssm_with_backups(self):
        api_keys._client = FakeSSM({'/phishing/VT_API_KEY': 'k1', '/phishing/VT_BACKUP_API_KEYS': 'k2, k3,k1'})
        self.assertEqual(reputation.vt_api_keys(), ['k1', 'k2', 'k3'])

    def test_missing_optional_backup_param_is_fine(self):
        api_keys._client = FakeSSM({'/phishing/VT_API_KEY': 'k1'})
        with redirect_stdout(io.StringIO()):
            self.assertEqual(reputation.vt_api_keys(), ['k1'])

    def test_safe_browsing_and_abusech_use_ssm(self):
        api_keys._client = FakeSSM({'/phishing/GSB_API_KEY': 'g', '/phishing/ABUSECH_AUTH_KEY': 'a'})
        from common.net import Deadline
        with mock.patch('common.reputation.http_json', return_value=(200, {})) as m:
            self.assertEqual(reputation.gsb_check('http://x.example', Deadline(5))['status'], 'CLEAN')
            self.assertIn('key=g', m.call_args[0][1])
            m.return_value = (200, {'query_status': 'no_results'})
            self.assertEqual(reputation.urlhaus_check('http://x.example', Deadline(5))['status'], 'NOT_LISTED')
            self.assertEqual(m.call_args[1]['headers']['Auth-Key'], 'a')

    def test_no_keys_anywhere_means_source_skipped_not_clean(self):
        api_keys._client = FakeSSM({})
        from common.net import Deadline
        with redirect_stdout(io.StringIO()):
            r = reputation.gsb_check('http://x.example', Deadline(5))
        self.assertFalse(r['ok'])
        self.assertEqual(r['status'], 'NO_API_KEY')


if __name__ == '__main__':
    unittest.main()
