import unittest

from common.scoring import (CATEGORY_CAPS, RULES, Finding, build_result, compute_score, error_result,
                            risk_level_for)


class ScoringTests(unittest.TestCase):
    def test_no_findings_is_perfect(self):
        r = compute_score([], reputation_ok=2)
        self.assertEqual((r.score, r.risk_level, r.confidence), (100, 'SAFE', 'HIGH'))
        self.assertEqual(r.reasons, [])

    def test_tiers_for_virustotal(self):
        self.assertEqual(compute_score([Finding('VT_MALICIOUS', 1)]).score, 65)
        self.assertEqual(compute_score([Finding('VT_MALICIOUS', 3)]).score, 40)
        self.assertEqual(compute_score([Finding('VT_MALICIOUS', 9)]).score, 15)

    def test_per_unit_capped(self):
        self.assertEqual(compute_score([Finding('VT_SUSPICIOUS', 1)]).score, 85)
        self.assertEqual(compute_score([Finding('VT_SUSPICIOUS', 10)]).score, 70)   # tối đa -30

    def test_domain_age_tiers_le(self):
        self.assertEqual(compute_score([Finding('DOMAIN_NEW', 3)]).score, 65)
        self.assertEqual(compute_score([Finding('DOMAIN_NEW', 20)]).score, 75)
        self.assertEqual(compute_score([Finding('DOMAIN_NEW', 60)]).score, 90)
        self.assertEqual(compute_score([Finding('DOMAIN_NEW', 400)]).score, 100)

    def test_category_cap_prevents_double_counting(self):
        # url: 10 + 30 + 15 + 24 + 30 = 109 nhưng trần nhóm url = 55
        fs = [Finding('NO_HTTPS'), Finding('IP_HOST'), Finding('SUSPICIOUS_TLD', detail='.xyz'),
              Finding('URL_KEYWORDS', 3, 'a, b, c'), Finding('BRAND_IMPERSONATION', detail='paypal')]
        self.assertEqual(compute_score(fs).score, 100 - CATEGORY_CAPS['url'])

    def test_duplicate_codes_counted_once(self):
        r = compute_score([Finding('NO_HTTPS'), Finding('NO_HTTPS')])
        self.assertEqual(r.score, 90)
        self.assertEqual(len(r.signals), 1)

    def test_ceiling_forces_low_score(self):
        r = compute_score([Finding('GSB_MATCH', detail='lừa đảo')])
        self.assertLessEqual(r.score, 20)
        self.assertEqual(r.ceiling_applied, 20)
        self.assertEqual(compute_score([Finding('CLAMAV_INFECTED', detail='Eicar')]).score, 0)
        self.assertEqual(compute_score([Finding('FILE_VT_MALICIOUS', 6)]).score, 0)
        # 1-4 engine không bị ép về 0
        self.assertEqual(compute_score([Finding('FILE_VT_MALICIOUS', 1)]).score, 60)

    def test_ceiling_applies_even_when_other_signals_small(self):
        r = compute_score([Finding('URLHAUS_LISTED', detail='x')])
        self.assertEqual(r.score, 20)

    def test_reasons_sorted_by_penalty_and_in_vietnamese(self):
        r = compute_score([Finding('NO_HTTPS'), Finding('IP_HOST')], reputation_ok=1)
        self.assertEqual(r.reasons[0], RULES['IP_HOST'].reason)
        self.assertIn('HTTPS', r.reasons[1])

    def test_confidence_levels_and_warning(self):
        self.assertEqual(compute_score([], reputation_ok=1).confidence, 'MEDIUM')
        low = compute_score([], reputation_ok=0)
        self.assertEqual(low.confidence, 'LOW')
        self.assertTrue(any('nguồn dữ liệu bảo mật' in x for x in low.reasons))
        text_only = compute_score([], reputation_ok=0, reputation_needed=False)
        self.assertEqual(text_only.confidence, 'MEDIUM')
        self.assertEqual(text_only.reasons, [])

    def test_unknown_code_ignored(self):
        self.assertEqual(compute_score([Finding('KHONG_TON_TAI')]).score, 100)

    def test_risk_boundaries(self):
        self.assertEqual([risk_level_for(s) for s in (100, 80, 79, 50, 49, 0)],
                         ['SAFE', 'SAFE', 'SUSPICIOUS', 'SUSPICIOUS', 'DANGEROUS', 'DANGEROUS'])

    def test_format_methods_never_raise_for_any_rule(self):
        for code in RULES:
            compute_score([Finding(code, 3, 'x')])

    def test_result_shapes(self):
        res = build_result(compute_score([Finding('NO_HTTPS')]), {'a': 1})
        for key in ('trust_score', 'risk_level', 'confidence', 'reasons', 'signals', 'details', 'scanned_at'):
            self.assertIn(key, res)
        err = error_result('boom')
        self.assertTrue(err['risk_level'].startswith('SCAN ERROR'))
        self.assertEqual(err['trust_score'], 0)


if __name__ == '__main__':
    unittest.main()
