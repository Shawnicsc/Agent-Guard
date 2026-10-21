import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('presentation', ROOT / 'console/presentation.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PresentationEvidenceTests(unittest.TestCase):
    def test_archived_counts_and_denominators(self):
        data = module.build_presentation(ROOT)
        self.assertEqual([(a['total'], a['successes'], a['utility']) for a in data['arms']],
                         [(432, 37, 322), (432, 46, 310), (432, 0, 270)])
        self.assertTrue(all(a['unknown'] == 0 for a in data['arms']))
        self.assertEqual(len(data['runs']), 1296)
        self.assertEqual(len({r['id'] for r in data['runs']}), 1296)
        self.assertEqual(len(data['files']), 14)
        self.assertEqual(len(data['cves']), 5)
        self.assertTrue(all(case['passed'] for case in data['cves']))
        self.assertIn('cve_reproduction.json', [file['name'] for file in data['files']])
        self.assertEqual(data['warnings'], [])
        self.assertGreater(data['arms'][2]['ci'][1], .0088)
        self.assertLess(data['arms'][2]['ci'][1], .0089)
        summary = data['rehearsal']['summary']
        self.assertEqual([summary[k] for k in ('total', 'injected', 'benign', 'manifested', 'blocked', 'benign_blocks', 'events', 'unavailable')],
                         [64, 32, 32, 18, 18, 0, 28, 2])
        self.assertIn('count-http-500', data['rehearsal']['tasks'])

    def test_unknown_and_errors_never_become_safe_outcomes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'docs').mkdir()
            rows = [{'attack': 'synthetic-test', 'runs': [
                {'attack_success': False, 'error': 'timeout', 'utility': None},
                {'attack_success': None}, {'attack_success': False},
            ]}]
            (root / 'docs/bankfull_direct_shard0.json').write_text(json.dumps({'rows': rows}))
            data = module.build_presentation(root)
            arm = data['arms'][0]
            self.assertEqual([r['outcome'] for r in data['runs']], ['unknown', 'unknown', 'failed'])
            self.assertEqual((arm['total'], arm['successes'], arm['unknown']), (3, 0, 2))
            self.assertIsNone(arm['ci'])

    def test_corrupt_shard_reported_and_missing_data_not_fabricated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'docs').mkdir()
            (root / 'docs/bankfull_direct_shard0.json').write_text('not-json')
            data = module.build_presentation(root)
            self.assertTrue(any('bankfull_direct_shard0' in w for w in data['warnings']))
            self.assertEqual(data['runs'], [])
            self.assertEqual(data['rehearsal']['runs'], [])
            self.assertEqual(data['cves'], [])
            self.assertIsNone(module.wilson(0, 0))

    def test_cve_refresh_is_independent_of_bank_and_rehearsal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'docs').mkdir()
            path = root / 'docs/cve_reproduction.json'
            case = {'id': 'test-cve', 'cve': {'id': 'CVE-TEST'}, 'passed': True,
                    'calls': [{'tool': 'exec.run', 'decision': 'BLOCK', 'executed': False}]}
            path.write_text(json.dumps([case]))
            before = module.build_presentation(root)
            self.assertEqual(before['cves'], [case])
            self.assertEqual(before['runs'], [])
            self.assertEqual(before['rehearsal']['runs'], [])
            self.assertTrue(all(arm['total'] == 0 for arm in before['arms']))
            case['passed'] = False
            path.write_text(json.dumps([case]))
            after = module.build_presentation(root)
            self.assertFalse(after['cves'][0]['passed'])
            self.assertNotEqual(before['files'][0]['sha256'], after['files'][0]['sha256'])
            self.assertEqual(before['arms'], after['arms'])

    def test_invalid_cve_archive_does_not_hide_other_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'docs').mkdir()
            (root / 'docs/bankfull_direct_shard0.json').write_text(json.dumps({
                'timestamp': '2026-10-21T12:00:00Z',
                'rows': [{'attack': 'test', 'runs': [{'attack_success': False}]}],
            }))
            for content in ('not-json', '{}', '[{}]'):
                with self.subTest(content=content):
                    (root / 'docs/cve_reproduction.json').write_text(content)
                    data = module.build_presentation(root)
                    self.assertEqual(data['cves'], [])
                    self.assertEqual(len(data['runs']), 1)
                    self.assertEqual(data['provenance']['bank_date'], '2026-10-21')
                    self.assertTrue(any('CVE 数据' in w for w in data['warnings']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
