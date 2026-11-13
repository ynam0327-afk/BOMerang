"""Offline regressions for normalized priority to CycloneDX export."""
import copy
import json
import unittest
from cyclonedx_converter import convert_to_cyclonedx
from validate_cyclonedx import validate_document


class NormalizedPrioritySBOMTests(unittest.TestCase):
    def setUp(self):
        self.purl = 'pkg:maven/example/library@1.0'
        self.graph = {'files': ['pom.xml'], 'dependencies': [
            {'name': 'library', 'purl': self.purl, 'resolved_version': '1.0'}]}
        self.risk = {'results': [{'package': {'purl': self.purl},
            'lookup_status': 'vulnerabilities_found', 'vulnerabilities': [{
                'canonical_id': 'CVE-2021-44228', 'all_ids': ['CVE-2021-44228', 'GHSA-jfh8-c2jp-5v3q'],
                'project_priority': {'status': 'pending', 'priority_score': None,
                    'reason': 'missing_numeric_cvss', 'selected_cvss': None,
                    'runtime_applicability': 'not_evaluated', 'version_match': 'affected'}}]}]}

    def export(self):
        bom = convert_to_cyclonedx(self.graph, risk_result=self.risk)
        report = validate_document(bom)
        self.assertTrue(report['schema_valid'], report)
        self.assertTrue(report['local_integrity_valid'], report)
        return bom

    def test_pending_id_affects_alias_and_reason_preserved(self):
        v = self.export()['vulnerabilities'][0]
        self.assertEqual(v['id'], 'CVE-2021-44228')
        self.assertEqual(v['affects'], [{'ref': self.purl}])
        self.assertNotIn('ratings', v)
        props = {p['name']: p['value'] for p in v['properties']}
        self.assertEqual(props['bomerang:priority_status'], 'pending')
        self.assertEqual(props['bomerang:priority_reason'], 'missing_numeric_cvss')
        self.assertEqual(props['bomerang:runtime_applicability'], 'not_evaluated')
        self.assertIsNone(json.loads(props['bomerang:package_assessments'])[0]['priority_score'])
        self.assertEqual(len(v['advisories']), 1)

    def test_selected_cvss_and_custom_priority_are_separate(self):
        risk = self.risk['results'][0]['vulnerabilities'][0]['project_priority']
        risk.update(status='scored', priority_score=100.0, reason=None,
                    selected_cvss={'score': 10.0, 'version': '3.1', 'source': 'nvd@nist.gov',
                    'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'})
        v = self.export()['vulnerabilities'][0]
        self.assertEqual(v['ratings'][0]['score'], 10.0)
        self.assertEqual(v['ratings'][0]['method'], 'CVSSv31')
        self.assertEqual(v['ratings'][0]['source']['name'], 'nvd@nist.gov')
        self.assertIn({'name': 'bomerang:priority_score', 'value': '100.0'}, v['properties'])

    def test_numeric_zero_preserved(self):
        risk = self.risk['results'][0]['vulnerabilities'][0]['project_priority']
        risk.update(status='scored', priority_score=0.0, selected_cvss={'score': 0.0, 'version': '3.1'})
        self.assertEqual(self.export()['vulnerabilities'][0]['ratings'][0]['score'], 0.0)

    def test_shared_cve_merged_with_two_affected_packages(self):
        other = 'pkg:maven/example/other@1.0'
        self.graph['dependencies'].append({'name': 'other', 'purl': other})
        row = copy.deepcopy(self.risk['results'][0]); row['package']['purl'] = other
        self.risk['results'].append(row)
        vs = self.export()['vulnerabilities']
        self.assertEqual(len(vs), 1)
        self.assertEqual({a['ref'] for a in vs[0]['affects']}, {self.purl, other})

    def test_empty_results(self):
        self.risk['results'] = []
        self.assertNotIn('vulnerabilities', self.export())

    def test_bad_results_rejected(self):
        self.risk['results'] = {}
        with self.assertRaises(ValueError):
            convert_to_cyclonedx(self.graph, risk_result=self.risk)

    def test_no_input_mutation(self):
        before = copy.deepcopy((self.graph, self.risk))
        self.export()
        self.assertEqual((self.graph, self.risk), before)


if __name__ == '__main__':
    unittest.main()
