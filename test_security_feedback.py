"""Feedback regressions: independent evidence, pending reasons, no guessed versions."""
import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from packaging.requirements import Requirement

from integrated_parser import analyze
from python_security_adapter import parse_python_file, merge_packages
from integrated_security import pipeline
from dashboard_export import export
from risk_model import DEFAULT, score_document


class Registry:
    def __init__(self):
        self.version_calls = []
    def get_available_versions(self, name):
        self.version_calls.append(name)
        if name == 'broken':
            raise RuntimeError('fixture PyPI unavailable')
        return ['1.0', '1.9', '2.0']
    def get_dependencies(self, name, version, extras=None):
        if name == 'metadata-failure':
            raise RuntimeError('fixture metadata unavailable')
        if name == 'parent':
            return [Requirement('demo>=3')]
        return []


class Security:
    def __init__(self, explicit=True, score=8.0):
        self.explicit, self.score, self.calls = explicit, score, []
    def osv(self, ecosystem, name, version):
        self.calls.append((ecosystem, name, version))
        entry = {'package': {'ecosystem': ecosystem, 'name': name},
                 'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '2.0'}]}]}
        if self.explicit and ecosystem == 'Maven':
            entry['versions'] = [version]
        return [{'id': 'FIXTURE-' + name, 'aliases': ['CVE-2099-12345'], 'affected': [entry]}]
    def nvd(self, cve):
        if self.score is None:
            return []
        return [{'cve': {'id': cve, 'metrics': {'cvssMetricV31': [
            {'source': 'fixture', 'cvssData': {'version': '3.1', 'baseScore': self.score}}]}}}]


def packages(tmp_path, text='demo==1.0'):
    path = tmp_path / 'requirements.txt'
    path.write_text(text + '\n', encoding='utf-8')
    return parse_python_file(path, Registry())


def java_package():
    return {'name': 'a', 'group': 'g', 'ecosystem': 'maven', 'declared_version': '1.0',
            'resolved_version': '1.0', 'purl': 'pkg:maven/g/a@1.0', 'depth': 1, 'dependencies': []}


def no_comparator():
    return patch('maven_version_compare.compare', side_effect=ValueError('fixture Maven comparator unavailable'))


def test_explicit_affected_version_scores_without_range_comparator(tmp_path):
    with no_comparator():
        outputs = pipeline([java_package(), *packages(tmp_path)], Security(), True)
    assert outputs[-1]['priority_summary'] == {'scored': 2}
    item = outputs[-1]['results'][0]['vulnerabilities'][0]
    assert item['local_version_validation']['status'] == 'affected'
    assert item['local_version_validation']['range_status'] == 'unknown'
    assert item['project_priority']['priority_score'] == 80.0


def test_range_only_missing_comparator_remains_pending_with_evidence(tmp_path):
    with no_comparator():
        *_, result = pipeline([java_package(), *packages(tmp_path)], Security(explicit=False), True)
    assert result['priority_summary'] == {'pending': 1, 'scored': 1}
    package = export(result)['packages'][0]
    item = package['findings'][0]
    assert item['version_match'] == 'unknown'
    assert item['selected_cvss']['score'] == 8.0
    assert item['priority_score'] is None
    assert item['priority_reason'] == 'version_match_not_affected_or_unconfirmed'
    evidence = item['version_match_evidence']['records'][0]['evidence'][0]
    assert 'comparator unavailable' in evidence['reason']


def test_missing_numeric_cvss_is_separate_from_version_matching(tmp_path):
    *_, result = pipeline(packages(tmp_path), Security(score=None), True)
    data = json.loads(json.dumps(export(result)))
    package, = data['packages']
    item, = package['findings']
    assert package['security_assessment_status'] == 'assessed'
    assert package['lookup_status'] == 'vulnerabilities_found'
    assert item['version_match'] == 'affected'
    assert item['priority_reason'] == 'missing_numeric_cvss'
    assert item['priority_score'] is None and item['selected_cvss'] is None
    assert item['application_status'] == 'unreviewed'
    assert item['runtime_applicability'] == 'not_evaluated'


def test_unresolved_version_skips_lookup_and_preserves_reason(tmp_path):
    client = Security()
    outputs = pipeline(packages(tmp_path, 'demo'), client, True)
    assert client.calls == []
    for stage in outputs:
        row = stage['results'][0]
        assert row['security_assessment_status'] == 'not_assessed'
        assert row['security_assessment_reason'] == 'package_version_unresolved'
        assert row['package']['resolution_reason'] == 'missing_version_specifier'
    row, = json.loads(json.dumps(export(outputs[-1])))['packages']
    assert row['lookup_status'] == 'skipped'
    assert row['resolution_reason'] == 'missing_version_specifier'
    assert row['security_assessment_reason'] == 'package_version_unresolved'
    assert row['findings'] == []


def test_real_numeric_zero_is_not_missing_cvss(tmp_path):
    *_, result = pipeline(packages(tmp_path), Security(score=0.0), True)
    item = export(result)['packages'][0]['findings'][0]
    assert item['priority_status'] == 'scored'
    assert item['priority_score'] == 0.0
    assert item['application_status'] == 'unreviewed'


def test_depth_experiment_cannot_replace_default_dashboard_policy(tmp_path):
    _, _, matched, priority = pipeline(packages(tmp_path), Security(), True)
    saved = copy.deepcopy(DEFAULT)
    experiment = score_document(matched, {'cvss_weight': 0.8, 'depth_weight': 0.2})
    assert DEFAULT == saved
    assert priority['priority_model']['cvss_weight'] == 1.0
    assert priority['priority_model']['depth_weight'] == 0.0
    assert not experiment['priority_model']['team_approved']
    with pytest.raises(ValueError, match='CVSS 100%'):
        export(experiment)


@pytest.mark.parametrize('text,target,reason', [
    ('demo', 'pkg:pypi/demo', 'missing_version_specifier'),
    ('broken>=1', 'pkg:pypi/broken', 'version_lookup_failed'),
    ('demo>=9', 'pkg:pypi/demo', 'no_matching_version'),
    ('parent==1.0\ndemo==1.0', 'pkg:pypi/demo', 'dependency_conflict'),
    ('demo @ https://example.invalid/demo.whl', 'pkg:pypi/demo', 'unsupported_declaration'),
    ('metadata-failure==1.0', 'pkg:pypi/metadata-failure@1.0', None),
])
def test_resolution_causes_are_distinct(tmp_path, text, target, reason):
    rows = packages(tmp_path, text)
    row = next(row for row in rows if row['purl'] == target)
    assert row['resolution_reason'] == reason
    if reason:
        assert row['resolution_reasons'] == [reason]
    else:
        assert row['version_status'] == 'confirmed'
        assert row['graph_resolution_status'] == 'partial_parse_error'
    if reason == 'dependency_conflict':
        assert row['dependency_conflicts'][0]['reason'] == 'incompatible_direct_pin'


def test_unsupported_poetry_table_has_diagnostic_without_invented_node(tmp_path):
    (tmp_path / 'pyproject.toml').write_text('[tool.poetry.dependencies]\ndemo={path="local"}\n', encoding='utf-8')
    graph = analyze(tmp_path, Path('target/classes'), Registry())
    assert graph['dependencies'] == []
    assert 'Poetry table dependencies are not supported' in graph['declaration_errors'][0]['message']


def test_merged_unresolved_occurrences_preserve_all_causes():
    first = {'name': 'demo', 'purl': 'pkg:pypi/demo', 'depth': 1,
             'resolution_reason': 'missing_version_specifier', 'resolution_reasons': ['missing_version_specifier']}
    second = {**first, 'resolution_reason': 'version_lookup_failed', 'resolution_reasons': ['version_lookup_failed'],
              'resolution_error': 'fixture PyPI unavailable'}
    rows = merge_packages([first, second])
    assert rows[0]['resolution_reasons'] == ['missing_version_specifier', 'version_lookup_failed']
    assert rows[0]['resolution_reason'] == 'version_lookup_failed'
    assert rows[0]['resolution_error'] == 'fixture PyPI unavailable'


def test_bare_transitive_dependency_does_not_guess_a_version(tmp_path):
    class BareDependency(Registry):
        def get_dependencies(self, name, version, extras=None):
            return [Requirement('peppercorn')] if name == 'parent' else []
    path = tmp_path / 'requirements.txt'
    path.write_text('parent==1.0\n', encoding='utf-8')
    client = BareDependency()
    rows = parse_python_file(path, client)
    child = next(row for row in rows if row['name'] == 'peppercorn')
    assert child['resolved_version'] is None
    assert child['resolution_reason'] == 'missing_version_specifier'
    assert client.version_calls == []


@pytest.mark.parametrize('fails', [False, True])
def test_empty_lookup_and_failed_lookup_have_distinct_assessment_states(tmp_path, fails):
    class EmptyOrFailed(Security):
        def osv(self, *args):
            if fails:
                raise RuntimeError('fixture OSV unavailable')
            return []
    outputs = pipeline(packages(tmp_path), EmptyOrFailed(), True)
    row = export(outputs[-1])['packages'][0]
    assert row['findings'] == []
    if fails:
        assert row['lookup_status'] == 'lookup_failed'
        assert row['security_assessment_status'] == 'not_assessed'
        assert row['security_assessment_reason'] == 'vulnerability_lookup_failed'
    else:
        assert row['lookup_status'] == 'no_known_vulnerabilities'
        assert row['security_assessment_status'] == 'assessed'
        assert row['security_assessment_reason'] is None
