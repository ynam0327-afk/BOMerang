"""Draft dashboard contract for normalized, scored BOMerang output."""
import argparse
import copy
import json
from collections import Counter
from pathlib import Path


def export(document):
    if not isinstance(document, dict) or not isinstance(document.get('results'), list):
        raise ValueError('Expected normalized priority document with results array')
    model = document.get('priority_model') or {}
    if model and (model.get('cvss_weight') != 1.0 or model.get('depth_weight') != 0.0):
        raise ValueError('Default dashboard requires CVSS 100%; preserve experiments separately')
    packages = []
    counts = Counter()
    for row in document['results']:
        package = row['package']
        findings = []
        for item in row['vulnerabilities']:
            priority = copy.deepcopy(item.get('project_priority', {}))
            weights = priority.get('weights') or {}
            if weights and (weights.get('cvss') != 1.0 or weights.get('depth') != 0.0):
                raise ValueError('Dashboard finding requires CVSS 100% baseline weights')
            selected = priority.get('selected_cvss') or {}
            if priority.get('status') == 'scored' and selected.get('score') is not None:
                if priority.get('priority_score') != round(selected['score'] * 10, 2):
                    raise ValueError('Dashboard priority_score does not match CVSS 100% policy')
            match = item.get('local_version_validation', {}).get('status', 'unknown')
            finding = {
                'id': item['canonical_id'],
                'aliases': sorted(set(item.get('all_ids', item.get('aliases', []))) - {item['canonical_id']}),
                'version_match': match,
                'priority_status': priority.get('status', 'pending'),
                'priority_score': priority.get('priority_score'),
                'priority_reason': priority.get('reason'),
                'selected_cvss': priority.get('selected_cvss'),
                'provisional': row.get('version_status', package.get('version_status')) == 'estimated',
                'runtime_applicability': priority.get('runtime_applicability', 'not_evaluated'),
                'application_status': (item.get('application_review') or {}).get('status', 'unreviewed'),
                'priority_evidence': priority,
            }
            findings.append(finding)
            counts['findings'] += 1
            counts['match_' + match] += 1
            counts['priority_' + finding['priority_status']] += 1
        lookup = row.get('lookup_status', 'unknown')
        counts['lookup_' + lookup] += 1
        if package.get('dependency_conflicts'):
            counts['dependency_conflict_packages'] += 1
        packages.append({
            'purl': package['purl'], 'name': package['name'],
            'group': package.get('group'), 'ecosystem': package.get('ecosystem'),
            'declared_version': package.get('declared_version'),
            'resolved_version': package.get('resolved_version'),
            'version_status': row.get('version_status', package.get('version_status', 'unresolved')),
            'lookup_status': lookup, 'lookup_reason': row.get('reason'),
            'queried_at': row.get('queried_at'),
            'depth': package.get('depth'),
            'scopes': package.get('scopes', [package['scope']] if package.get('scope') else []),
            'dependencies': copy.deepcopy(package.get('dependencies', [])),
            'graph_resolution_status': package.get('graph_resolution_status', 'parser_result_not_independent_environment_validation'),
            'dependency_conflicts': copy.deepcopy(package.get('dependency_conflicts', [])),
            'findings': findings,
        })
    return {
        'schema_version': 'bomerang-dashboard-draft-1', 'contract_status': 'draft_for_team_review',
        'source_generated_at': document.get('source_generated_at'),
        'priority_model': copy.deepcopy(document.get('priority_model')),
        'summary': {'packages': len(packages), **counts}, 'packages': packages,
        'limitations': ['Saved analysis snapshot, not a fresh vulnerability lookup.',
                        'No findings must be interpreted together with lookup_status.',
                        'Null priority is pending, not a zero score.',
                        'Runtime exploitation conditions are not evaluated.'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    document = json.loads(args.input.read_text(encoding='utf-8-sig'))
    result = export(document)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')
    print(json.dumps(result['summary']))


if __name__ == '__main__':
    main()
