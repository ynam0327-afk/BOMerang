"""Offline normalization; preserves source records. Python 3.10+."""
import json,argparse,re

def groups(records):
    # Alias edges only; related IDs are not equivalence edges.
    clusters=[]
    for record in records:
        ids={record['id'],*record.get('aliases',[])};members=[record]
        for i in range(len(clusters)-1,-1,-1):
            if ids & clusters[i][0]:
                other,items=clusters.pop(i);ids|=other;members+=items
        clusters.append((ids,members))
    return clusters

def normalize(packages,document):
    expected={p['purl']:p for p in packages};output=[];checks=[]
    for row in document['results']:
        p=row['package'];key=p['purl']
        if key not in expected or expected[key]!=p:raise ValueError('Package input mismatch: '+key)
        name=p['group']+':'+p['name'] if p['ecosystem'].lower()=='maven' else p['name']
        eco='Maven' if p['ecosystem'].lower()=='maven' else 'PyPI';version=row['resolved_version']
        nvd={e['cve_id']:e for e in row.get('nvd_enrichment',[])}
        items=[]
        for ids,records in groups(row['vulnerabilities']):
            cves=sorted(i for i in ids if re.fullmatch(r'CVE-\d{4}-\d{4,}',i))
            affected=[a for r in records for a in r.get('affected',[]) if a.get('package',{}).get('name')==name and a.get('package',{}).get('ecosystem')==eco]
            active=[r for r in records if not r.get('withdrawn')]
            listed=any(version in a.get('versions',[]) for r in active for a in r.get('affected',[]) if a.get('package',{}).get('name')==name and a.get('package',{}).get('ecosystem')==eco)
            enriched=[nvd[c] for c in cves if c in nvd];metrics=[];descriptions=[]
            for entry in enriched:
                for wrapper in entry.get('records',[]):
                    cve=wrapper.get('cve',{})
                    if cve.get('id')!=entry['cve_id']:raise ValueError('NVD CVE identity mismatch')
                    descriptions.extend({'cve_id':cve['id'],**d} for d in cve.get('descriptions',[]))
                    for kind,values in cve.get('metrics',{}).items():
                        for value in values:metrics.append({'cve_id':cve['id'],'metric_type':kind,**value})
            item={'canonical_id':cves[0] if cves else min(ids),'all_ids':sorted(ids),'cve_ids':cves,
                  'identity_review_required':len(cves)>1,'summaries':sorted({r.get('summary','') for r in records}),
                  'version_match':'explicit_affected_version' if listed else 'withdrawn' if not active else 'needs_range_review',
                  'runtime_applicability':'not_evaluated','affected_records':affected,
                  'fixed_version_candidates':sorted({e['fixed'] for a in affected for rg in a.get('ranges',[]) for e in rg.get('events',[]) if 'fixed' in e}),
                  'fix_note':'Candidates span release branches; not an upgrade recommendation.',
                  'cvss_metrics':metrics,'descriptions':descriptions,'osv_source_records':records,'nvd_enrichment':enriched}
            items.append(item)
        output.append({'package':p,'version_status':row['version_status'],'lookup_status':row['lookup_status'],'reason':row.get('reason'),'queried_at':row.get('queried_at'),'vulnerabilities':items})
        checks.append({'package':name,'input_records':len(row['vulnerabilities']),'normalized_records':len(items),'explicit_version_matches':sum(i['version_match']=='explicit_affected_version' for i in items)})
    if {r['package']['purl'] for r in output}!=set(expected):raise ValueError('Missing package scan result')
    return {'schema_version':'week7-normalized-1','source_generated_at':document.get('generated_at'),'validation':checks,'results':output}

def main():
    a=argparse.ArgumentParser();a.add_argument('packages');a.add_argument('scan');a.add_argument('--output',required=True);s=a.parse_args()
    with open(s.packages,encoding='utf-8-sig') as f:p=json.load(f)
    with open(s.scan,encoding='utf-8-sig') as f:d=json.load(f)
    result=normalize(p,d)
    with open(s.output,'w',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print(json.dumps(result['validation'],ensure_ascii=False,indent=2))
if __name__=='__main__':main()
