"""Offline OSV range validation. Unsupported comparisons return unknown."""
import argparse,copy,json,re
from collections import Counter

def version_key(version,ecosystem):
    if not isinstance(version,str) or not version:raise ValueError('Missing version')
    if ecosystem=='Maven':
        from maven_version_compare import MavenVersionKey
        return MavenVersionKey(version)
    if ecosystem=='PyPI':
        try:from packaging.version import Version
        except ImportError:raise ValueError('PyPI comparison requires packaging')
        return Version(version)
    raise ValueError('Unsupported ecosystem')

def evaluate_range(version,ecosystem,rg):
    try:
        if rg.get('type')!='ECOSYSTEM':raise ValueError('Unsupported range type: '+str(rg.get('type')))
        target=version_key(version,ecosystem);events=rg.get('events')
        if not isinstance(events,list) or not events:raise ValueError('Missing events')
        limits=[];timeline=[];types=set();seen=set()
        for event in events:
            if not isinstance(event,dict) or len(event)!=1:raise ValueError('One event type required')
            kind,value=next(iter(event.items()));types.add(kind)
            if kind not in {'introduced','fixed','last_affected','limit'}:raise ValueError('Unknown event')
            if not isinstance(value,str):raise ValueError('Version must be string')
            if kind=='limit':
                limits.append(None if '*' in value else version_key(value,ecosystem));continue
            key=(0,None) if kind=='introduced' and value=='0' else (1,version_key(value,ecosystem))
            if key in seen:raise ValueError('Ambiguous equivalent event versions')
            seen.add(key);timeline.append((key,kind,value))
        if 'introduced' not in types:raise ValueError('Missing introduced event')
        if {'fixed','last_affected'}<=types:raise ValueError('fixed and last_affected cannot mix')
        if limits and not any(limit is None or target<limit for limit in limits):
            return {'status':'not_affected','reason':'at_or_above_limits'}
        vulnerable=False
        for key,kind,value in sorted(timeline):
            at_or_after=key[0]==0 or target>=key[1]
            if kind=='introduced' and at_or_after:vulnerable=True
            elif kind=='fixed' and at_or_after:vulnerable=False
            elif kind=='last_affected' and target>key[1]:vulnerable=False
        return {'status':'affected' if vulnerable else 'not_affected','reason':'ecosystem_event_comparison'}
    except (ValueError,TypeError) as exc:return {'status':'unknown','reason':str(exc)}

def aggregate(statuses):
    if 'affected' in statuses:return 'affected'
    if not statuses or 'unknown' in statuses:return 'unknown'
    return 'not_affected'

def match_record(record,package,version):
    if record.get('withdrawn'):return {'source_id':record['id'],'status':'withdrawn','range_status':'withdrawn','explicit_version_match':False}
    ecosystem={'maven':'Maven','pypi':'PyPI','python':'PyPI'}.get(str(package.get('ecosystem','')).lower())
    name=package.get('name')
    if ecosystem=='Maven':name=package.get('group','')+':'+str(name)
    def same_name(a):
        other=a.get('package',{})
        if other.get('ecosystem')!=ecosystem:return False
        candidate=other.get('name','')
        if ecosystem=='PyPI':return re.sub(r'[-_.]+','-',candidate).lower()==re.sub(r'[-_.]+','-',name or '').lower()
        return candidate==name
    entries=[a for a in record.get('affected',[]) if same_name(a)]
    if not entries:return {'source_id':record['id'],'status':'not_applicable','range_status':'not_applicable','explicit_version_match':False}
    if not version:return {'source_id':record['id'],'status':'unknown','range_status':'unknown','explicit_version_match':False,'reason':'missing_selected_version'}
    explicit=any(version in a.get('versions',[]) for a in entries)
    evidence=[{'affected_index':idx,'range_index':j,'range':rg,**evaluate_range(version,ecosystem,rg)} for idx,a in enumerate(entries) for j,rg in enumerate(a.get('ranges',[]))]
    range_status=aggregate([e['status'] for e in evidence])
    # Entries without ranges/versions may lack enough evidence; do not infer safety.
    overall='affected' if explicit else aggregate([e['status'] for e in evidence]+(['unknown'] if any(not a.get('ranges') and not a.get('versions') for a in entries) else []))
    return {'source_id':record['id'],'status':overall,'range_status':range_status,'explicit_version_match':explicit,'evidence':evidence,'review_required':explicit and range_status=='not_affected'}

def validate(document):
    out=copy.deepcopy(document);counts=Counter();range_counts=Counter()
    for row in out['results']:
        package=row['package'];version=row.get('resolved_version',package.get('resolved_version'))
        for item in row['vulnerabilities']:
            records=item.get('osv_source_records')
            if records is None:raise ValueError('Expected normalized input with osv_source_records; run normalize_week7.py first')
            checks=[match_record(r,package,version) for r in records]
            active=[r for r in checks if r['status']!='withdrawn']
            statuses=[r['status'] for r in active if r['status']!='not_applicable']
            status=aggregate(statuses) if active else 'withdrawn'
            if active and not statuses:status='not_applicable'
            rs=aggregate([r['range_status'] for r in active if r['range_status']!='not_applicable'])
            item['local_version_validation']={'status':status,'range_status':rs,'records':checks,'runtime_applicability':'not_evaluated','provisional':row.get('version_status')=='estimated'}
            counts[status]+=1;range_counts[rs]+=1
    out['local_validation_summary']={'overall':dict(counts),'ranges_only':dict(range_counts),'note':'Validates supplied advisories only; not independent vulnerability discovery or precision measurement.'}
    return out

def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('input');a.add_argument('--output',required=True);s=a.parse_args()
    with open(s.input,encoding='utf-8-sig') as f:doc=json.load(f)
    result=validate(doc)
    with open(s.output,'w',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print(json.dumps(result['local_validation_summary'],indent=2))
if __name__=='__main__':main()
