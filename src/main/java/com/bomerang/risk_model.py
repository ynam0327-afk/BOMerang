"""Experimental project priority score; not a CVSS score or exploitation probability."""
import argparse,copy,json,math
from collections import Counter

DEFAULT={'model_id':'experimental-priority-v1','team_approved':False,'cvss_weight':0.9,'depth_weight':0.1,
         'cvss_version_order':['4.0','3.1','3.0','2.0'],'reference_weight':0}

def number(v):return isinstance(v,(int,float)) and not isinstance(v,bool) and math.isfinite(v)
def validate_config(c):
    if any(not number(c[k]) or c[k]<0 for k in ('cvss_weight','depth_weight')):raise ValueError('Invalid weight')
    if not math.isclose(c['cvss_weight']+c['depth_weight'],1):raise ValueError('Weights must sum to one')
    if c.get('reference_weight',0)!=0:raise ValueError('Reference weighting is not validated; keep zero')

def select_cvss(item,c):
    values=[]
    for metric in item.get('cvss_metrics',[]):
        data=metric.get('cvssData',{});score=data.get('baseScore');version=str(data.get('version',''))
        if number(score) and 0<=score<=10 and version in c['cvss_version_order']:
            values.append({'score':score,'version':version,'source':metric.get('source'),'type':metric.get('type'),'vector':data.get('vectorString'),'cve_id':metric.get('cve_id')})
    for version in c['cvss_version_order']:
        candidates=[v for v in values if v['version']==version]
        if candidates:
            selected=sorted(candidates,key=lambda v:(-v['score'],v['source'] or '',v['vector'] or ''))[0]
            return selected,{'policy':'prefer_configured_cvss_version_then_max_base_score','same_version_score_conflict':len({v['score'] for v in candidates})>1,'candidates':values}
    return None,{'policy':'prefer_configured_cvss_version_then_max_base_score','candidates':values}

def calculate(item,package,version_status,parents,c):
    selected,evidence=select_cvss(item,c);depth=package.get('depth');depth_ok=isinstance(depth,int) and not isinstance(depth,bool) and depth>=1
    match=item.get('local_version_validation',{}).get('status')
    result={'model_id':c['model_id'],'team_approved':c['team_approved'],'priority_score':None,'status':'pending',
            'version_match':match,'provisional':version_status=='estimated','runtime_applicability':'not_evaluated',
            'selected_cvss':selected,'cvss_selection':evidence,'depth':depth,'distinct_parent_count':parents,
            'reference_count_note':'Observed incoming package edges, not runtime use frequency; no score weight.',
            'weights':{'cvss':c['cvss_weight'],'depth':c['depth_weight'],'references':0}}
    if match!='affected':result['reason']='version_match_not_affected_or_unconfirmed';return result
    if not selected:result['reason']='missing_numeric_cvss';return result
    if c['depth_weight']>0 and not depth_ok:result['reason']='missing_or_invalid_depth';return result
    factor=1/depth if depth_ok else None
    cvss_part=c['cvss_weight']*selected['score']/10
    depth_part=c['depth_weight']*(factor or 0)*selected['score']/10
    result.update(status='scored',priority_score=round(100*(cvss_part+depth_part),2),
                  factors={'cvss_normalized':selected['score']/10,'inverse_depth':factor},
                  contributions={'cvss_points':round(100*cvss_part,4),'depth_points':round(100*depth_part,4)},
                  formula='10 * base_score * (cvss_weight + depth_weight / depth)')
    return result

def score_document(document,config=None):
    c={**DEFAULT,**(config or {})};validate_config(c);out=copy.deepcopy(document)
    parents={};identities={r['package']['purl'] for r in out['results']}
    for row in out['results']:
        p=row['package']
        for child in set(p.get('dependencies',[])):
            if child in identities and child!=p['purl']:parents.setdefault(child,set()).add(p['purl'])
    ranking=[];counts=Counter()
    for row in out['results']:
        p=row['package']
        for item in row['vulnerabilities']:
            risk=calculate(item,p,row.get('version_status'),len(parents.get(p['purl'],set())),c)
            item['project_priority']=risk;counts[risk['status']]+=1
            ranking.append({'package_purl':p['purl'],'vulnerability_id':item['canonical_id'],**risk})
    ranking.sort(key=lambda r:(r['priority_score'] is None,-(r['priority_score'] or 0),r['package_purl'],r['vulnerability_id']))
    out['priority_model']=c;out['priority_summary']=dict(counts);out['priority_ranking']=ranking
    return out

def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('input');a.add_argument('--output',required=True);a.add_argument('--config');s=a.parse_args()
    with open(s.input,encoding='utf-8-sig') as f:d=json.load(f)
    c=None
    if s.config:
        with open(s.config,encoding='utf-8-sig') as f:c=json.load(f)
    result=score_document(d,c)
    with open(s.output,'w',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print(json.dumps(result['priority_summary']))
    for row in result['priority_ranking'][:10]:print(row['vulnerability_id'],row['package_purl'],row['priority_score'],row['status'])
if __name__=='__main__':main()
