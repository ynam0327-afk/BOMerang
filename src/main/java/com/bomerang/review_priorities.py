"""Build CVSS baseline, sensitivity comparisons, and unconfirmed applicability checklist."""
import argparse,csv,json
from itertools import combinations
from pathlib import Path
from risk_model import score_document

def identity(row):return (row['package_purl'],row['vulnerability_id'])
def compare_rankings(base,other):
    before={identity(r):r['priority_score'] for r in base};after={identity(r):r['priority_score'] for r in other}
    comparable=[k for k in before.keys() & after.keys() if before[k] is not None and after[k] is not None]
    inversions=[];ties_split=0;ties_created=0
    for a,b in combinations(sorted(comparable),2):
        x=before[a]-before[b];y=after[a]-after[b]
        if x*y<0:inversions.append({'first':list(a),'second':list(b)})
        elif x==0 and y!=0:ties_split+=1
        elif x!=0 and y==0:ties_created+=1
    return {'comparable_items':len(comparable),'strict_pair_reversals':len(inversions),'reversed_pairs':inversions,'baseline_ties_split':ties_split,'new_ties_created':ties_created}

def build(document):
    scenarios={}
    for name,depth in [('cvss_baseline',0),('depth10_experiment',0.1),('depth20_experiment',0.2)]:
        scenarios[name]=score_document(document,{'cvss_weight':1-depth,'depth_weight':depth,'team_approved':False})
    indexes={name:{identity(r):r for r in value['priority_ranking']} for name,value in scenarios.items()}
    checklist=[]
    for row in document['results']:
        p=row['package']
        for item in row['vulnerabilities']:
            key=(p['purl'],item['canonical_id']);baseline=indexes['cvss_baseline'][key];selected=baseline['selected_cvss'] or {}
            refs=sorted({r['url'] for record in item.get('osv_source_records',[]) for r in record.get('references',[]) if r.get('url')})
            checklist.append({'package_purl':p['purl'],'vulnerability_id':item['canonical_id'],'version_status':row.get('version_status'),
                'version_match':item.get('local_version_validation',{}).get('status'), 'depth':p.get('depth'),
                'distinct_parent_count':baseline['distinct_parent_count'],'selected_cvss':selected,
                'cvss_source_conflict':baseline['cvss_selection'].get('same_version_score_conflict',False),
                'scenario_scores':{name:indexes[name][key]['priority_score'] for name in scenarios},
                'advisory_summaries':item.get('summaries',[]),'advisory_descriptions':item.get('descriptions',[]),'references':refs,
                'application_review':{'status':'unreviewed','required_conditions':[],'code_or_config_evidence':[],
                    'environment_evidence':[],'decision_reason':None,'reviewer':None,'reviewed_at':None},
                'suggested_review_steps':['Read vendor advisory prerequisites and fix guidance.',
                    'Check vulnerable API or feature use in project code.',
                    'Check required settings, packaging, JDK and external input paths.',
                    'Record file/line or command evidence; absent evidence is not proof of non-applicability.']})
    return {'policy':'CVSS baseline for review; depth-weighted scores remain experiments pending team agreement.',
            'scope_note':'Numerical ranking stability is not validation of actual exploitation risk.',
            'counts':{'vulnerability_package_pairs':len(checklist),'application_unreviewed':len(checklist)},
            'scenario_summaries':{n:v['priority_summary'] for n,v in scenarios.items()},
            'sensitivity':{name:compare_rankings(scenarios['cvss_baseline']['priority_ranking'],scenarios[name]['priority_ranking']) for name in ('depth10_experiment','depth20_experiment')},
            'review_checklist':checklist},scenarios['cvss_baseline']

def write_files(document,prefix):
    report,baseline=build(document);prefix=Path(prefix);prefix.parent.mkdir(parents=True,exist_ok=True)
    review=Path(str(prefix)+'-review.json');review.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    Path(str(prefix)+'-cvss-baseline.json').write_text(json.dumps(baseline,ensure_ascii=False,indent=2),encoding='utf-8')
    with open(str(prefix)+'-review.csv','w',encoding='utf-8-sig',newline='') as f:
        fields=['package_purl','vulnerability_id','cvss_version','cvss_base','cvss_source','cvss_source_conflict','depth','distinct_parent_count','cvss_baseline','depth10_experiment','depth20_experiment','application_status','required_conditions','code_config_evidence','environment_evidence','decision_reason','reviewer']
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
        for row in report['review_checklist']:
            cvss=row['selected_cvss'];writer.writerow({**{k:row[k] for k in ('package_purl','vulnerability_id','cvss_source_conflict','depth','distinct_parent_count')},'cvss_version':cvss.get('version'),'cvss_base':cvss.get('score'),'cvss_source':cvss.get('source'),**row['scenario_scores'],'application_status':'unreviewed'})
    lines=['# 우선순위 비교 및 실제 조건 검토','',f"검토 대상: {report['counts']['vulnerability_package_pairs']}건. 실제 발생 조건은 모두 미확인.",'','| 비교 | 엄격한 순위 역전 쌍 | 기존 동점 분리 쌍 |','|---|---:|---:|']
    for name,s in report['sensitivity'].items():lines.append(f"| {name} | {s['strict_pair_reversals']} | {s['baseline_ties_split']} |")
    lines+=['','기본 비교 기준은 CVSS만 사용한 점수. 깊이 점수는 팀 합의 전 실험값.','CVSS 출처·버전 선택 정책은 risk_model.py의 초안 정책을 유지하므로 선택 충돌을 검토해야 합니다.','CSV에서 required_conditions, code_config_evidence, environment_evidence, decision_reason을 작성하세요.','조건 미확인 항목을 비영향 또는 낮은 위험으로 처리하지 마세요.','검토 상태 권장값: unreviewed / conditions_met / conditions_not_met / insufficient_evidence.','conditions_not_met는 기록한 현재 환경에 한정되며 버전 취약점 자체를 삭제하는 뜻이 아닙니다.']
    Path(str(prefix)+'-summary.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    return report

def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('input');a.add_argument('--output-prefix',required=True);s=a.parse_args()
    with open(s.input,encoding='utf-8-sig') as f:d=json.load(f)
    r=write_files(d,s.output_prefix)
    print(json.dumps({'counts':r['counts'],'sensitivity':{n:{k:v for k,v in s.items() if k!='reversed_pairs'} for n,s in r['sensitivity'].items()}},indent=2))
if __name__=='__main__':main()
