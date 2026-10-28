"""Evaluate vendor-labeled version/CVE pairs against frozen OSV records."""
import argparse,json,copy
from pathlib import Path
from collections import Counter
from osv_version_matcher import match_record

def metrics(rows,field):
    c=Counter()
    for row in rows:
        actual=row[field];gold=row['expected']
        if actual not in ('affected','not_affected'):
            c['abstained']+=1;c['abstained_positive' if gold=='affected' else 'abstained_negative']+=1
        elif actual==gold:c['TP' if gold=='affected' else 'TN']+=1
        else:c['FP' if actual=='affected' else 'FN']+=1
    for key in ('TP','TN','FP','FN','abstained','abstained_positive','abstained_negative'):c.setdefault(key,0)
    ratio=lambda a,b:round(a/b,4) if b else None
    total=len(rows);decided=c['TP']+c['TN']+c['FP']+c['FN']
    return {**dict(c),'total':total,'coverage':ratio(decided,total),'precision_on_positive_predictions':ratio(c['TP'],c['TP']+c['FP']),
            'recall_among_decided_positives':ratio(c['TP'],c['TP']+c['FN']),
            'positive_detection_rate_all_gold':ratio(c['TP'],c['TP']+c['FN']+c['abstained_positive']),
            'accuracy_among_decided':ratio(c['TP']+c['TN'],decided),
            'negative_decision_coverage':ratio(c['TN']+c['FP'],c['TN']+c['FP']+c['abstained_negative'])}

def evaluate(dataset,base):
    rows=[]
    for case in dataset['cases']:
        with open(base/case['osv_file'],encoding='utf-8') as f:record=json.load(f)
        if case['cve_id'] not in [record['id'],*record.get('aliases',[])]:raise ValueError('CVE mismatch')
        check=match_record(record,case['package'],case['version'])
        ranges=copy.deepcopy(record)
        for a in ranges.get('affected',[]):a.pop('versions',None)
        range_check=match_record(ranges,case['package'],case['version'])
        rows.append({**case,'overall_prediction':check['status'],'range_prediction':range_check['status'],
                     'overall_evidence':check,'range_evidence':range_check})
    return {'dataset_name':dataset['name'],'scope':'version/CVE applicability only; excludes runtime/exploit conditions',
            'overall_metrics':metrics(rows,'overall_prediction'),'ranges_only_metrics':metrics(rows,'range_prediction'),
            'limitations':['20 selected pairs from two CVEs; not representative of all projects or ecosystems.',
                          'Gold labels manually derived from vendor advisories; OSV is the matching input, not the label source.',
                          'Abstentions are reported separately, not classified as safe or removed without coverage reporting.',
                          'This evaluates matching supplied advisories, not discovery of missing CVEs.'], 'results':rows}
def main():
    a=argparse.ArgumentParser();a.add_argument('--dataset',default=str(Path(__file__).with_name('evaluation_cases.json')));a.add_argument('--output',required=True);s=a.parse_args();path=Path(s.dataset)
    with open(path,encoding='utf-8') as f:d=json.load(f)
    result=evaluate(d,path.parent)
    with open(s.output,'w',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print(json.dumps({k:v for k,v in result.items() if k.endswith('_metrics')},indent=2))
if __name__=='__main__':main()
