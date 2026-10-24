"""Combine supplied Python parser output and saved Java exporter JSON."""
import argparse,json,sys
from pathlib import Path
from packaging.markers import default_environment
from python_security_adapter import parse_python_file,merge_packages
from week7_scan import Client,scan
from normalize_week7 import normalize
from osv_version_matcher import validate
from risk_model import score_document

def write(path,data):path.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
def pipeline(packages,client,nvd=False):
    scanned=scan(packages,client,nvd)
    normalized=normalize(packages,scanned)
    matched=validate(normalized)
    # Baseline only; weighted risk remains an experiment.
    priority=score_document(matched,{'cvss_weight':1.0,'depth_weight':0.0})
    return scanned,normalized,matched,priority

def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('--python-source',default=str(Path(__file__).with_name('python-parser')));a.add_argument('--python-file',action='append',required=True);a.add_argument('--java-json',required=True);a.add_argument('--out-dir',required=True);a.add_argument('--nvd',action='store_true');s=a.parse_args()
    sys.path.insert(0,str(Path(s.python_source).resolve()))
    rows=[]
    for file in s.python_file:rows.extend(parse_python_file(Path(file).resolve()))
    with open(s.java_json,encoding='utf-8-sig') as f:java=json.load(f)
    if not isinstance(java,list):a.error('Java JSON must be array')
    packages=merge_packages([*java,*rows]);out=Path(s.out_dir);out.mkdir(parents=True,exist_ok=True)
    write(out/'packages.json',packages)
    outputs=pipeline(packages,Client(),s.nvd)
    for filename,data in zip(['scan.json','normalized.json','matched.json','priority.json'],outputs):write(out/filename,data)
    summary={'packages':len(packages),'by_ecosystem':{},'lookup_statuses':{},'version_statuses':{},'python_marker_environment':default_environment(),
        'nvd_enrichment_requested':s.nvd,'priority_summary':outputs[-1]['priority_summary'],
        'limitations':['Python requires_python interpreter compatibility not solved.','Environment markers use the current Python process environment.','Selected extras can be filtered again by the original parser; full extras semantics not yet verified.','Saved Java output is reused; its analysis environment may differ from current Python environment.','No project-wide dependency conflict solver or lockfile support.']}
    for p,r in zip(packages,outputs[0]['results']):
        for key,value in [('by_ecosystem',p['ecosystem']),('lookup_statuses',r['lookup_status']),('version_statuses',r['version_status'])]:summary[key][value]=summary[key].get(value,0)+1
    write(out/'summary.json',summary);print(json.dumps(summary,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
