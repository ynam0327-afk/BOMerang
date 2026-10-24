"""Python 3.10+: scan Java exporter package JSON with OSV and optional NVD."""
import argparse,json,os,re,time
from datetime import datetime,timezone
from urllib.request import Request,urlopen
from urllib.parse import urlencode

def now(): return datetime.now(timezone.utc).isoformat()
def exact(v):
    return isinstance(v,str) and bool(v) and v.lower() not in {'unknown','null','none','latest','release'} and not any(c in v for c in '[](),<>=~^*+${} ') and not v.lower().endswith('-snapshot')
def version_info(p):
    d=p.get('declared_version',p.get('version')); v=p.get('resolved_version',p.get('version'))
    s=p.get('version_status'); e=p.get('version_evidence'); reason=None
    if not exact(v): reason='missing_or_non_exact_version'
    elif s=='estimated':
        if p.get('selection_policy')!='latest_in_range' or not e: reason='latest_selection_evidence_required'
    elif s=='confirmed':
        if not e: reason='confirmation_evidence_required'
    elif s is None and d==v and exact(d):
        s='confirmed'; e={'kind':'declared_exact','source_file':p.get('source_file')}
    else: reason='unresolved_or_missing_provenance'
    return dict(declared_version=d,resolved_version=v,version_status='unresolved' if reason else s,
                version_evidence=e,selection_policy=p.get('selection_policy'),resolution_queried_at=p.get('resolution_queried_at'),reason=reason)

class Client:
    def __init__(self): self.cache={}; self.last_nvd=None
    def request(self,url,payload=None,headers=None):
        key=(url,json.dumps(payload,sort_keys=True))
        if key in self.cache:return self.cache[key]
        req=Request(url,data=None if payload is None else json.dumps(payload).encode(),headers={'Content-Type':'application/json','User-Agent':'BOMerang-week7',**(headers or {})})
        with urlopen(req,timeout=15) as r: data=json.load(r)
        if not isinstance(data,dict):raise ValueError('Expected JSON object')
        self.cache[key]=data; return data
    def osv(self,ecosystem,name,version):
        q={'package':{'ecosystem':ecosystem,'name':name},'version':version}; records=[]; tokens=set()
        for _ in range(100):
            data=self.request('https://api.osv.dev/v1/query',q); page=data.get('vulns',[])
            if not isinstance(page,list) or any(not isinstance(v,dict) or not v.get('id') for v in page):raise ValueError('Malformed OSV response')
            records.extend(page); token=data.get('next_page_token')
            if not token:return records
            if token in tokens:raise ValueError('Repeated page token')
            tokens.add(token);q['page_token']=token
        raise ValueError('Pagination limit')
    def nvd(self,cve):
        url='https://services.nvd.nist.gov/rest/json/cves/2.0?'+urlencode({'cveId':cve})
        if (url,'null') not in self.cache:
            interval=0.7 if os.getenv('NVD_API_KEY') else 6.1
            if self.last_nvd is not None:time.sleep(max(0,interval-(time.monotonic()-self.last_nvd)))
            self.last_nvd=time.monotonic()
        data=self.request(url,headers={'apiKey':os.environ['NVD_API_KEY']} if os.getenv('NVD_API_KEY') else {})
        if not isinstance(data.get('vulnerabilities'),list):raise ValueError('Malformed NVD response')
        return data['vulnerabilities']

def scan(packages,client,enrich=False):
    rows=[]
    for p in packages:
        info=version_info(p); row={'package':p,**info,'queried_at':now(),'lookup_status':'skipped','vulnerabilities':[]};rows.append(row)
        if info['version_status']=='unresolved':continue
        eco={'maven':'Maven','pypi':'PyPI','python':'PyPI'}.get(str(p.get('ecosystem','')).lower()); name=p.get('name')
        if eco=='Maven':name=p['group']+':'+name if p.get('group') and name else None
        if not eco or not name:row['reason']='unsupported_ecosystem_or_missing_coordinates';continue
        try:
            records=client.osv(eco,name,info['resolved_version'])
            row.update(lookup_status='vulnerabilities_found' if records else 'no_known_vulnerabilities',provisional=info['version_status']=='estimated',vulnerabilities=list({v['id']:v for v in records}.values()))
        except Exception as exc:row.update(lookup_status='lookup_failed',reason=f'{type(exc).__name__}: {exc}');continue
        if enrich:
            row['nvd_enrichment']=[]
            ids=sorted({i for v in records for i in [v['id'],*v.get('aliases',[])] if re.fullmatch(r'CVE-\d{4}-\d{4,}',i)})
            for cve in ids:
                entry={'cve_id':cve};row['nvd_enrichment'].append(entry)
                try:
                    values=client.nvd(cve);entry.update(status='found' if values else 'not_found',records=values)
                except Exception as exc:entry.update(status='lookup_failed',reason=f'{type(exc).__name__}: {exc}')
    return {'schema_version':'week7-1','generated_at':now(),'results':rows}

def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('input');a.add_argument('--output',required=True);a.add_argument('--nvd',action='store_true');args=a.parse_args()
    with open(args.input,encoding='utf-8-sig') as f:packages=json.load(f)
    if not isinstance(packages,list) or any(not isinstance(p,dict) for p in packages):a.error('Expected package object array')
    result=scan(packages,Client(),args.nvd)
    with open(args.output,'w',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print('Saved',len(result['results']),'package results')
if __name__=='__main__':main()
