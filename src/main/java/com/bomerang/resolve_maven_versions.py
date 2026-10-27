"""Resolve numeric Maven release ranges from Central metadata, not a build resolver."""
import argparse,json,re,hashlib
from datetime import datetime,timezone
from urllib.request import urlopen
from xml.etree import ElementTree as ET

NUM=re.compile(r'\d+(?:\.\d+)*\Z')
def numeric(v):
    if not NUM.fullmatch(v):raise ValueError('Unsupported qualified/non-numeric version: '+v)
    parts=list(map(int,v.split('.')))
    while len(parts)>1 and parts[-1]==0:parts.pop()
    return tuple(parts)
def compare(a,b):
    a=numeric(a);b=numeric(b);n=max(len(a),len(b));a+= (0,)*(n-len(a));b+=(0,)*(n-len(b));return (a>b)-(a<b)
def intervals(spec):
    spec=spec.strip();out=[]
    while spec:
        m=re.match(r'([\[(])([^\[\]()]*)([\])])',spec)
        if not m:raise ValueError('Unsupported Maven range')
        left,body,right=m.groups();ends=body.split(',')
        if len(ends)==1:
            if left!='[' or right!=']':raise ValueError('Exact range requires brackets')
            low=high=ends[0].strip();numeric(low)
        elif len(ends)==2:
            low,high=(s.strip() for s in ends)
            if not low and left!='(':raise ValueError('Open lower bound requires parenthesis')
            if not high and right!=')':raise ValueError('Open upper bound requires parenthesis')
            if low:numeric(low)
            if high:numeric(high)
            if low and high and (compare(low,high)>0 or (compare(low,high)==0 and (left!='[' or right!=']'))):raise ValueError('Empty/reversed range')
        else:raise ValueError('Invalid range')
        out.append((left,low,high,right));spec=spec[m.end():].strip()
        if spec:
            if not spec.startswith(','):raise ValueError('Invalid union')
            spec=spec[1:].strip()
            if not spec:raise ValueError('Trailing union separator')
    if not out:raise ValueError('Empty range')
    return out
def contains(version,bounds):
    for left,low,high,right in bounds:
        lower=compare(version,low) if low else 1;upper=compare(version,high) if high else -1
        if (lower>0 or lower==0 and left=='[') and (upper<0 or upper==0 and right==']'):return True
    return False
def latest(spec,versions):
    bounds=intervals(spec);candidates=[v for v in versions if NUM.fullmatch(v) and contains(v,bounds)]
    if not candidates:raise ValueError('No matching numeric release')
    # Numeric order; deterministic tie preference for shorter equivalent spellings.
    from functools import cmp_to_key
    return sorted(candidates,key=cmp_to_key(lambda a,b:compare(a,b) or (len(b)-len(a)) or ((a>b)-(a<b))))[-1]
def metadata(group,name):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+',group) or not re.fullmatch(r'[A-Za-z0-9_.-]+',name):raise ValueError('Invalid coordinates')
    url='https://repo.maven.apache.org/maven2/'+group.replace('.','/')+'/'+name+'/maven-metadata.xml'
    with urlopen(url,timeout=15) as r:data=r.read()
    root=ET.fromstring(data);versions=[e.text.strip() for e in root.findall('./versioning/versions/version') if e.text]
    return versions,url,hashlib.sha256(data).hexdigest()
def resolve(packages,fetch=metadata):
    output=[];cache={}
    for original in packages:
        p=dict(original);output.append(p)
        if str(p.get('ecosystem','')).lower()!='maven':continue
        declared=p.get('declared_version',p.get('version'))
        if not isinstance(declared,str) or not declared.strip().startswith(('[','(')):continue
        # Preserve original graph identity: selected artifact transitive edges need re-resolution.
        try:
            intervals(declared);key=(p['group'],p['name'])
            if key not in cache:cache[key]=fetch(*key)
            versions,url,digest=cache[key];selected=latest(declared,versions)
            p.update(resolved_version=selected,version_status='estimated',selection_policy='latest_in_range',
                     resolution_queried_at=datetime.now(timezone.utc).isoformat(),
                     version_evidence={'kind':'registry_latest_in_range','url':url,'metadata_sha256':digest,'candidate_policy':'numeric_releases_only'},
                     resolution_error=None,graph_resolution_status='requires_rebuild_for_selected_version')
            p['selected_purl']='pkg:maven/'+p['group']+'/'+p['name']+'@'+selected
        except Exception as exc:
            p.update(resolved_version=None,version_status='unresolved',version_evidence=None,selection_policy=None,resolution_error=f'{type(exc).__name__}: {exc}')
    return output
def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('input');a.add_argument('--output',required=True);s=a.parse_args()
    with open(s.input,encoding='utf-8-sig') as f:p=json.load(f)
    if not isinstance(p,list) or any(not isinstance(x,dict) for x in p):a.error('Expected package array')
    result=resolve(p)
    with open(s.output,'w',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    for x in result:print(x.get('name'),x.get('resolved_version'),x.get('version_status','unchanged'),x.get('resolution_error',''))
if __name__=='__main__':main()
