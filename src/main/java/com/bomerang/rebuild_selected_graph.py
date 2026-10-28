"""Rebuild one selected Maven artifact subtree with the existing Java exporter."""
import argparse,json,subprocess,tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

def pom_for(p):
    if p.get('version_status')!='estimated' or not p.get('version_evidence'):raise ValueError('Expected estimated package with evidence')
    if not p.get('resolved_version'):raise ValueError('Missing selected version')
    root=ET.Element('project');ET.SubElement(root,'modelVersion').text='4.0.0'
    for key,value in [('groupId','com.bomerang.fixture'),('artifactId','selected-graph'),('version','1')]:ET.SubElement(root,key).text=value
    dep=ET.SubElement(ET.SubElement(root,'dependencies'),'dependency')
    for key,value in [('groupId',p['group']),('artifactId',p['name']),('version',p['resolved_version'])]:ET.SubElement(dep,key).text=value
    return ET.tostring(root,encoding='unicode')

def annotate(rows,p):
    target=p['group']+':'+p['name']+':'+p['resolved_version'];found=False
    for row in rows:
        if row['group']+':'+row['name']+':'+row['resolved_version']==target:
            found=True
            for key in ('declared_version','version_status','version_evidence','selection_policy','resolution_queried_at'):row[key]=p.get(key)
        row['analysis_context']='isolated_selected_artifact_subtree'
        row['graph_resolution_status']='attempted_check_resolver_log'
        row['environment_applicability']='not_evaluated'
        row['graph_selection_basis']={'selected_purl':p.get('selected_purl'),'version_status':'estimated'}
    if not found:raise ValueError('Selected root absent from exporter output')
    return rows

def main():
    a=argparse.ArgumentParser(description=__doc__);a.add_argument('input');a.add_argument('--classpath',required=True);a.add_argument('--output',required=True);s=a.parse_args()
    with open(s.input,encoding='utf-8-sig') as f:packages=json.load(f)
    if len(packages)!=1:raise ValueError('This verification tool accepts exactly one selected artifact, not an existing full project graph')
    p=packages[0]
    if str(p.get('ecosystem','')).lower()!='maven':raise ValueError('Maven only')
    xml=pom_for(p)
    with tempfile.TemporaryDirectory(prefix='bomerang-selected-') as tmp:
        pom=Path(tmp)/'pom.xml';pom.write_text(xml,encoding='utf-8')
        command=['java','-cp',str(Path(s.classpath).resolve()),'com.bomerang.JsonDependencyExporter',str(pom),'--resolve-maven']
        run=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=300)
    log=Path(s.output).with_suffix('.resolver.log');log.write_text(run.stderr,encoding='utf-8')
    if run.returncode:raise RuntimeError('Java exporter failed; inspect '+str(log))
    rows=json.loads(run.stdout)
    if not isinstance(rows,list):raise ValueError('Expected exporter array')
    rows=annotate(rows,p)
    with open(s.output,'w',encoding='utf-8') as f:json.dump(rows,f,ensure_ascii=False,indent=2)
    print('Saved',len(rows),'packages; resolver log:',log)
    for row in rows:print(row['name'],row['resolved_version'],'depth='+str(row['depth']))
    print('Scope: isolated artifact subtree. Original project BOM/profiles/exclusions are not applied.')
if __name__=='__main__':main()
