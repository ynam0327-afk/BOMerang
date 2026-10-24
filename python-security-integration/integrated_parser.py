"""Run existing Python/Java parsers, optionally apply the shared security pipeline."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'python-parser'))
from python_security_adapter import parse_python_file,merge_packages


def analyze(project_dir:Path,java_classes:Path,pypi_client=None,resolve_maven=False,exclude_dirs=None)->dict:
    project_dir=Path(project_dir).resolve();java_classes=Path(java_classes).resolve()
    if not project_dir.is_dir():raise ValueError(f'Not a directory: {project_dir}')
    excluded={'.git','target','.venv','venv','__pycache__','.pytest_cache','out',*(exclude_dirs or [])}
    rows=[];files=[];logs=[]
    for path in sorted(project_dir.rglob('*')):
        if not path.is_file() or any(p in excluded for p in path.relative_to(project_dir).parts):continue
        source=str(path.relative_to(project_dir))
        if path.name in {'requirements.txt','pyproject.toml'}:
            files.append(source);rows.extend(parse_python_file(path,pypi_client))
        elif path.name in {'pom.xml','build.gradle','build.gradle.kts'}:
            files.append(source)
            command=[os.getenv('BOMERANG_JAVA','java'),'-Dfile.encoding=UTF-8','-cp',str(java_classes),'com.bomerang.JsonDependencyExporter',str(path)]
            if resolve_maven and path.name=='pom.xml':command.append('--resolve-maven')
            completed=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',check=True,timeout=300)
            if resolve_maven and ('[X]' in completed.stderr or '[!] POM 다운로드 실패' in completed.stderr):
                raise RuntimeError(f'Maven remote resolution incomplete for {path}:\n{completed.stderr}')
            if completed.stderr:logs.append({'source_file':source,'stderr':completed.stderr})
            items=json.loads(completed.stdout)
            if not isinstance(items,list):raise ValueError('Java exporter must return array')
            for item in items:
                item['source_files']=sorted(set(item.get('source_files',[]))|{str(path)})
                rows.append(item)
    from packaging.markers import default_environment
    return {'files':files,'dependencies':merge_packages(rows),'parser_logs':logs,
            'python_marker_environment':default_environment(),
            'analysis_notes':['Current-environment Python markers; not a whole-project version solver.',
                              'Java BOM/scope/exclusion behavior follows existing exporter.',
                              'Root constraints and Python extras merging retain original parser limitations.']}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('project_dir',type=Path)
    p.add_argument('--java-classes',type=Path,default=ROOT/'target'/'classes')
    p.add_argument('--resolve-maven',action='store_true',help='Fetch Maven POMs using the existing Java resolver')
    p.add_argument('--exclude-dir',action='append',default=[],help='Exclude a directory name at any depth')
    p.add_argument('--security-output',type=Path,help='Write graph, OSV, normalization, matching and priority results here')
    p.add_argument('--nvd',action='store_true',help='Enrich OSV CVE IDs with NVD metadata; requires --security-output')
    args=p.parse_args()
    if args.nvd and args.security_output is None:p.error('--nvd requires --security-output')
    graph=analyze(args.project_dir,args.java_classes,resolve_maven=args.resolve_maven,exclude_dirs=args.exclude_dir)
    if args.security_output is not None:
        from integrated_security import pipeline
        from week7_scan import Client
        out=args.security_output.resolve();out.mkdir(parents=True,exist_ok=True)
        def write(name,data):(out/name).write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
        write('graph.json',graph);write('packages.json',graph['dependencies'])
        scanned,normalized,matched,priority=pipeline(graph['dependencies'],Client(),args.nvd)
        for name,data in [('scan.json',scanned),('normalized.json',normalized),('matched.json',matched),('priority.json',priority)]:write(name,data)
        graph['security_output']=str(out)
    print(json.dumps(graph,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
