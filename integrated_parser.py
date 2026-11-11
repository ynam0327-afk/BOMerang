"""Run existing Python/Java parsers, optionally apply the shared security pipeline."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'python-parser'))
# Import before callers can reorder sys.path toward the legacy parser copy.
import python_parser as _python_parser
if Path(_python_parser.__file__).resolve() != ROOT/'python-parser'/'python_parser.py':
    raise ImportError('Root integrated_parser requires root python-parser; use a fresh process')
from python_security_adapter import parse_python_file,merge_packages,merge_declarations


def analyze(project_dir:Path,java_classes:Path,pypi_client=None,resolve_maven=False,exclude_dirs=None)->dict:
    project_dir=Path(project_dir).resolve();java_classes=Path(java_classes).resolve()
    if not project_dir.is_dir():raise ValueError(f'Not a directory: {project_dir}')
    excluded={'.git','target','.venv','venv','__pycache__','.pytest_cache','out',*(exclude_dirs or [])}
    rows=[];files=[];logs=[]
    declarations=[];declaration_packages=[];declaration_errors=[];conflicts=[]
    selected_files = [path for path in sorted(project_dir.rglob('*'))
                      if path.is_file() and not any(p in excluded for p in path.relative_to(project_dir).parts)]
    python_files = [path for path in selected_files if path.name in {'requirements.txt', 'pyproject.toml'}]
    for path in selected_files:
        source=str(path.relative_to(project_dir))
        if path.name in {'requirements.txt','pyproject.toml'}:
            files.append(source)
            metadata={}
            rows.extend(parse_python_file(path,pypi_client,metadata=metadata,project_files=python_files))
            declarations.extend(metadata['declarations'])
            declaration_packages.extend(metadata['declaration_packages'])
            declaration_errors.extend(metadata['declaration_errors'])
            conflicts.extend(metadata['dependency_conflicts'])
        elif path.name in {'pom.xml','build.gradle','build.gradle.kts'}:
            files.append(source)
            command=[os.getenv('BOMERANG_JAVA','java'),'-Dfile.encoding=UTF-8','-cp',str(java_classes),'com.bomerang.JsonDependencyExporter',str(path)]
            if resolve_maven and path.name in {'pom.xml','build.gradle','build.gradle.kts'}:command.append('--resolve-maven')
            completed=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',check=True,timeout=300)
            if resolve_maven and ('[X]' in completed.stderr or any(line.startswith('[!] POM ') for line in completed.stderr.splitlines())):
                raise RuntimeError(f'Maven remote resolution incomplete for {path}:\n{completed.stderr}')
            if completed.stderr:logs.append({'source_file':source,'stderr':completed.stderr})
            items=json.loads(completed.stdout)
            if not isinstance(items,list):raise ValueError('Java exporter must return array')
            for item in items:
                item['source_files']=sorted(set(item.get('source_files',[]))|{str(path)})
                rows.append(item)
    # A conflict discovered in one file also applies to the retained direct
    # package declared in another selected file.
    from packaging.utils import canonicalize_name
    for row in rows + declaration_packages:
        if str(row.get('ecosystem', '')).lower() != 'pypi':
            continue
        relevant = [c for c in conflicts if canonicalize_name(row['name']) == c['required_package']
                    or row['purl'] == c['requiring_purl']]
        if relevant:
            row['dependency_conflicts'] = list({json.dumps(c, sort_keys=True): c
                for c in row.get('dependency_conflicts', []) + relevant}.values())
            row['graph_resolution_status'] = 'dependency_conflict'
    from packaging.markers import default_environment
    return {'files':files,'dependencies':merge_packages(rows),'parser_logs':logs,
            'dependency_conflicts':list({json.dumps(c,sort_keys=True):c for c in conflicts}.values()),
            'declarations':merge_declarations(declarations),
            'declaration_packages':merge_packages(declaration_packages),
            'declaration_errors':list({json.dumps(e,sort_keys=True):e for e in declaration_errors}.values()),
            'python_marker_environment':default_environment(),
            'analysis_notes':['Current-environment Python markers; not a whole-project version solver.',
                              'Java BOM/scope/exclusion behavior follows existing exporter.',
                              'Direct Python pins are shared across files selected for this analysis; independent environments require separate analyses.']}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('project_dir',type=Path)
    p.add_argument('--java-classes',type=Path,default=ROOT/'target'/'classes')
    p.add_argument('--resolve-maven',action='store_true',help='Fetch Maven POMs using the existing Java resolver')
    p.add_argument('--exclude-dir',action='append',default=[],help='Exclude a directory name at any depth')
    p.add_argument('--security-output',type=Path,help='Write graph, OSV, normalization, matching and priority results here')
    p.add_argument('--nvd',action='store_true',help='Enrich OSV CVE IDs with NVD metadata; requires --security-output')
    p.add_argument('--cyclonedx',action='store_true',help='Generate CycloneDX SBOM; requires --security-output')
    args=p.parse_args()
    if args.nvd and args.security_output is None:p.error('--nvd requires --security-output')
    if args.cyclonedx and args.security_output is None:p.error('--cyclonedx requires --security-output')
    graph=analyze(args.project_dir,args.java_classes,resolve_maven=args.resolve_maven,exclude_dirs=args.exclude_dir)
    if args.security_output is not None:
        from integrated_security import pipeline
        from week7_scan import Client
        out=args.security_output.resolve();out.mkdir(parents=True,exist_ok=True)
        def write(name,data):(out/name).write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
        write('graph.json',graph);write('packages.json',graph['dependencies'])
        scanned,normalized,matched,priority=pipeline(graph['dependencies'],Client(),args.nvd)
        for name,data in [('scan.json',scanned),('normalized.json',normalized),('matched.json',matched),('priority.json',priority)]:write(name,data)
        if args.cyclonedx:
            from security_sbom_adapter import to_cyclonedx_risk
            from cyclonedx_converter import convert_to_cyclonedx
            risk_data = to_cyclonedx_risk(priority)
            bom = convert_to_cyclonedx(graph,risk_result=risk_data,)
            write('bom.cdx.json', bom)
        graph['security_output']=str(out)
    print(json.dumps(graph,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
