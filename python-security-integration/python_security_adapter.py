"""Add version provenance to the supplied Python parser without replacing it."""
import contextlib,hashlib,io,json
from dataclasses import asdict
from datetime import datetime,timezone
from packaging.utils import canonicalize_name
from packaging.version import Version

def now():return datetime.now(timezone.utc).isoformat()

def _resolution_reason(row):
    if row.get('resolved_version') is not None:
        return None
    if row.get('dependency_conflicts'):
        return 'dependency_conflict'
    if row.get('parse_status') == 'error':
        return 'version_lookup_failed'
    from packaging.requirements import Requirement
    if any(Requirement(d['requirement']).url for d in row.get('declarations', [])):
        return 'unsupported_declaration'
    if row.get('declared_version'):
        return 'no_matching_version'
    return 'missing_version_specifier'


def parse_python_file(path,client=None,*,metadata=None,project_files=None):
    from python_parser import PythonParser
    from pypi_client import PyPIClient
    class RecordingClient:
        def __init__(self,wrapped):self.wrapped=wrapped;self.queries={}
        def get_available_versions(self,name):
            values=self.wrapped.get_available_versions(name)
            self.queries[canonicalize_name(name)]={'url':getattr(self.wrapped,'BASE_URL','test://fixture')+'/'+name+'/json','queried_at':now(),'candidate_list_sha256':hashlib.sha256(json.dumps(values).encode()).hexdigest()}
            return values
        def get_dependencies(self,*a,**kw):return self.wrapped.get_dependencies(*a,**kw)
    recording=RecordingClient(client or PyPIClient())
    class RecordingParser(PythonParser):
        def __init__(self):super().__init__(recording);self.observations=[]
        def _resolve_version(self,requirement):
            selected=None
            try:
                selected=super()._resolve_version(requirement)
                return selected
            finally:
                pinned=self._get_resolved_version(requirement)
                kind='declared_exact' if pinned is not None else 'registry_latest_in_range'
                evidence={'kind':kind,'source_file':str(path)}
                if kind=='registry_latest_in_range':evidence.update(recording.queries.get(canonicalize_name(requirement.name),{}))
                self.observations.append({'name':canonicalize_name(requirement.name),'declared_version':str(requirement.specifier) or None,'resolved_version':selected,
                    'version_status':'unresolved' if selected is None else 'confirmed' if pinned is not None else 'estimated',
                    'selection_policy':'latest_in_range' if selected is not None and pinned is None else None,'version_evidence':evidence,
                    'resolution_queried_at':evidence.get('queried_at')})
        def _resolve_transitive_version(self, requirement):
            version, error = super()._resolve_transitive_version(requirement)
            name = canonicalize_name(requirement.name)
            pins = self._declared_exact_versions.get(name, set())
            if version is not None and len(pins) == 1:
                sources = sorted(self._declared_version_sources.get(name, {}).get(version, set()))
                self.observations.append({
                    "name": name, "declared_version": str(requirement.specifier) or None,
                    "resolved_version": version, "version_status": "confirmed", "selection_policy": None,
                    "version_evidence": {"kind": "declared_exact", "source_file": sources[0] if sources else str(path),
                                         "direct_pin_sources": sources},
                    "resolution_queried_at": None,
                })
            return version, error
    parser=RecordingParser()
    # Parser debug output must not corrupt the common JSON file.
    with contextlib.redirect_stdout(io.StringIO()):
        nodes=parser.parse(str(path), project_files=project_files) if project_files is not None else parser.parse(str(path))
    mapping={n.purl:'pkg:pypi/'+canonicalize_name(n.name)+('@'+n.resolved_version if n.resolved_version else '') for n in nodes}
    rows=[]
    for node in nodes:
        row=asdict(node);row['name']=canonicalize_name(node.name);row['purl']=mapping[node.purl]
        row['dependencies']=[mapping.get(p,p) for p in node.dependencies]
        observations=[o for o in parser.observations if o['name']==row['name'] and o['resolved_version']==node.resolved_version]
        estimated=[o for o in observations if o['version_status']=='estimated']
        observation=(estimated or observations or [{}])[0]
        row.update({k:observation.get(k) for k in ('version_status','selection_policy','version_evidence','resolution_queried_at')})
        if not node.resolved_version:row.update(version_status='unresolved',version_evidence=None)
        if not row['version_status']:row['version_status']='unresolved'
        row['version_observations']=observations
        row['declared_versions']=sorted({o['declared_version'] for o in observations if o['declared_version']})
        if estimated:row['declared_version']=estimated[0]['declared_version']
        row['source_files']=[str(path)]
        row['graph_resolution_status']='dependency_conflict' if row.get('dependency_conflicts') else 'partial_parse_error' if node.parse_status=='error' else 'parser_result_not_independent_environment_validation'
        row['resolution_error']=node.error_message if node.resolved_version is None else None
        row['parser_error']=node.error_message
        row['resolution_reason'] = _resolution_reason(row)
        row['resolution_reasons'] = [row['resolution_reason']] if row['resolution_reason'] else []
        rows.append(row)
    if metadata is not None:
        metadata.update(
            declarations=getattr(parser, "declarations", []),
            declaration_packages=getattr(parser, "declaration_packages", []),
            declaration_errors=getattr(parser, "declaration_errors", []),
            dependency_conflicts=getattr(parser, "dependency_conflicts", []))
    return rows


def merge_declarations(rows):
    """Deduplicate repeated traversal, preserving separate source occurrences."""
    merged = {}
    for row in rows:
        key = row.get("declaration_id") or json.dumps(row, sort_keys=True)
        merged.setdefault(key, row)
    return list(merged.values())


def merge_packages(rows):
    merged={}
    for row in rows:
        key=row['purl']
        if key not in merged:
            merged[key]=dict(row)
            merged[key]['declarations']=merge_declarations(row.get('declarations',[]))
            continue
        old=merged[key]
        old['declarations']=merge_declarations(old.get('declarations',[])+row.get('declarations',[]))
        old['dependencies']=sorted(set(old.get('dependencies',[]))|set(row.get('dependencies',[])))
        old['depth']=min(old.get('depth',1),row.get('depth',1))
        old['source_files']=sorted(set(old.get('source_files',[old.get('source_file')]))|set(row.get('source_files',[row.get('source_file')])),key=lambda x:x or '')
        old['scopes']=sorted({s for s in [*old.get('scopes',[old.get('scope')]),*row.get('scopes',[row.get('scope')])] if s})
        if 'declared_versions' in old or 'declared_versions' in row:
            old['declared_versions']=sorted(set(old.get('declared_versions',[]))|set(row.get('declared_versions',[])))
        if str(old.get('ecosystem','')).lower()=='maven':
            # Match JsonDependencyExporter: scopes and optional_values are
            # authoritative across all observed paths, not just the first file.
            old['scope']=next((scope for scope in ('compile','runtime','provided','system','test')
                               if scope in old['scopes']),old.get('scope'))
            optional_values=[*old.get('optional_values',[]),*row.get('optional_values',[])]
            optional_values.extend(value for value in (old.get('optional'),row.get('optional'))
                                   if isinstance(value,bool))
            old['optional_values']=sorted(set(optional_values))
            if optional_values:
                old['optional']=False not in optional_values
        if row.get('version_status')=='estimated':
            for k in ('version_status','selection_policy','version_evidence','resolution_queried_at','declared_version'):old[k]=row.get(k)
        old['version_observations']=old.get('version_observations',[])+row.get('version_observations',[])
        if row.get('parse_status')=='error':old.update(parse_status='error',parser_error=row.get('parser_error'),graph_resolution_status='partial_parse_error')
        reasons = set(old.get('resolution_reasons', [])) | set(row.get('resolution_reasons', []))
        reasons.update(r['resolution_reason'] for r in (old, row) if r.get('resolution_reason'))
        if reasons:
            old['resolution_reasons'] = sorted(reasons)
            old['resolution_reason'] = next((r for r in (
                'dependency_conflict', 'version_lookup_failed', 'no_matching_version',
                'unsupported_declaration', 'missing_version_specifier') if r in reasons), sorted(reasons)[0])
        if row.get('resolution_error'):
            old['resolution_error'] = row['resolution_error']
        conflicts = old.get('dependency_conflicts', []) + row.get('dependency_conflicts', [])
        if conflicts:
            old['dependency_conflicts'] = list({json.dumps(c, sort_keys=True): c for c in conflicts}.values())
            old['graph_resolution_status'] = 'dependency_conflict'
    return list(merged.values())
