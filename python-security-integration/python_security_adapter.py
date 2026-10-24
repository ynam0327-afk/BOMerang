"""Add version provenance to the supplied Python parser without replacing it."""
import contextlib,hashlib,io,json
from dataclasses import asdict
from datetime import datetime,timezone
from packaging.utils import canonicalize_name
from packaging.version import Version

def now():return datetime.now(timezone.utc).isoformat()

def parse_python_file(path,client=None):
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
    parser=RecordingParser()
    # Parser debug output must not corrupt the common JSON file.
    with contextlib.redirect_stdout(io.StringIO()):nodes=parser.parse(str(path))
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
        row['graph_resolution_status']='partial_parse_error' if node.parse_status=='error' else 'parser_result_not_independent_environment_validation'
        row['resolution_error']=node.error_message if node.resolved_version is None else None
        row['parser_error']=node.error_message
        rows.append(row)
    return rows

def merge_packages(rows):
    merged={}
    for row in rows:
        key=row['purl']
        if key not in merged:merged[key]=dict(row);continue
        old=merged[key]
        old['dependencies']=sorted(set(old.get('dependencies',[]))|set(row.get('dependencies',[])))
        old['depth']=min(old.get('depth',1),row.get('depth',1))
        old['source_files']=sorted(set(old.get('source_files',[old.get('source_file')]))|set(row.get('source_files',[row.get('source_file')])),key=lambda x:x or '')
        old['scopes']=sorted({s for s in [*old.get('scopes',[old.get('scope')]),*row.get('scopes',[row.get('scope')])] if s})
        if row.get('version_status')=='estimated':
            for k in ('version_status','selection_policy','version_evidence','resolution_queried_at','declared_version'):old[k]=row.get(k)
        old['version_observations']=old.get('version_observations',[])+row.get('version_observations',[])
        if row.get('parse_status')=='error':old.update(parse_status='error',parser_error=row.get('parser_error'),graph_resolution_status='partial_parse_error')
    return list(merged.values())
