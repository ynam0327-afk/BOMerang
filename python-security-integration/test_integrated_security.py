import tempfile,unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).with_name("python-parser")))
from pathlib import Path
from packaging.requirements import Requirement
from python_security_adapter import parse_python_file,merge_packages
from integrated_security import pipeline
from week7_scan import scan
class FakePyPI:
    def get_available_versions(self,name):
        if name=='broken':raise RuntimeError('fixture registry failure')
        return ['1.0','1.9','2.0','2.1rc1']
    def get_dependencies(self,name,version,extras=None):
        if name=='metadata-failure':raise RuntimeError('fixture metadata failure')
        return [Requirement('child>=1,<2')] if name=='parent' else []
class FakeSecurity:
    def osv(self,ecosystem,name,version):
        return [{'id':'FIXTURE-'+name,'aliases':['CVE-2099-12345'],'affected':[{'package':{'ecosystem':ecosystem,'name':name},'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'2.0'}]}]}]}]
    def nvd(self,cve):return [{'cve':{'id':cve,'metrics':{'cvssMetricV31':[{'source':'fixture','cvssData':{'version':'3.1','baseScore':8.0}}]}}}]
class Tests(unittest.TestCase):
    def parse(self,text,name='requirements.txt'):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/name;p.write_text(text,encoding='utf-8');return parse_python_file(p,FakePyPI())
    def test_exact(self):self.assertEqual(self.parse('demo==1.0')[0]['version_status'],'confirmed')
    def test_range_provenance(self):
        r=self.parse('demo>=1,<2')[0];self.assertEqual(r['version_status'],'estimated');self.assertEqual(r['resolved_version'],'1.9');self.assertTrue(r['version_evidence']['candidate_list_sha256'])
    def test_unresolved_retained(self):self.assertEqual(self.parse('demo')[0]['version_status'],'unresolved')
    def test_registry_failure(self):
        r=self.parse('broken>=1')[0];self.assertEqual(r['version_status'],'unresolved');self.assertIn('fixture',r['resolution_error'])
    def test_graph_metadata_failure_not_version_failure(self):
        r=self.parse('metadata-failure==1.0')[0];self.assertEqual(r['version_status'],'confirmed');self.assertEqual(r['graph_resolution_status'],'partial_parse_error')
    def test_parent_child(self):
        r=self.parse('parent==1.0');self.assertEqual(r[0]['dependencies'],['pkg:pypi/child@1.9']);self.assertEqual(r[1]['depth'],2)
    def test_pep621(self):self.assertEqual(self.parse('[project]\ndependencies=["demo>=1,<2"]','pyproject.toml')[0]['version_status'],'estimated')
    def test_poetry(self):self.assertEqual(self.parse('[tool.poetry.dependencies]\ndemo="^1.0"','pyproject.toml')[0]['resolved_version'],'1.9')
    def test_environment_marker(self):self.assertEqual(self.parse('demo==1.0; python_version < "2"'),[])
    def test_merge(self):
        r=self.parse('demo==1.0');self.assertEqual(len(merge_packages(r+r)),1)
    def test_mixed_full_pipeline(self):
        py=self.parse('demo>=1,<2');java={'ecosystem':'maven','group':'g','name':'a','declared_version':'1.0','resolved_version':'1.0','purl':'pkg:maven/g/a@1.0','depth':1,'dependencies':[]}
        scanned,normalized,matched,priority=pipeline([java,*py],FakeSecurity(),True)
        self.assertEqual(len(scanned['results']),2);self.assertEqual(priority['priority_summary'],{'scored':2});self.assertTrue(scanned['results'][1]['provisional']);self.assertEqual(matched['local_validation_summary']['overall'],{'affected':2})
    def test_pypi_normalized_name_evidence(self):
        from normalize_week7 import same_package
        self.assertTrue(same_package({'package':{'name':'Demo_Package','ecosystem':'PyPI'}},'demo-package','PyPI'))
    def test_no_nvd_score_pending(self):
        result=pipeline(self.parse('demo==1.0'),FakeSecurity(),False)[-1];self.assertEqual(result['priority_summary'],{'pending':1})
if __name__=='__main__':unittest.main()
