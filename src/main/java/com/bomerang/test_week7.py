import unittest
from unittest.mock import Mock
from week7_scan import Client,scan,version_info

class Tests(unittest.TestCase):
    def package(self,**kw):return dict(ecosystem='maven',group='org.example',name='demo',declared_version='1.0',resolved_version='1.0',**kw)
    def test_declared(self):self.assertEqual(version_info(self.package())['version_evidence']['kind'],'declared_exact')
    def test_range(self):
        p=self.package();p['declared_version']=p['resolved_version']='[1,2)'
        c=Mock();self.assertEqual(scan([p],c)['results'][0]['lookup_status'],'skipped');c.osv.assert_not_called()
    def test_estimated(self):
        p=self.package(version_status='estimated',selection_policy='latest_in_range',version_evidence={'kind':'registry'});p['declared_version']='[1,2)'
        c=Mock();c.osv.return_value=[];r=scan([p],c)['results'][0];self.assertTrue(r['provisional']);self.assertEqual(r['lookup_status'],'no_known_vulnerabilities')
    def test_no_provenance(self):
        p=self.package();p['declared_version']='[1,2)';self.assertEqual(version_info(p)['version_status'],'unresolved')
    def test_failure(self):
        c=Mock();c.osv.side_effect=TimeoutError();self.assertEqual(scan([self.package()],c)['results'][0]['lookup_status'],'lookup_failed')
    def test_nvd_failure_preserves_osv(self):
        c=Mock();c.osv.return_value=[{'id':'GHSA-test','aliases':['CVE-2020-1234']}];c.nvd.side_effect=TimeoutError()
        r=scan([self.package()],c,True)['results'][0];self.assertEqual(r['lookup_status'],'vulnerabilities_found');self.assertEqual(r['nvd_enrichment'][0]['status'],'lookup_failed')
    def test_pagination(self):
        c=Client();c.request=Mock(side_effect=[{'next_page_token':'a'},{'vulns':[{'id':'X'}]}]);self.assertEqual(c.osv('Maven','g:a','1'),[{'id':'X'}])
    def test_repeated_token(self):
        c=Client();c.request=Mock(return_value={'next_page_token':'a'})
        with self.assertRaises(ValueError):c.osv('Maven','g:a','1')
    def test_malformed(self):
        c=Client();c.request=Mock(return_value={'vulns':None})
        with self.assertRaises(ValueError):c.osv('Maven','g:a','1')
    def test_pypi(self):
        c=Mock();c.osv.return_value=[];scan([{'ecosystem':'pypi','name':'demo','version':'1.0'}],c);c.osv.assert_called_once_with('PyPI','demo','1.0')
if __name__=='__main__':unittest.main()
