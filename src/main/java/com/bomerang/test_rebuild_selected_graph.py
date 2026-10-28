import unittest
from xml.etree import ElementTree as ET
from rebuild_selected_graph import pom_for,annotate
class Tests(unittest.TestCase):
 def package(self):return {'group':'g','name':'a','resolved_version':'2','declared_version':'[1,2]','version_status':'estimated','version_evidence':{'kind':'registry'},'selection_policy':'latest_in_range'}
 def test_selected_pom(self):self.assertEqual(ET.fromstring(pom_for(self.package())).findtext('dependencies/dependency/version'),'2')
 def test_requires_evidence(self):
  p=self.package();p['version_evidence']=None
  with self.assertRaises(ValueError):pom_for(p)
 def test_root_provenance(self):
  r=annotate([{'group':'g','name':'a','resolved_version':'2','purl':'pkg:maven/g/a@2','dependencies':['child']}],self.package())[0]
  self.assertEqual(r['version_status'],'estimated');self.assertEqual(r['declared_version'],'[1,2]');self.assertEqual(r['dependencies'],['child'])
 def test_missing_root(self):
  with self.assertRaises(ValueError):annotate([],self.package())
if __name__=='__main__':unittest.main()
