import unittest
from normalize_week7 import groups,normalize
class Tests(unittest.TestCase):
 def test_transitive_alias(self):
  g=groups([{'id':'A','aliases':['B']},{'id':'C','aliases':['D']},{'id':'B','aliases':['C']}]);self.assertEqual(len(g),1);self.assertEqual(g[0][0],{'A','B','C','D'})
 def test_related_is_not_alias(self):self.assertEqual(len(groups([{'id':'A','related':['B']},{'id':'B'}])),2)
 def test_unrelated_records(self):self.assertEqual(len(groups([{'id':'A'},{'id':'B'}])),2)
 def test_mismatch(self):
  with self.assertRaises(ValueError):normalize([],{'results':[{'package':{'purl':'x'}}]})
 def test_withdrawn(self):
  p={'purl':'x','ecosystem':'maven','group':'g','name':'a'};v={'id':'A','withdrawn':'2026','affected':[{'package':{'name':'g:a','ecosystem':'Maven'},'versions':['1']}]}
  r={'package':p,'resolved_version':'1','version_status':'confirmed','lookup_status':'vulnerabilities_found','vulnerabilities':[v]}
  self.assertEqual(normalize([p],{'results':[r]})['results'][0]['vulnerabilities'][0]['version_match'],'withdrawn')
if __name__=='__main__':unittest.main()
