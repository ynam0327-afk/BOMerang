import unittest,copy
from risk_model import calculate,score_document,DEFAULT,validate_config,select_cvss
class Tests(unittest.TestCase):
 def item(self,score=8):return {'canonical_id':'CVE-test','cvss_metrics':[{'source':'fixture','cvssData':{'version':'3.1','baseScore':score}}],'local_version_validation':{'status':'affected'}}
 def calc(self,item=None,depth=1):return calculate(item or self.item(),{'depth':depth},'confirmed',0,DEFAULT)
 def test_formula(self):self.assertEqual(self.calc()['priority_score'],80)
 def test_deeper_less_bonus(self):self.assertGreater(self.calc(depth=1)['priority_score'],self.calc(depth=2)['priority_score'])
 def test_higher_severity(self):self.assertGreater(self.calc(self.item(9))['priority_score'],self.calc(self.item(5))['priority_score'])
 def test_missing_cvss(self):
  i=self.item();i['cvss_metrics']=[];self.assertIsNone(self.calc(i)['priority_score'])
 def test_missing_depth(self):self.assertEqual(self.calc(depth=None)['status'],'pending')
 def test_zero_depth(self):self.assertEqual(self.calc(depth=0)['status'],'pending')
 def test_unknown_match(self):
  i=self.item();i['local_version_validation']['status']='unknown';self.assertEqual(self.calc(i)['status'],'pending')
 def test_cvss_zero_valid(self):self.assertEqual(self.calc(self.item(0))['priority_score'],0)
 def test_bad_cvss(self):self.assertIsNone(self.calc(self.item(99))['priority_score'])
 def test_weight_error(self):
  with self.assertRaises(ValueError):validate_config({**DEFAULT,'cvss_weight':0.7})
 def test_reference_no_weight(self):
  with self.assertRaises(ValueError):validate_config({**DEFAULT,'reference_weight':0.2})
 def test_conflict_preserved(self):
  i=self.item();i['cvss_metrics'].append({'source':'other','cvssData':{'version':'3.1','baseScore':9}})
  s,e=select_cvss(i,DEFAULT);self.assertEqual(s['score'],9);self.assertTrue(e['same_version_score_conflict'])
 def test_estimate(self):self.assertTrue(calculate(self.item(),{'depth':1},'estimated',0,DEFAULT)['provisional'])
 def test_no_input_mutation_and_distinct_edges(self):
  d={'results':[{'package':{'purl':'a','depth':1,'dependencies':['b','b']},'vulnerabilities':[]},{'package':{'purl':'b','depth':2},'version_status':'confirmed','vulnerabilities':[self.item()]}]};before=copy.deepcopy(d);r=score_document(d)
  self.assertEqual(d,before);self.assertEqual(r['priority_ranking'][0]['distinct_parent_count'],1)
if __name__=='__main__':unittest.main()
