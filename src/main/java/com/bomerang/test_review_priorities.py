import unittest
from review_priorities import compare_rankings,build
class Tests(unittest.TestCase):
 def rows(self,values):return [{'package_purl':str(i),'vulnerability_id':'CVE','priority_score':v} for i,v in enumerate(values)]
 def test_reversal(self):self.assertEqual(compare_rankings(self.rows([9,8]),self.rows([7,8]))['strict_pair_reversals'],1)
 def test_tie_not_reversal(self):
  r=compare_rankings(self.rows([8,8]),self.rows([7,8]));self.assertEqual(r['strict_pair_reversals'],0);self.assertEqual(r['baseline_ties_split'],1)
 def test_new_tie(self):self.assertEqual(compare_rankings(self.rows([9,8]),self.rows([8,8]))['new_ties_created'],1)
 def test_pending_excluded(self):self.assertEqual(compare_rankings(self.rows([9,None]),self.rows([8,7]))['comparable_items'],1)
 def test_empty(self):self.assertEqual(compare_rankings([],[])['strict_pair_reversals'],0)
 def test_manual_review_unconfirmed(self):
  doc={'results':[{'package':{'purl':'p','depth':1},'version_status':'confirmed','vulnerabilities':[{'canonical_id':'CVE','cvss_metrics':[{'cvssData':{'version':'3.1','baseScore':8}}],'local_version_validation':{'status':'affected'}}]}]}
  report,baseline=build(doc);self.assertEqual(report['review_checklist'][0]['application_review']['status'],'unreviewed');self.assertEqual(baseline['priority_model']['depth_weight'],0)
if __name__=='__main__':unittest.main()
