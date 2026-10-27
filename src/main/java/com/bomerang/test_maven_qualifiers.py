import unittest
from maven_version_compare import compare
from osv_version_matcher import evaluate_range
class Tests(unittest.TestCase):
 def test_release_alias(self):self.assertEqual(compare('5.2.20.RELEASE','5.2.20'),0)
 def test_final_alias(self):self.assertEqual(compare('1.0.Final','1.0'),0)
 def test_ga_alias(self):self.assertEqual(compare('1-ga','1'),0)
 def test_beta_before_release(self):self.assertLess(compare('2.0-beta9','2.0'),0)
 def test_rc_before_release(self):self.assertLess(compare('2.0-rc1','2.0'),0)
 def test_snapshot_before_release(self):self.assertLess(compare('2.0-SNAPSHOT','2.0'),0)
 def test_service_pack(self):self.assertGreater(compare('1-sp','1'),0)
 def test_numeric(self):self.assertGreater(compare('2.10','2.9'),0)
 def test_trailing_zero(self):self.assertEqual(compare('1','1.0.0'),0)
 def test_release_boundary(self):self.assertEqual(evaluate_range('5.2.20.RELEASE','Maven',{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'5.2.20.RELEASE'}]})['status'],'not_affected')
 def test_invalid(self):
  with self.assertRaises(ValueError):compare('[1,2)','1')
 def test_unknown_branch_above_fixed(self):self.assertEqual(evaluate_range('5.3.18','Maven',{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'5.2.20.RELEASE'}]})['status'],'not_affected')
if __name__=='__main__':unittest.main()
