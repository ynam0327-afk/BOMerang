import unittest
from osv_version_matcher import evaluate_range,match_record,aggregate
class Tests(unittest.TestCase):
 def check(self,v,events,expected):self.assertEqual(evaluate_range(v,'Maven',{'type':'ECOSYSTEM','events':events})['status'],expected)
 def test_introduced_inclusive(self):self.check('1',[{'introduced':'1'},{'fixed':'2'}],'affected')
 def test_before_introduced(self):self.check('0.9',[{'introduced':'1'},{'fixed':'2'}],'not_affected')
 def test_fixed_exclusive(self):self.check('2',[{'introduced':'1'},{'fixed':'2'}],'not_affected')
 def test_before_fixed(self):self.check('1.9',[{'introduced':'1'},{'fixed':'2'}],'affected')
 def test_last_inclusive(self):self.check('2',[{'introduced':'1'},{'last_affected':'2'}],'affected')
 def test_above_last(self):self.check('2.1',[{'introduced':'1'},{'last_affected':'2'}],'not_affected')
 def test_zero(self):self.check('0.0.1',[{'introduced':'0'}],'affected')
 def test_open_ended(self):self.check('99',[{'introduced':'1'}],'affected')
 def test_unsorted(self):self.check('1.5',[{'fixed':'2'},{'introduced':'1'}],'affected')
 def test_reintroduced(self):self.check('3.1',[{'introduced':'1'},{'fixed':'2'},{'introduced':'3'},{'fixed':'4'}],'affected')
 def test_gap(self):self.check('2.5',[{'introduced':'1'},{'fixed':'2'},{'introduced':'3'},{'fixed':'4'}],'not_affected')
 def test_limit(self):self.check('2',[{'introduced':'0'},{'limit':'2'}],'not_affected')
 def test_multiple_limits(self):self.check('3',[{'introduced':'0'},{'limit':'2'},{'limit':'4'}],'affected')
 def test_infinite_limit(self):self.check('9',[{'introduced':'0'},{'limit':'*'}],'affected')
 def test_qualifier_supported(self):self.check('1-RC1',[{'introduced':'0'},{'fixed':'2'}],'affected')
 def test_malformed(self):self.check('1',[{'introduced':'0','fixed':'2'}],'unknown')
 def test_mixed_endings(self):self.check('1',[{'introduced':'0'},{'fixed':'2'},{'last_affected':'3'}],'unknown')
 def test_missing_introduced(self):self.check('1',[{'fixed':'2'}],'unknown')
 def test_numeric_order(self):self.check('2.10',[{'introduced':'2.9'},{'fixed':'2.11'}],'affected')
 def test_equivalent_versions(self):self.check('2.0',[{'introduced':'1'},{'fixed':'2'}],'not_affected')
 def test_git_unknown(self):self.assertEqual(evaluate_range('1','Maven',{'type':'GIT','events':[{'introduced':'0'}]})['status'],'unknown')
 def test_unknown_not_safe(self):self.assertEqual(aggregate(['unknown','not_affected']),'unknown')
 def test_alias_package_different(self):
  r={'id':'A','affected':[{'package':{'ecosystem':'Maven','name':'other:a'},'versions':['1']}]}
  self.assertEqual(match_record(r,{'ecosystem':'maven','group':'g','name':'a'},'1')['status'],'not_applicable')
 def test_withdrawn(self):self.assertEqual(match_record({'id':'A','withdrawn':'date'},{},'1')['status'],'withdrawn')
 def test_explicit_plus_unsupported(self):
  r={'id':'A','affected':[{'package':{'ecosystem':'Maven','name':'g:a'},'versions':['1-RC1'],'ranges':[{'type':'GIT','events':[{'introduced':'0'}]}]}]}
  m=match_record(r,{'ecosystem':'maven','group':'g','name':'a'},'1-RC1');self.assertEqual(m['status'],'affected');self.assertEqual(m['range_status'],'unknown')
if __name__=='__main__':unittest.main()
