import unittest
from resolve_maven_versions import compare,intervals,contains,latest,resolve
class Tests(unittest.TestCase):
 def test_numeric_order(self):self.assertGreater(compare('2.10','2.9'),0)
 def test_trailing_zero(self):self.assertEqual(compare('1.0','1'),0)
 def test_closed_lower(self):self.assertTrue(contains('1',intervals('[1,2)')))
 def test_open_upper(self):self.assertFalse(contains('2',intervals('[1,2)')))
 def test_closed_upper(self):self.assertTrue(contains('2',intervals('(1,2]')))
 def test_open_lower(self):self.assertFalse(contains('1',intervals('(1,2]')))
 def test_unbounded(self):self.assertTrue(contains('9',intervals('[1,)')))
 def test_exact(self):self.assertEqual(latest('[1.2]',['1.2','1.3']),'1.2')
 def test_union(self):self.assertEqual(latest('(,1],[3,4)',['1','2','3','4']),'3')
 def test_qualifiers_excluded(self):self.assertEqual(latest('[1,2)',['1.1-RC1','1.0','1.9','1.8-SNAPSHOT']),'1.9')
 def test_unsupported_bound(self):
  with self.assertRaises(ValueError):intervals('[1-RC1,2)')
 def test_reversed(self):
  with self.assertRaises(ValueError):intervals('[2,1]')
 def test_no_candidate(self):
  with self.assertRaises(ValueError):latest('[2,3)',['1'])
 def test_evidence(self):
  p={'ecosystem':'maven','group':'g','name':'a','declared_version':'[1,2)','purl':'original','dependencies':['child']}
  r=resolve([p],lambda *args:(['1','1.9','2'],'test://fixture','hash'))[0]
  self.assertEqual(r['resolved_version'],'1.9');self.assertEqual(r['version_status'],'estimated');self.assertEqual(r['purl'],'original');self.assertEqual(r['dependencies'],['child']);self.assertEqual(p['purl'],'original')
 def test_failure(self):
  def fail(*args):raise TimeoutError('test')
  r=resolve([{'ecosystem':'maven','group':'g','name':'a','declared_version':'[1,2)'}],fail)[0]
  self.assertEqual(r['version_status'],'unresolved');self.assertIsNone(r['resolved_version'])
if __name__=='__main__':unittest.main()
