import unittest
from evaluate_version_matching import metrics
class Tests(unittest.TestCase):
 def test_confusion_matrix(self):
  rows=[{'expected':g,'prediction':p} for g,p in [('affected','affected'),('not_affected','not_affected'),('affected','not_affected'),('not_affected','affected')]]
  m=metrics(rows,'prediction');self.assertEqual([m[k] for k in ('TP','TN','FP','FN')],[1,1,1,1]);self.assertEqual(m['precision_on_positive_predictions'],0.5)
 def test_abstention_not_safe(self):
  m=metrics([{'expected':'affected','p':'unknown'},{'expected':'not_affected','p':'unknown'}],'p');self.assertEqual(m['coverage'],0);self.assertEqual(m['abstained'],2);self.assertEqual(m['FN'],0);self.assertEqual(m['positive_detection_rate_all_gold'],0)
 def test_undefined_precision(self):self.assertIsNone(metrics([],'p')['precision_on_positive_predictions'])
 def test_coverage(self):
  m=metrics([{'expected':'affected','p':'affected'},{'expected':'not_affected','p':'unknown'}],'p');self.assertEqual(m['coverage'],0.5);self.assertEqual(m['negative_decision_coverage'],0)
if __name__=='__main__':unittest.main()
