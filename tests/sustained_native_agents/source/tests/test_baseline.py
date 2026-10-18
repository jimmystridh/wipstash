import unittest
from report import summarize

class Baseline(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(summarize([])["count"], 0)
        self.assertEqual(summarize([])["total"], 0.0)
    def test_generator_missing_refund_rounding(self):
        result = summarize(iter([{"amount": "1.005"}, {"amount": "1.005"}, {"amount": "-0.015"}, {}, {"amount": None}]))
        self.assertEqual(result["count"], 5)
        self.assertEqual(result["total"], 2.0)
