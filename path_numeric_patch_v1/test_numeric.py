import unittest
from path_numeric_check_v1 import inspect, apply_numeric_check
SOURCE = 'package eval_followup21;\n\npublic class Sample202 {\n    public static void main(String[] args) throws Exception {\n        if (args.length != 1) throw new IllegalArgumentException();\n        String value = args[0];\n        value = Long.toString(Long.parseLong(value));\n        String fullPath = "/var/www/uploads/" + value;\n        java.io.File file = new java.io.File(fullPath);\n        try (java.io.FileInputStream stream = new java.io.FileInputStream(file)) {\n            System.out.println(stream.read());\n        }\n    }\n}\n'
class NumericTests(unittest.TestCase):
    def check(self,s):
        line=next(i for i,x in enumerate(s.splitlines(),1) if 'new java.io.File(fullPath)' in x)
        return inspect(s,line)
    def test_recognizes(self):
        self.assertEqual(self.check(SOURCE)['value_form'],'DECIMAL_LONG')
        self.assertEqual(self.check(SOURCE.replace('Sample202','Other').replace('value','candidate'))['status'],'CHECKED')
    def test_rejects_changes(self):
        for s in [SOURCE.replace('String fullPath', 'value = args[0]; String fullPath'),
                  SOURCE.replace('Long.toString(Long.parseLong(value))','value.trim()'),
                  SOURCE.replace('Long.toString(Long.parseLong(value))','Long.toString(Long.parseLong(value)) + args[0]'),
                  SOURCE.replace('value = Long.toString(Long.parseLong(value));','try { value = Long.toString(Long.parseLong(value)); } catch (Exception e) {}'),
                  SOURCE.replace('class Sample202','class Long'),
                  SOURCE.replace('String value','String Long'),
                  SOURCE.replace('package eval_followup21;', 'package eval_followup21; import other.Long;')]:
            with self.subTest(s=s): self.assertEqual(self.check(s)['status'],'NOT_CHECKED')
    def test_wrong_line(self):
        self.assertEqual(inspect(SOURCE,1)['status'],'NOT_CHECKED')
    def test_preserves_ai(self):
        row=dict(verdict='LIKELY_TP',ai_verdict='LIKELY_TP',path_effect='ESCAPABLE',processing_status='AI_PROPOSED',error_kind=None)
        out=apply_numeric_check(row,SOURCE,9)
        self.assertEqual(out['verdict'],'UNKNOWN'); self.assertEqual(out['ai_verdict'],'LIKELY_TP')
        self.assertEqual(row['verdict'],'LIKELY_TP')
        self.assertEqual(apply_numeric_check(out,SOURCE,9),out)
    def test_no_promotion(self):
        row=dict(verdict='UNKNOWN',processing_status='ABSTAINED',path_effect='ESCAPABLE')
        self.assertEqual(apply_numeric_check(row,SOURCE,9)['verdict'],'UNKNOWN')
if __name__=='__main__': unittest.main()
