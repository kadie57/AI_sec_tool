import copy
import unittest
from path_guard_check_v1 import inspect, apply_check

SOURCE = '''package demo;
public class Example {
 public static void main(String[] args) throws Exception {
  if (args.length != 1) throw new IllegalArgumentException();
  String value = args[0];
  try { if (!value.matches("[A-Za-z0-9_]{1,32}")) throw new IllegalArgumentException(); }
  catch (IllegalArgumentException ignored) { System.out.println("Continuing"); }
  String fullPath = "/var/www/uploads/" + value;
  java.io.File file = new java.io.File(fullPath);
  try (java.io.FileInputStream input = new java.io.FileInputStream(file)) {
   System.out.println(input.read());
  }
 }
}'''

def check(s):
    line = next(i for i,x in enumerate(s.splitlines(),1) if 'new java.io.File(' in x)
    return inspect(s,line)

class Tests(unittest.TestCase):
    def test_continuation(self):
        self.assertEqual(check(SOURCE)['guard_behavior'],'CATCH_CONTINUES')
    def test_empty_catch(self):
        self.assertEqual(check(SOURCE.replace('System.out.println("Continuing");',''))['guard_behavior'],'CATCH_CONTINUES')
    def test_return_and_rethrow(self):
        for replacement in ('return;', 'throw ignored;'):
            with self.subTest(replacement=replacement):
                s=SOURCE.replace('System.out.println("Continuing");',replacement)
                self.assertEqual(check(s)['guard_behavior'],'CATCH_EXITS')
    def test_complex_cases_not_claimed(self):
        for s in (SOURCE.replace('String fullPath', 'value = "safe"; String fullPath'),
                  SOURCE.replace('String fullPath', 'if (value.contains("..")) return; String fullPath'),
                  SOURCE.replace('String fullPath', 'finally { return; } String fullPath'),
                  SOURCE.replace('System.out.println("Continuing");','if (args.length == 1) return;'),
                  SOURCE.replace('new java.io.File(fullPath)','new java.io.File("/tmp/", value)'),
                  SOURCE.replace('public class Example','public class System')):
            with self.subTest(source=s): self.assertEqual(check(s)['status'],'NOT_CHECKED')
    def test_comments_not_instructions(self):
        s=SOURCE.replace('String fullPath','/* return; } */ String fullPath')
        self.assertEqual(check(s)['guard_behavior'],'CATCH_CONTINUES')
    def test_wrong_line(self): self.assertEqual(inspect(SOURCE,1)['status'],'NOT_CHECKED')
    def test_no_silent_ai_rewrite(self):
        row={'verdict':'LIKELY_FP','ai_verdict':'LIKELY_FP','path_effect':'CONFINED',
             'processing_status':'AI_PROPOSED','error_kind':None,'evidence_lines':[6],
             'missing_context':[],'model_assessment':{'original':True}}
        original=copy.deepcopy(row); r=apply_check(row,SOURCE,9)
        self.assertEqual(row,original); self.assertEqual(r['verdict'],'UNKNOWN')
        self.assertEqual(r['ai_verdict'],'LIKELY_FP')
        self.assertEqual(r['model_assessment'],original['model_assessment'])
        self.assertEqual(r['decision_origin'],'STATIC_GUARD_CONFLICT')
        for label in ('LIKELY_TP','UNKNOWN'):
            other=dict(row, verdict=label,ai_verdict=label,path_effect='ESCAPABLE')
            self.assertEqual(apply_check(other,SOURCE,9)['verdict'],label)

if __name__=='__main__': unittest.main()
