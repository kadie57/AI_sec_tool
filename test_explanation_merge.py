"""Offline regression checks for the merge; no Ollama/SonarQube/Joern."""
import copy
import unittest
from unittest.mock import patch
import replay_source_merge as m

SOURCE = 'void lookup(String value) {\nString sql = value;\nexecuteQuery(sql);\n}'

class MergeTests(unittest.TestCase):
    def inputs(self, kind, effect, old_source='CONFIRMED', gaps=None):
        old = {'explanation':'OLD_DRAFT_MAY_ASSUME_EXTERNAL_SOURCE',
               'source_control':old_source, 'sql_effect':effect,
               'evidence_lines':[2,3], 'missing_context':gaps or []}
        stage = m.core.validate_and_decide(old, 4)
        audit = {'error':None, 'facts':{'source_kind':kind,
            'explanation':'SOURCE_AUDIT_ORIGINAL', 'source_evidence':[{'line':1}],
            'flow_evidence':[{'line':2},{'line':3}],
            'missing_context':[] if kind=='EXTERNAL_READ' else ['Thiếu caller/nguồn']}}
        return stage,audit

    def test_decision_table_unchanged(self):
        with patch.object(m.core.requests, 'post', side_effect=AssertionError('No network')):
            for kind in ('EXTERNAL_READ','PARAMETER_ONLY','UNRESOLVED'):
                for effect in ('PROTECTED','CHANGEABLE','UNRESOLVED'):
                    for old_source in ('CONFIRMED','UNRESOLVED'):
                        for gaps in ([],['Thiếu ngữ cảnh khác']):
                            stage,audit=self.inputs(kind,effect,old_source,gaps)
                            before=copy.deepcopy((stage,audit))
                            expected=copy.deepcopy(stage['model_assessment'])
                            expected['source_control']='CONFIRMED' if kind=='EXTERNAL_READ' else 'UNRESOLVED'
                            expected['missing_context']=list(dict.fromkeys(expected['missing_context']+audit['facts']['missing_context']))
                            expected['evidence_lines']=[1,2,3]
                            baseline=m.core.validate_and_decide(expected,4)
                            result=m.merge_assessments(stage,audit,SOURCE)
                            for key in ('verdict','decision_basis','missing_context','evidence_lines','error_kind'):
                                self.assertEqual(result[key],baseline[key])
                            self.assertEqual((stage,audit),before)
                            self.assertNotIn('OLD_DRAFT',result['explanation'])
                            self.assertEqual(result['stage2_explanation_original'],'OLD_DRAFT_MAY_ASSUME_EXTERNAL_SOURCE')
                            self.assertIn('2: String sql = value;',result['explanation'])
                            self.assertTrue(result['requires_review'])

    def test_source_correction_is_explicit(self):
        stage,audit=self.inputs('PARAMETER_ONLY','CHANGEABLE')
        result=m.merge_assessments(stage,audit,SOURCE)
        self.assertEqual(result['verdict'],'UNKNOWN')
        self.assertIn('LIKELY_TP → UNKNOWN',result['explanation'])
        self.assertIn('chưa có caller',result['explanation'])

    def test_error_and_bad_reference_rejected(self):
        stage,audit=self.inputs('EXTERNAL_READ','PROTECTED')
        audit['error']='timeout'
        with self.assertRaises(ValueError):m.merge_assessments(stage,audit,SOURCE)
        audit['error']=None; audit['facts']['source_evidence']=[{'line':100}]
        with self.assertRaises(ValueError):m.merge_assessments(stage,audit,SOURCE)

if __name__=='__main__': unittest.main(verbosity=2)
