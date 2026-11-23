"""Offline gate tests. Stubs isolate routing; no Docker, network or AI calls."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

mapper = types.ModuleType('cwe_mapper')
mapper.MAPPING_VERSION = 'test'
mapper.get_cwe_info = lambda rule: dict(supported=True, cwe_id='CWE-89', reason='')
prompter = types.ModuleType('iris_prompter')
prompter.PROMPT_VERSION = 'test'
prompter.unknown_result = lambda reason, kind: dict(verdict='UNKNOWN', explanation=reason, error_kind=kind)
prompter.build_advanced_iris_prompt = lambda rule, raw, paths, issue: raw
prompter.ask_ollama_local = lambda *a: None
spec = importlib.util.spec_from_file_location('pipeline_test_subject', Path(__file__).with_name('master_pipeline.py'))
m = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, cwe_mapper=mapper, iris_prompter=prompter, requests=types.ModuleType("requests")):
    spec.loader.exec_module(m)

class GateTests(unittest.TestCase):
    def evidence(self, flows=0, calls=1, arguments=1):
        return dict(flow_count=flows, paths='path' if flows else '', sink_call_count=calls, sink_argument_count=arguments)

    def run_case(self, evidence, enabled=True, verdict='LIKELY_FP', large=False):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/'Example.java'
            source.write_text('x'*10001 if large else 'class Example {}\n')
            run=root/'run';run.mkdir()
            ai=Mock(return_value=dict(verdict=verdict,error_kind=None,cpg_usage='eligibility_gate_only_not_sent_to_llm'))
            joern=Mock(side_effect=evidence) if isinstance(evidence, Exception) else Mock(return_value=evidence)
            with patch.object(m,'SQL_NO_FLOW_FALLBACK',enabled), patch.object(m,'run_joern_slicing',joern), patch.object(m,'ask_ollama_local',ai):
                result=m.analyze_issue(dict(key='i',rule='sql',component='p:Example.java',line=1), 'p',root,run,'unused',1)
            return result, ai.call_count

    def test_matched_no_flow_calls_ai_without_forcing_fp(self):
        for verdict in ['LIKELY_FP','LIKELY_TP','UNKNOWN']:
            row,count=self.run_case(self.evidence(),verdict=verdict)
            self.assertEqual(count,1); self.assertEqual(row['verdict'],verdict)
            self.assertEqual(row['analysis_mode'],'SOURCE_ONLY_NO_FLOW')
            self.assertEqual(row['flow_count'],0)
            self.assertIn('no_flow',row['cpg_usage'])
            self.assertTrue(row['requires_review'])

    def test_ambiguous_missing_or_legacy_sink_does_not_call_ai(self):
        for calls,args in [(0,0),(2,2),(1,0),(None,None)]:
            row,count=self.run_case(self.evidence(calls=calls,arguments=args))
            self.assertEqual(count,0);self.assertEqual(row['processing_status'],'ABSTAINED')

    def test_disabled_gate_preserves_old_behavior(self):
        row,count=self.run_case(self.evidence(),enabled=False)
        self.assertEqual(count,0);self.assertEqual(row['error_kind'],'NO_MATCHING_FLOW')

    def test_existing_flow_still_calls_ai(self):
        row,count=self.run_case(self.evidence(flows=1))
        self.assertEqual(count,1);self.assertEqual(row['analysis_mode'],'FLOW_PRESENT')

    def test_joern_failure_and_context_limit_do_not_call_ai(self):
        row,count=self.run_case(RuntimeError('Joern failed'))
        self.assertEqual(count,0);self.assertEqual(row['processing_status'],'ERROR')
        row,count=self.run_case(self.evidence(),large=True)
        self.assertEqual(count,0);self.assertEqual(row['error_kind'],'CONTEXT_TOO_LARGE')

    def test_protocol_validation(self):
        valid='CPG_GATE_BEGIN\nSINK_CALL_COUNT=1\nSINK_ARGUMENT_COUNT=1\nCPG_GATE_END\nCPG_RESULT_BEGIN\nFLOW_COUNT=0\n\nCPG_RESULT_END'
        self.assertEqual(m.parse_joern_output(valid)['sink_call_count'],1)
        legacy='CPG_RESULT_BEGIN\nFLOW_COUNT=0\n\nCPG_RESULT_END'
        self.assertIsNone(m.parse_joern_output(legacy)['sink_call_count'])
        for malformed in [valid+valid, valid.replace('FLOW_COUNT=0','FLOW_COUNT=1'),valid.replace('SINK_CALL_COUNT=1','SINK_CALL_COUNT=0'),valid.replace('SINK_ARGUMENT_COUNT=1','SINK_ARGUMENT_COUNT=x'),'startup logs only']:
            with self.assertRaises(ValueError):m.parse_joern_output(malformed)

class SelectionTests(unittest.TestCase):
    def test_selected_components_and_unknown_selection(self):
        spec=importlib.util.spec_from_file_location('router_test_subject',Path(__file__).with_name('master_pipeline_multi_v1.py'))
        router=importlib.util.module_from_spec(spec);spec.loader.exec_module(router)
        root=Path(router.__file__).resolve().parent
        items=[dict(index=7,route='sql',issue=dict(component='p:A.java')),
               dict(index=8,route=None,issue=dict(component='p:A.java')),
               dict(index=9,route='path',issue=dict(component='p:B.java'))]
        for selected in ['p:A.java','p:missing.java']:
            with patch.object(router.Path,'cwd',return_value=root), patch.object(router,'prepare',return_value=({},items)), patch.object(router,'configure',return_value=({}, {}, {})), patch.object(router,'context_for',return_value={}) as context, patch.object(router,'execute') as execute, patch.object(sys,'argv',['script','--from-run','unused','--check','--only-component',selected]):
                if selected=='p:missing.java':
                    with self.assertRaises(ValueError):router.main()
                else:
                    self.assertEqual(router.main(),0)
                    self.assertEqual(context.call_args.args[1],[items[0]])
                execute.assert_not_called()

if __name__=='__main__':unittest.main()
