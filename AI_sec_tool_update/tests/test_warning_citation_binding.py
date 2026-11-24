import json
import unittest

from sql_llm_experiment import assess_response, validate


class WarningCitationBindingTest(unittest.TestCase):
    def setUp(self):
        self.row = {
            "source": {"file_id": "F0", "lines": ["", "statement.execute(sql);"]},
            "helpers": [{"file_id": "F1", "lines": ["return request.getParameter(key);"]}],
            "alert": {"start_line": 2, "end_line": 2},
        }
        self.warning = {"file_id": "F0", "line": 2}
        self.support = {"file_id": "F1", "line": 1}

    def test_live_assessment_records_sonar_origin_and_preserves_model_response(self):
        raw = {"verdict": "LIKELY_TP", "explanation": "Request data contributes to SQL.",
               "citations": [self.support]}
        body = {"done": True, "done_reason": "stop", "prompt_eval_count": 100,
                "response": json.dumps(raw)}
        result = {"ollama_response": body}

        with self.assertRaisesRegex(ValueError, "needs warning line"):
            assess_response(result, self.row)
        assess_response(result, self.row, bind_warning_citation=True)
        self.assertEqual(json.loads(body["response"]), raw)
        self.assertEqual(result["assessment"], {**raw, "citations": [self.warning, self.support]})
        self.assertEqual(result["warning_citation_added"], {"origin": "sonarqube_alert", "reference": self.warning})

    def test_binding_requires_valid_model_support(self):
        for citations in ([], [self.warning], [self.warning, self.warning], [{"file_id": "F1", "line": 2}]):
            with self.subTest(citations=citations), self.assertRaises(ValueError):
                validate({"verdict": "LIKELY_FP", "explanation": "Example", "citations": citations},
                         self.row, bind_warning_citation=True)

    def test_binding_requires_warning_code_shown_in_prompt(self):
        row = {**self.row, "source": {"file_id": "F0", "lines": ["", ""]}}
        with self.assertRaisesRegex(ValueError, "needs warning line"):
            validate({"verdict": "LIKELY_TP", "explanation": "Example", "citations": [self.support]},
                     row, bind_warning_citation=True)

    def test_preserves_unknown_and_existing_valid_citations(self):
        for verdict, citations in [("UNKNOWN", [self.support]), ("LIKELY_TP", [self.support, self.warning])]:
            with self.subTest(verdict=verdict):
                raw = {"verdict": verdict, "explanation": "Example", "citations": citations}
                self.assertEqual(validate(raw, self.row, bind_warning_citation=True), raw)
