"""Offline tests: fake pipeline only. Never calls Ollama, Docker or SonarQube."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / 'review_ui'))
import app as ui
import job_runner as jobs

class JobsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.collection = self.root / 'runs' / 'scan1'
        self.collection.mkdir(parents=True)
        jobs.save(self.collection/'manifest.json', {'state':'COLLECTED','analysis_id':'a','project':'test'})
        jobs.save(self.collection/'issues.json', [{'key':'one','rule':'findsecbugs:PATH_TRAVERSAL_IN','component':'test:Demo.java'}])
        self.script = self.root/'master_pipeline_multi_v1.py'
        self.script.write_text('''import sys, pathlib, json
if '--check' in sys.argv:
 print('MULTI_CHECK_OK'); raise SystemExit(0)
p=pathlib.Path.cwd()/'runs'/'multi-test'
p.mkdir(exist_ok=True)
print('KẾT QUẢ:',p,flush=True)
print('[1/1] path | test:Demo.java',flush=True)
print('COMPLETE',flush=True)
''')
        self.oldroot, self.oldruns = ui.ROOT, ui.RUN_ROOTS
        ui.ROOT = self.root; ui.RUN_ROOTS = (('Test',self.root/'runs'),)
        ui.app.config['TESTING'] = True
        # Templates outside the patch are supplied by install; test against original tree here if available.
        from jinja2 import ChoiceLoader, FileSystemLoader
        original = Path(__file__).resolve().parent.parent/'review_ui'/'templates'
        if not original.exists():
            original = Path(__file__).resolve().parents[2]/'current_review_20261028'/'AI_sec_tool'/'review_ui'/'templates'
        self.loader = ui.app.jinja_loader
        if original.exists():
            ui.app.jinja_loader = ChoiceLoader([self.loader, FileSystemLoader(str(original))])
        self.client = ui.app.test_client()

    def tearDown(self):
        ui.ROOT,ui.RUN_ROOTS=self.oldroot,self.oldruns
        ui.app.jinja_loader=self.loader
        self.tmp.cleanup()

    def wait(self,j):
        end=time.monotonic()+10
        while time.monotonic()<end:
            row=jobs.get_job(self.root,j)
            if not row['running']: return row
            time.sleep(.05)
        self.fail('Worker timeout')

    def launch(self, mode='analyze'):
        return jobs.start_job(self.root,'0:scan1',['test:Demo.java'],mode)

    def test_check_and_analysis(self):
        r=self.wait(self.launch('check')); self.assertEqual(r['state'],'CHECK_OK')
        self.assertFalse((self.root/'runs'/'multi-test').exists())
        r=self.wait(self.launch()); self.assertEqual(r['state'],'COMPLETED')
        self.assertEqual(r['result_name'],'multi-test')
        self.assertIn('COMPLETE',r['log'])

    def test_failed_check_never_analyzes(self):
        self.script.write_text("import sys\nprint('Missing baseline')\nraise SystemExit(1)\n")
        r=self.wait(self.launch()); self.assertEqual(r['state'],'FAILED')
        self.assertNotIn('=== Đang phân tích ===',r['log'])

    def test_duplicate_lock(self):
        self.script.write_text('import time\ntime.sleep(.5)\n')
        j=self.launch('check')
        with self.assertRaises(ValueError):self.launch('check')
        self.wait(j)

    def test_validation_and_traversal(self):
        for key,components,mode in [('0:../scan1',['test:Demo.java'],'check'),
            ('0:scan1',['--something'],'analyze'),('0:scan1',[],'analyze'),('0:scan1',['test:Demo.java'],'shell')]:
            with self.assertRaises(ValueError):jobs.start_job(self.root,key,components,mode)
        with self.assertRaises(ValueError):jobs.get_job(self.root,'../../x')

    def test_orphan_and_redaction(self):
        j='a'*32; p=jobs.job_path(self.root,j);p.mkdir()
        jobs.save(p/'job.json',{'state':'ANALYZING','id':j})
        self.assertEqual(jobs.get_job(self.root,j)['state'],'INTERRUPTED')
        with patch.dict('os.environ',{'SONAR_TOKEN':'squ_test_secret'}):
            self.assertNotIn('squ_test_secret',jobs.redact('TOKEN=squ_test_secret'))

    def test_ui_csrf_and_post(self):
        r=self.client.get('/analysis');self.assertEqual(r.status_code,200)
        self.assertIn(b'Demo.java',r.data)
        self.assertEqual(self.client.post('/analysis/start',data={}).status_code,400)
        with self.client.session_transaction() as s: token=s['csrf']
        r=self.client.post('/analysis/start',data={'csrf':token,'collection':'0:scan1','components':'test:Demo.java','mode':'check'})
        self.assertEqual(r.status_code,303)
        j=r.location.rsplit('/',1)[-1];self.wait(j)
        self.assertEqual(self.client.get(r.location).status_code,200)

    def test_review_export_regression(self):
        folder=self.root/'runs'/'done';folder.mkdir()
        raw=b'public class Demo {}\n';(folder/'issue-0001').mkdir()
        (folder/'issue-0001'/'source.java.txt').write_bytes(raw)
        manifest={'state':'COMPLETED','analysis_id':'done','project':'test','result_count':1}
        row={'issue_id':'i','component':'test:Demo.java','line':1,'rule':'findsecbugs:PATH_TRAVERSAL_IN',
             'processing_status':'AI_PROPOSED','verdict':'UNKNOWN','ai_verdict':'LIKELY_FP',
             'combined_verdict':'UNKNOWN','decision_origin':'STATIC_GUARD_CONFLICT',
             'artifact_dir':'issue-0001','source_sha256':hashlib.sha256(raw).hexdigest()}
        jobs.save(folder/'manifest.json',manifest);jobs.save(folder/'ai_results.json',[row])
        original=(folder/'ai_results.json').read_bytes()
        self.client.get('/analysis')
        with self.client.session_transaction() as s:token=s['csrf']
        payload={'csrf':token,'record_key':ui.review_key(manifest,row),'revision':'0',
                 'reviewer':'Tester','notes':'Checked source','reviewed_verdict':'LIKELY_TP'}
        self.assertEqual(self.client.post('/runs/0/done/review/0',data=payload).status_code,303)
        self.assertEqual(self.client.post('/runs/0/done/review/0',data=payload).status_code,409)
        self.assertEqual(original,(folder/'ai_results.json').read_bytes())
        r=self.client.get('/runs/0/done/export.csv');self.assertEqual(r.status_code,200)
        self.assertIn(b'STATIC_GUARD_CONFLICT',r.data)
        # Rendering needs the existing run/statistics templates, not changed by this patch.
        if ui.app.jinja_env.loader.get_source(ui.app.jinja_env,'run.html'):
            self.assertEqual(self.client.get('/runs/0/done').status_code,200)
            self.assertEqual(self.client.get('/runs/0/done/statistics').status_code,200)

if __name__=='__main__':unittest.main()
