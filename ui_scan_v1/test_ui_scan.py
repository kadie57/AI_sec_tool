"""Scan jobs, credential persistence, failure states, and real collector wiring.

Offline only: no SonarQube, scanner, Docker or model calls. Tests substitute
external operations while executing the existing master_pipeline collector.
"""
import importlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import test_ui_jobs as base

ui, jobs = base.ui, base.jobs
import collect_worker

FAKE_SCAN = '''import os, pathlib, json
p=pathlib.Path.cwd()/'runs'/'fresh-scan'
p.mkdir(exist_ok=True)
(p/'manifest.json').write_text(json.dumps({'state':'COLLECTED','analysis_id':'new-analysis',
'project':os.environ['SONAR_PROJECT_KEY'],'issue_count':1,'supported_issue_count':1,
'supported_by_route':{'sql':0,'path':1,'command':0}}))
(p/'issues.json').write_text(json.dumps([{'key':'p','rule':'findsecbugs:PATH_TRAVERSAL_IN',
'component':os.environ['SONAR_PROJECT_KEY']+':Clean_Code/Demo.java'}]))
print('TOKEN='+os.environ['SONAR_TOKEN'],flush=True)
print('Kết quả:',p,flush=True)
'''

class ScanTests(unittest.TestCase):
    tearDown = base.JobsTests.tearDown
    wait = base.JobsTests.wait

    def setUp(self):
        base.JobsTests.setUp(self)
        (self.root/'Clean_Code').mkdir()
        (self.root/'Clean_Code'/'Demo.java').write_text('class Demo {}\n')
        (self.root/'master_pipeline.py').write_text('# collector\n')
        (self.root/'review_ui').mkdir()
        self.collector = self.root/'review_ui'/'collect_worker.py'
        self.collector.write_text(FAKE_SCAN)

    def test_scan_to_selection_and_token_not_persisted(self):
        j=jobs.start_scan(self.root,'project_1','plain-secret-for-one-scan')
        row=self.wait(j)
        self.assertEqual(row['state'],'COLLECTED')
        self.assertEqual(row['max_calls'],0)
        self.assertEqual(row['result_name'],'fresh-scan')
        self.assertEqual(row['scan_summary']['supported_by_route']['path'],1)
        for p in (self.root/'.review_jobs').rglob('*'):
            if p.is_file(): self.assertNotIn(b'plain-secret-for-one-scan',p.read_bytes())
        response=self.client.get('/analysis/jobs/'+j)
        self.assertEqual(response.status_code,200)
        self.assertIn(b'/analysis?collection=0:fresh-scan',response.data)
        response=self.client.get('/analysis?collection=0:fresh-scan')
        self.assertIn(b'Clean_Code/Demo.java',response.data)
        self.assertNotIn('plain-secret-for-one-scan',os.getenv('SONAR_TOKEN',''))

    def test_scan_errors_and_shared_lock(self):
        self.collector.write_text('import time\ntime.sleep(.4)\nraise SystemExit(1)\n')
        j=jobs.start_scan(self.root,'project_1','token')
        with self.assertRaises(ValueError):
            jobs.start_job(self.root,'0:scan1',['test:Demo.java'],'check')
        with self.assertRaises(ValueError): jobs.start_scan(self.root,'project_1','token')
        row=self.wait(j);self.assertEqual(row['state'],'FAILED')
        self.assertEqual(row['returncode'],1)
        self.assertEqual(self.client.get('/analysis/jobs/'+j).status_code,200)
        self.collector.write_text(FAKE_SCAN.replace("'state':'COLLECTED'","'state':'FAILED'"))
        self.assertEqual(self.wait(jobs.start_scan(self.root,'project_1','token'))['state'],'FAILED')

    def test_scan_validation_and_ui_csrf(self):
        with patch.dict(os.environ,{'SONAR_TOKEN':''}):
            for project,token in [('x;echo hi','token'),('123','token'),('p',''),('p','bad\ntoken')]:
                with self.assertRaises(ValueError): jobs.start_scan(self.root,project,token)
        with patch.dict(os.environ,{'SONAR_URL':'http://user:pass@localhost:9000'}):
            with self.assertRaises(ValueError): jobs.start_scan(self.root,'p','token')
        with patch.dict(os.environ,{'SONAR_TOKEN':'server-secret'}):
            response=self.client.get('/scan');self.assertEqual(response.status_code,200)
            self.assertNotIn(b'server-secret',response.data)
            self.assertEqual(self.client.post('/scan/start',data={}).status_code,400)
            with self.client.session_transaction() as session: csrf=session['csrf']
            response=self.client.post('/scan/start',data={'csrf':csrf,'project':'project_1','sonar_token':''})
            self.assertEqual(response.status_code,303)
            self.assertEqual(self.wait(response.location.rsplit('/',1)[-1])['state'],'COLLECTED')

    def test_zero_supported_scan_has_no_analysis_link(self):
        self.collector.write_text(FAKE_SCAN.replace("'supported_issue_count':1","'supported_issue_count':0")
                                  .replace("'path':1","'path':0"))
        j=jobs.start_scan(self.root,'project_1','token');self.wait(j)
        response=self.client.get('/analysis/jobs/'+j)
        self.assertNotIn(b'/analysis?collection=',response.data)
        self.assertIn('Chưa có cảnh báo thuộc phạm vi hỗ trợ'.encode(),response.data)

    def collector_fixture(self, mutate=False, fail_compile=False):
        code_root=Path(__file__).resolve().parent.parent
        if not (code_root/'master_pipeline.py').is_file():
            code_root=Path(__file__).resolve().parents[2]/'current_review_20261028'/'AI_sec_tool'
        sys.path.insert(0,str(code_root))
        pipeline=importlib.import_module('master_pipeline')
        router=importlib.import_module('master_pipeline_multi_v1')
        rules=['findsecbugs:SQL_INJECTION_JDBC','findsecbugs:PATH_TRAVERSAL_IN',
               'findsecbugs:COMMAND_INJECTION','java:S106']
        def command(args,log,timeout,cwd):
            Path(log).write_text('fake tool log')
            if args[0]=='javac':
                if fail_compile: raise RuntimeError('Compilation failed (fake)')
                return ''
            task=next(a.split('=',1)[1] for a in args if a.startswith('-Dsonar.scanner.metadataFilePath='))
            Path(task).write_text('ceTaskId=task1\n')
            if mutate: (self.root/'Clean_Code'/'Demo.java').write_text('class Changed {}\n')
            return ''
        def fetched(_sonar,project,run):
            return [{'key':str(i),'rule':r,'component':project+':Clean_Code/Demo.java','line':1}
                    for i,r in enumerate(rules)]
        previous=Path.cwd(); os.chdir(self.root)
        try:
            with patch.dict(os.environ,{'SONAR_TOKEN':'private-token','SONAR_PROJECT_KEY':'test'}), \
                 patch.object(pipeline,'run_command',side_effect=command), \
                 patch.object(pipeline.SonarClient,'wait_for_analysis',return_value={'status':'SUCCESS','analysisId':'a1'}), \
                 patch.object(pipeline.SonarClient,'fetch_issues',new=fetched), \
                 patch.object(pipeline.SonarClient,'get',return_value={'rule':{}}), \
                 patch.object(pipeline,'analyze_issue',side_effect=AssertionError('Must not run AI')):
                code=collect_worker.collect(self.root,pipeline,router)
        finally: os.chdir(previous)
        path=next(p for p in (self.root/'runs').glob('*/manifest.json') if p.parent.name!='scan1')
        return code,jobs.read(path),path.parent

    def test_real_collector_maps_three_routes_without_ai(self):
        code,manifest,folder=self.collector_fixture()
        self.assertEqual(code,0);self.assertEqual(manifest['state'],'COLLECTED')
        self.assertEqual(manifest['supported_by_route'],dict(sql=1,path=1,command=1))
        self.assertEqual(manifest['supported_issue_count'],3)
        self.assertEqual(manifest['result_count'],0)
        self.assertEqual(len(manifest['source_hashes']),1)
        self.assertFalse((folder/'ai_results.json').exists())
        inventory=jobs.read(folder/'rule_inventory.json')
        self.assertEqual(sum(r['supported'] for r in inventory),3)
        self.assertTrue(manifest['collection_adapter']['collector_sha256'])

    def test_source_changes_do_not_become_successful_collection(self):
        code,manifest,_=self.collector_fixture(mutate=True)
        self.assertEqual(code,1);self.assertEqual(manifest['state'],'FAILED')
        self.assertIn('Mã nguồn đã thay đổi',manifest['error'])

    def test_compile_failure_does_not_produce_ai_results(self):
        code,manifest,folder=self.collector_fixture(fail_compile=True)
        self.assertEqual(code,1);self.assertEqual(manifest['state'],'FAILED')
        self.assertFalse((folder/'issues.json').exists())

if __name__=='__main__': unittest.main()
