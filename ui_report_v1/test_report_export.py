"""Offline tests for report export. Uses synthetic data, never invokes AI/scanners."""
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PACKAGE = Path(__file__).resolve().parent
EXISTING = PACKAGE.parent / 'review_ui'
if not (EXISTING / 'job_runner.py').exists():
    EXISTING = PACKAGE.parents[1] / 'ui_scan_build/ui_scan_v1/review_ui'
sys.path[:0] = [str(PACKAGE / 'review_ui'), str(EXISTING)]
import app as ui
from jinja2 import ChoiceLoader, FileSystemLoader

class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.folder = self.root/'runs'/'demo'
        self.folder.mkdir(parents=True)
        self.before_root,self.before_runs = ui.ROOT,ui.RUN_ROOTS
        ui.ROOT,self.loader = self.root,ui.app.jinja_loader
        ui.RUN_ROOTS = (('Test',self.root/'runs'),)
        templates = [str(PACKAGE/'review_ui/templates'),str(EXISTING/'templates')]
        original = PACKAGE.parents[1]/'current_review_20261028/AI_sec_tool/review_ui/templates'
        if original.exists(): templates.append(str(original))
        ui.app.jinja_loader=FileSystemLoader(templates)
        ui.app.config.update(TESTING=True)
        self.client=ui.app.test_client()
        self.manifest={'state':'COMPLETED','analysis_id':'demo-analysis','project':'Bộ kiểm tra xuất báo cáo',
            'started_at':'2026-11-03T00:00:00+00:00','finished_at':'2026-11-03T00:18:15+00:00','result_count':3}
        raw='public class Demo {\n    String value = input;\n    use(value);\n}\n'.encode()
        self.rows=[];self.reviews={'version':1,'history':[]}
        for idx,(rule,ai,system,name) in enumerate([
            ('findsecbugs:SQL_INJECTION_JDBC','LIKELY_FP','LIKELY_FP','SqlDemo.java'),
            ('findsecbugs:PATH_TRAVERSAL_IN','LIKELY_TP','LIKELY_TP','PathDemo.java'),
            ('findsecbugs:COMMAND_INJECTION','UNKNOWN','LIKELY_FP','CommandDemo.java')],1):
            artifact=f'issue-{idx:04d}';(self.folder/artifact).mkdir()
            (self.folder/artifact/'source.java.txt').write_bytes(raw)
            row=dict(issue_id=str(idx),component='demo:'+name,rule=rule,line=3,artifact_dir=artifact,
                source_sha256=hashlib.sha256(raw).hexdigest(),processing_status='AI_PROPOSED',
                verdict=system,ai_verdict=ai,combined_verdict=system,
                decision_origin='STATIC_GUARD' if idx==3 else 'AI_PIPELINE',
                explanation='Giải thích hệ thống: đối chiếu đường đi của dữ liệu và bước bảo vệ.',
                ai_explanation='Nhận định AI đã lưu; cần đối chiếu bằng chứng trong mã nguồn.',
                evidence_lines=[2,3],ai_evidence_lines=[2,3],missing_context=[],ai_missing_context=[])
            self.rows.append(row)
            self.reviews['history'].append(dict(record_key=ui.review_key(self.manifest,row),revision=1,
                reviewed_verdict=system,reviewer='Khanh',notes='Đã đối chiếu nguồn, bước bảo vệ và dòng thực thi.',
                saved_at='2026-11-03T01:00:00+00:00'))
        self.write()

    def write(self):
        for name,value in [('manifest.json',self.manifest),('ai_results.json',self.rows),('reviews_ui.json',self.reviews)]:
            (self.folder/name).write_text(json.dumps(value,ensure_ascii=False),encoding='utf-8')

    def tearDown(self):
        ui.ROOT,ui.RUN_ROOTS,self.client=self.before_root,self.before_runs,None
        ui.app.jinja_loader=self.loader;self.tmp.cleanup()

    def test_preview_download_and_no_side_effects(self):
        before={p:p.read_bytes() for p in self.folder.rglob('*') if p.is_file()}
        with patch('subprocess.Popen',side_effect=AssertionError('No subprocess allowed')):
            preview=self.client.get('/runs/0/demo/report')
            html=self.client.get('/runs/0/demo/report.html?status=SKIPPED')
            pdf=self.client.get('/runs/0/demo/report.pdf')
        for response in (preview,html,pdf):self.assertEqual(response.status_code,200)
        self.assertIn('Tải PDF'.encode(),preview.data)
        self.assertNotIn(b'<nav',html.data)
        self.assertIn(b'attachment',html.headers['Content-Disposition'].encode())
        self.assertEqual(pdf.mimetype,'application/pdf');self.assertTrue(pdf.data.startswith(b'%PDF-'))
        self.assertIn('0 giờ 18 phút 15 giây'.encode(),html.data)
        for p,raw in before.items():self.assertEqual(raw,p.read_bytes())
        self.assertIn(b'CommandDemo.java',html.data)
        self.assertIn(b'UNKNOWN',html.data)
        self.assertIn('Kiểm tra bằng luật'.encode(),html.data)

    def test_xss_escaping_html_and_pdf(self):
        self.rows[0]['explanation']='<script>alert(1)</script><img src="https://invalid.test/a">'
        self.write()
        response=self.client.get('/runs/0/demo/report.html')
        self.assertNotIn(b'<script>',response.data)
        self.assertIn(b'&lt;script&gt;',response.data)
        self.assertIn("default-src 'none'",response.headers['Content-Security-Policy'])
        self.assertEqual(self.client.get('/runs/0/demo/report.pdf').status_code,200)

    def test_source_mismatch_excludes_review_and_source(self):
        (self.folder/'issue-0001/source.java.txt').write_text('UNVERIFIED_SOURCE')
        response=self.client.get('/runs/0/demo/report.html')
        text=response.data.decode()
        self.assertIn('Hash mã nguồn không khớp',text)
        self.assertNotIn('UNVERIFIED_SOURCE',text)
        self.assertIn('Có bản thẩm định đã lưu trước đây',text)
        entries=ui.build_entries(self.folder,self.manifest,self.rows,self.reviews)
        self.assertEqual(sum(e['review_state']=='REVIEWED' for e in entries),2)

    def test_bad_missing_data_and_traversal(self):
        self.assertEqual(self.client.get('/runs/9/demo/report').status_code,404)
        self.assertEqual(self.client.get('/runs/0/demo/report.exe').status_code,404)
        self.assertEqual(self.client.get('/runs/0/../report').status_code,404)
        (self.folder/'reviews_ui.json').write_text('{broken')
        self.assertEqual(self.client.get('/runs/0/demo/report').status_code,409)
        (self.folder/'ai_results.json').unlink()
        self.assertEqual(self.client.get('/runs/0/demo/report').status_code,409)

    def test_partial_run_and_skipped_not_ai_unknown(self):
        self.manifest['state']='IN_PROGRESS'
        self.rows.append(dict(issue_id='skip',component='demo:Other.java',rule='java:S106',
                             processing_status='SKIPPED',verdict='UNKNOWN',ai_verdict=None))
        self.write()
        response=self.client.get('/runs/0/demo/report.html')
        self.assertEqual(response.status_code,200)
        self.assertIn('Lượt chưa hoàn tất'.encode(),response.data)
        report=ui.report_export.prepare(ui,self.folder,'demo',self.manifest,self.rows,self.reviews,{})
        self.assertEqual(report['stats']['total'],4)
        self.assertEqual(report['stats']['proposed'],3)
        self.assertEqual(report['totals']['ai']['UNKNOWN'],1)
        self.assertEqual(sum(report['totals']['human'].values()),0)

    def test_existing_review_csv_and_views(self):
        for route in ('/runs/0/demo','/runs/0/demo/statistics','/analysis','/scan'):
            self.assertEqual(self.client.get(route).status_code,200,route)
        response=self.client.get('/runs/0/demo/export.csv')
        self.assertEqual(response.status_code,200);self.assertIn(b'Khanh',response.data)
        with self.client.session_transaction() as s: csrf=s['csrf']
        raw=(self.folder/'ai_results.json').read_bytes()
        payload={'csrf':csrf,'record_key':ui.review_key(self.manifest,self.rows[0]),'revision':'1',
                 'reviewer':'Khanh','notes':'Cập nhật ghi chú sau khi kiểm tra lại.','reviewed_verdict':'UNKNOWN'}
        self.assertEqual(self.client.post('/runs/0/demo/review/0',data=payload).status_code,303)
        self.assertEqual((self.folder/'ai_results.json').read_bytes(),raw)
        self.assertIn('Cập nhật ghi chú'.encode(),self.client.get('/runs/0/demo/report.html').data)

if __name__=='__main__': unittest.main()
