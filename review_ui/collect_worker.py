"""Collect through the existing scanner; expose the multi-router's rule inventory.

This process never imports analyzer configuration or calls AI. Root backend files
are unchanged. Only in-process mapping and manifest writing are adapted.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
VERSION = 'ui-collection-multi-v1'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def source_hashes(root):
    hashes = {}
    for path in sorted((root / 'Clean_Code').rglob('*.java')):
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('File Java trỏ ra ngoài thư mục dự án.')
        hashes[str(path.relative_to(root))] = sha(path)
    return hashes

def collect(root, pipeline, router):
    """Dependencies are explicit so offline tests can substitute service calls."""
    original_save, original_map = pipeline.save_json, pipeline.get_cwe_info
    old_version, old_mapping = pipeline.PIPELINE_VERSION, pipeline.MAPPING_VERSION
    old_argv = sys.argv[:]
    manifest_path = None
    captured = {}
    initial_hashes = source_hashes(root)
    provenance = {'version': VERSION, 'wrapper_sha256': sha(Path(__file__)),
                  'router_sha256': sha(Path(router.__file__)),
                  'collector_sha256': sha(Path(pipeline.__file__)),
                  'rules': {k: list(v) for k, v in router.RULES.items()}}

    def mapping(rule):
        route = router.RULES.get(rule)
        if route:
            return {'cwe_id': route[1], 'name': {'sql': 'SQL Injection in JDBC',
                    'path': 'Path Traversal (file read)', 'command': 'Command Injection'}[route[0]],
                    'supported': True, 'mapping_source': 'master_pipeline_multi_v1.RULES', 'reason': ''}
        return {**original_map(rule), 'supported': False}

    def save_manifest(path, value):
        nonlocal manifest_path, captured
        path = Path(path)
        if path.name == 'manifest.json' and path.parent.parent.resolve() == (root / 'runs').resolve():
            first_save = manifest_path is None
            manifest_path = path
            value = dict(value, collection_adapter=provenance)
            value['limitations'] = ['Collection only; no AI verdicts.',
                'Java in Clean_Code; configured SonarQube quality profile controls detected rules.',
                'No Security Hotspots API.', 'Do not scan the same project concurrently outside this UI.']
            if value.get('state') == 'COLLECTED':
                try:
                    current = source_hashes(root)
                    if not value.get('analysis_id'):
                        raise ValueError('SonarQube không trả analysis_id hợp lệ.')
                    if not initial_hashes or current != initial_hashes or current != value.get('source_hashes'):
                        raise ValueError('Mã nguồn đã thay đổi trong khi quét. Quét lại khi đã lưu xong các file.')
                    bundle = json.loads((path.parent / 'issues.json').read_text(encoding='utf-8'))
                    issues = bundle['issues'] if isinstance(bundle, dict) else bundle
                    counts = dict(sql=0, path=0, command=0)
                    for issue in issues:
                        route = router.RULES.get(issue.get('rule'))
                        if route:
                            counts[route[0]] += 1
                    value.update(supported_by_route=counts, supported_issue_count=sum(counts.values()))
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    value.update(state='FAILED', error=pipeline.redact(str(exc)))
            captured = value
            original_save(path, value)
            if first_save:
                print('KẾT QUẢ:', path.parent, flush=True)
        else:
            original_save(path, value)

    try:
        pipeline.get_cwe_info = mapping
        pipeline.save_json = save_manifest
        pipeline.PIPELINE_VERSION += '+' + VERSION
        pipeline.MAPPING_VERSION = VERSION
        sys.argv = [str(pipeline.__file__), '--collect-only']
        code = pipeline.main()
        if code or captured.get('state') != 'COLLECTED':
            print('[LỖI]', captured.get('error', 'Thu thập cảnh báo chưa hoàn tất.'), flush=True)
            if manifest_path:
                for name in ('javac.log', 'scanner.log'):
                    log = manifest_path.parent / name
                    if log.is_file():
                        with log.open('rb') as stream:
                            stream.seek(max(0, log.stat().st_size - 6000))
                            tail = stream.read().decode('utf-8', errors='replace')
                        print('\n--- ' + name + ' (phần cuối) ---\n' + pipeline.redact(tail), flush=True)
            return 1
        print('THU THẬP XONG:', captured['issue_count'], 'cảnh báo;',
              captured['supported_issue_count'], 'thuộc phạm vi AI.', flush=True)
        print('Theo nhánh:', json.dumps(captured['supported_by_route']), flush=True)
        print('Chưa gọi AI. Chọn file trên giao diện để kiểm chứng cảnh báo.', flush=True)
        return 0
    finally:
        pipeline.save_json, pipeline.get_cwe_info = original_save, original_map
        pipeline.PIPELINE_VERSION, pipeline.MAPPING_VERSION = old_version, old_mapping
        sys.argv = old_argv

def main():
    os.chdir(ROOT)
    from job_runner import scan_config, redact
    try:
        scan_config(ROOT)
        if not os.getenv('SONAR_TOKEN', '').strip():
            raise ValueError('Thiếu SonarQube token.')
        if not shutil.which('javac'):
            raise ValueError('Không tìm thấy javac. Cần Java JDK để biên dịch các mẫu.')
        scanner = os.getenv('SONAR_SCANNER_PATH',
            '/home/khanh/Downloads/sonar-scanner-8.0.1.6346-linux-x64/bin/sonar-scanner')
        if not shutil.which(scanner):
            raise ValueError('Không tìm thấy sonar-scanner. Đặt SONAR_SCANNER_PATH tới bản đã cài trước khi mở UI.')
        import master_pipeline as pipeline
        import master_pipeline_multi_v1 as router
        return collect(ROOT, pipeline, router)
    except Exception as exc:
        print('[LỖI]', redact(str(exc)), flush=True)
        return 1

if __name__ == '__main__':
    sys.exit(main())
