"""Local Ubuntu job queue: fixed pipeline command, one UI job, durable records.

No shell, no arbitrary commands, no automatic retry. Worker survives browser/UI exit.
The inherited flock also stays held by a running pipeline if the worker dies.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from urllib.parse import urlsplit
from datetime import datetime, timezone

RULE_COST = {'findsecbugs:SQL_INJECTION_JDBC': 3, 'findbugs:SQL_INJECTION_JDBC': 3,
             'java:S3649': 3, 'findsecbugs:PATH_TRAVERSAL_IN': 2,
             'findsecbugs:COMMAND_INJECTION': 2}
ACTIVE = {'QUEUED', 'CHECKING', 'ANALYZING', 'SCANNING', 'DRAFTING'}
LABELS = {'DRAFTING': 'Đang tạo bản sửa đề xuất', 'DRAFT_READY': 'Đã có bản nháp — cần kiểm tra',
          'NEEDS_CONTEXT': 'Chưa đủ ngữ cảnh để đề xuất bản sửa',
          'QUEUED': 'Đang chờ bắt đầu', 'CHECKING': 'Đang kiểm tra cấu hình',
          'SCANNING': 'Đang quét và lấy cảnh báo SonarQube',
          'COLLECTED': 'Đã lấy cảnh báo SonarQube — chưa gọi AI',
          'ANALYZING': 'Đang phân tích', 'CHECK_OK': 'Kiểm tra đạt — chưa gọi AI',
          'COMPLETED': 'Đã hoàn tất tiến trình — mở kết quả để xem từng cảnh báo',
          'FAILED': 'Không hoàn tất — xem nhật ký', 'INTERRUPTED': 'Tiến trình đã dừng ngoài dự kiến'}

def now():
    return datetime.now(timezone.utc).isoformat()

def read(path):
    return json.loads(path.read_text(encoding='utf-8'))

def save(path, data):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    temp.replace(path)

def storage(root):
    p = root / '.review_jobs'
    p.mkdir(mode=0o700, exist_ok=True)
    if p.is_symlink():
        raise ValueError('Thư mục tác vụ không được là liên kết.')
    return p

def catalog(root):
    items = []
    for group, parent in enumerate((root / 'runs', root / 'eval_sql89_new_v1' / 'runs')):
        for path in sorted(parent.glob('*/manifest.json'), reverse=True):
            folder = path.parent
            if not re.fullmatch(r'[A-Za-z0-9_-]+', folder.name) or not folder.resolve().is_relative_to(parent.resolve()):
                continue
            try:
                manifest = read(path)
                ip = folder / 'issues.json'
                if not ip.resolve().is_relative_to(folder.resolve()):
                    continue
                bundle = read(ip)
                rows = bundle.get('issues') if isinstance(bundle, dict) else bundle
                if manifest.get('state') not in ('COLLECTED', 'COMPLETED') or not manifest.get('analysis_id') or not isinstance(rows, list):
                    continue
                components = {}
                for row in rows:
                    cost = RULE_COST.get(row.get('rule'))
                    name = row.get('component')
                    if cost and isinstance(name, str):
                        item = components.setdefault(name, {'name': name, 'count': 0, 'calls': 0})
                        item['count'] += 1; item['calls'] += cost
                if components:
                    items.append({'key': str(group) + ':' + folder.name, 'name': folder.name,
                                  'project': str(manifest.get('project', '')), 'folder': str(folder.resolve()),
                                  'components': list(components.values()),
                                  'calls': sum(v['calls'] for v in components.values())})
            except (OSError, ValueError, TypeError, AttributeError):
                continue
    return items

def job_path(root, job_id):
    if not re.fullmatch(r'[a-f0-9]{32}', job_id):
        raise ValueError('Mã tác vụ không hợp lệ.')
    path = storage(root) / job_id
    if path.is_symlink():
        raise ValueError('Đường dẫn tác vụ không hợp lệ.')
    return path

def active_id(root):
    with (storage(root) / 'worker.lock').open('a+') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return None
        except BlockingIOError:
            lock.seek(0)
            return lock.read().strip()

def get_job(root, job_id):
    folder = job_path(root, job_id)
    row = read(folder / 'job.json')
    if row['state'] in ACTIVE and active_id(root) != job_id:
        row['state'] = 'INTERRUPTED'
    row['label'] = LABELS.get(row['state'], row['state'])
    log = folder / 'output.log'
    if log.exists():
        with log.open('rb') as f:
            f.seek(max(0, log.stat().st_size - 18000))
            row['log'] = f.read().decode('utf-8', errors='replace')
    else:
        row['log'] = ''
    row['running'] = row['state'] in ACTIVE
    return row

def list_jobs(root):
    result = []
    for path in sorted(storage(root).glob('*/job.json'), key=lambda p: p.stat().st_mtime, reverse=True)[:20]:
        try:
            result.append(get_job(root, path.parent.name))
        except (OSError, ValueError, KeyError):
            continue
    return result

def start_job(root, collection_key, components, mode):
    if mode not in ('check', 'analyze'):
        raise ValueError('Chọn kiểm tra hoặc phân tích.')
    collection = next((c for c in catalog(root) if c['key'] == collection_key), None)
    if not collection:
        raise ValueError('Không tìm thấy lượt quét hợp lệ có cảnh báo được hỗ trợ.')
    selected = sorted(set(components))
    allowed = {c['name']: c for c in collection['components']}
    if not selected or any(c not in allowed for c in selected):
        raise ValueError('Chọn ít nhất một file trong danh sách.')
    script = root / 'master_pipeline_multi_v1.py'
    if not script.is_file():
        raise ValueError('Thiếu master_pipeline_multi_v1.py.')
    return launch(root, dict(mode=mode, collection=collection['folder'],
                  collection_name=collection['name'], project=collection['project'], components=selected,
                  max_calls=0 if mode == 'check' else sum(allowed[c]['calls'] for c in selected)))

def scan_config(root):
    url = os.getenv('SONAR_URL', 'http://127.0.0.1:9000').rstrip('/')
    parsed = urlsplit(url)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError('SONAR_URL phải là URL HTTP(S), không chứa mật khẩu, query hoặc fragment.')
    return {'url': url, 'project': os.getenv('SONAR_PROJECT_KEY', 'project_1'),
            'file_count': sum(1 for p in (root / 'Clean_Code').rglob('*.java') if p.is_file()),
            'has_token': bool(os.getenv('SONAR_TOKEN', '').strip())}

def start_scan(root, project, token):
    project = project.strip()
    if (not re.fullmatch(r'[A-Za-z0-9_.:-]{1,200}', project)
            or not re.search(r'[A-Za-z_.:-]', project)):
        raise ValueError('Project key chỉ gồm chữ, số, dấu _, -, ., : và không được chỉ có số.')
    token = token.strip() or os.getenv('SONAR_TOKEN', '').strip()
    if not token or len(token) > 4096 or any(c.isspace() or ord(c) < 32 for c in token):
        raise ValueError('Nhập SonarQube token hợp lệ hoặc đặt SONAR_TOKEN trước khi mở giao diện.')
    config = scan_config(root)
    if not config['file_count']:
        raise ValueError('Chưa có file Java trong Clean_Code.')
    for name in ('master_pipeline.py', 'master_pipeline_multi_v1.py', 'review_ui/collect_worker.py'):
        if not (root / name).is_file():
            raise ValueError('Thiếu file chương trình: ' + name)
    env = os.environ.copy()
    env.update(SONAR_TOKEN=token, SONAR_PROJECT_KEY=project, SONAR_URL=config['url'])
    # Credentials live in this process environment only, never the durable record.
    return launch(root, dict(mode='scan', collection=None, collection_name='Quét mới: Clean_Code',
                  project=project, components=[], max_calls=0, scan_url=config['url'],
                  source_file_count=config['file_count']), env=env)

def launch(root, record, env=None):
    lock = (storage(root) / 'worker.lock').open('a+')
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Đã có tác vụ UI đang chạy. Mở nhật ký và chờ hoàn tất.') from None
        if record.get('mode') == 'remediate':
            # Recheck completed requests under the same lock: two simultaneous
            # button submissions must not generate two identical successful drafts.
            import patch_core
            for previous in storage(root).glob('*/job.json'):
                if previous.is_symlink() or previous.parent.is_symlink():
                    continue
                try:
                    saved = read(previous)
                    if (saved.get('mode') == 'remediate' and saved.get('signature') == record.get('signature')
                            and patch_core.reusable(root, saved)):
                        return saved['id']
                except (OSError, ValueError, TypeError, KeyError):
                    continue
        job_id = uuid.uuid4().hex
        folder = job_path(root, job_id); folder.mkdir(mode=0o700)
        lock.seek(0); lock.truncate(); lock.write(job_id); lock.flush()
        record = dict(record, id=job_id, state='QUEUED', created_at=now(), result_name=None, returncode=None)
        save(folder / 'job.json', record)
        try:
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--worker',
                              str(root), job_id, str(lock.fileno())], cwd=root,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, env=env, pass_fds=(lock.fileno(),), start_new_session=True)
            threading.Thread(target=process.wait, daemon=True).start()
        except OSError:
            record.update(state='FAILED', finished_at=now(), error='Không khởi động được tiến trình nền.')
            save(folder / 'job.json', record)
            raise ValueError(record['error']) from None
        return job_id
    finally:
        # Do not LOCK_UN: child holds the same open file description.
        lock.close()

def redact(text):
    for key, value in os.environ.items():
        if value and any(s in key.upper() for s in ('TOKEN', 'PASSWORD', 'SECRET', 'API_KEY')):
            text = text.replace(value, '[REDACTED]')
    return re.sub(r'\b(?:squ|sqp|sqa)_[A-Za-z0-9]+', '[REDACTED]', text)

def worker(root, job_id, lock_fd):
    if read(job_path(root, job_id) / 'job.json').get('mode') == 'remediate':
        import patch_core
        return patch_core.worker(root, job_id, lock_fd)
    folder = job_path(root, job_id)
    row = read(folder / 'job.json')
    if row['mode'] == 'scan':
        args = [sys.executable, '-u', str(root / 'review_ui' / 'collect_worker.py')]
        phases = ['SCANNING']
    else:
        args = [sys.executable, '-u', str(root / 'master_pipeline_multi_v1.py'), '--from-run', row['collection']]
        for component in row['components']:
            args += ['--only-component', component]
        phases = ['CHECKING'] if row['mode'] == 'check' else ['CHECKING', 'ANALYZING']
    env = os.environ.copy(); env.setdefault('OLLAMA_TIMEOUT', '900'); env['PYTHONUNBUFFERED'] = '1'
    try:
        with (folder / 'output.log').open('a', encoding='utf-8') as log:
            for phase in phases:
                row.update(state=phase, updated_at=now()); save(folder / 'job.json', row)
                log.write('\n=== ' + LABELS[phase] + ' ===\n'); log.flush()
                timed_out = threading.Event()
                child = subprocess.Popen(args + (['--check'] if phase == 'CHECKING' else []), cwd=root,
                    env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding='utf-8', errors='replace', pass_fds=(lock_fd,), start_new_session=True)
                def expire():
                    timed_out.set()
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                timeout = {'CHECKING': 120, 'SCANNING': 1800, 'ANALYZING': 21600}[phase]
                timer = threading.Timer(timeout, expire)
                timer.daemon = True; timer.start()
                try:
                    for line in iter(lambda: child.stdout.readline(16384), ''):
                        clean = redact(line)
                        if log.tell() < 8_000_000:
                            log.write(clean); log.flush()
                        if clean.casefold().startswith('kết quả:'):
                            result = Path(clean.split(':', 1)[1].strip()).resolve()
                            if result.parent == (root / 'runs').resolve() and re.fullmatch(r'[A-Za-z0-9_-]+', result.name):
                                row['result_name'] = result.name; save(folder / 'job.json', row)
                    code = child.wait()
                finally:
                    timer.cancel(); child.stdout.close()
                row['returncode'] = code
                if code != 0 or timed_out.is_set():
                    row['error'] = ('Hết thời gian chờ (kiểm tra: 2 phút; quét: 30 phút; phân tích: 6 giờ). Xem nhật ký trước khi chạy lại.'
                                    if timed_out.is_set() else 'Pipeline dừng với mã ' + str(code) + '. Xem nhật ký bên dưới.')
                    row['state'] = 'FAILED'; break
            else:
                if row['mode'] == 'scan':
                    if not row['result_name']:
                        raise ValueError('Tiến trình quét không trả thư mục kết quả.')
                    manifest = read(root / 'runs' / row['result_name'] / 'manifest.json')
                    if manifest.get('state') != 'COLLECTED' or not manifest.get('analysis_id'):
                        raise ValueError('Lượt quét chưa có trạng thái COLLECTED và analysis_id hợp lệ.')
                    row['scan_summary'] = {k: manifest.get(k) for k in
                        ('issue_count', 'supported_issue_count', 'supported_by_route', 'analysis_id')}
                    row['state'] = 'COLLECTED'
                else:
                    row['state'] = 'CHECK_OK' if row['mode'] == 'check' else 'COMPLETED'
    except Exception as exc:
        row.update(state='FAILED', error=redact(str(exc)))
    finally:
        row['finished_at'] = now(); save(folder / 'job.json', row)
        os.close(lock_fd)

if __name__ == '__main__':
    if len(sys.argv) != 5 or sys.argv[1] != '--worker':
        raise SystemExit('Module nội bộ của giao diện.')
    worker(Path(sys.argv[2]).resolve(), sys.argv[3], int(sys.argv[4]))
