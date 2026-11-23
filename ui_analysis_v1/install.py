"""Run from ~/AI_sec_tool. Verify exact inputs, back up, and install UI only."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
from pathlib import Path
import shutil

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check',action='store_true')
args=parser.parse_args()
root=Path.cwd().resolve(); package=Path(__file__).resolve().parent
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
spec=json.loads((package/'install_manifest.json').read_text())
if not (root/'master_pipeline_multi_v1.py').is_file():
    raise SystemExit('Chạy lệnh từ thư mục ~/AI_sec_tool.')
for name,meta in spec.items():
    source=package/name; target=root/name
    if not source.resolve().is_relative_to(package) or not target.resolve().is_relative_to(root):
        raise SystemExit('Đường dẫn không hợp lệ.')
    if sha(source)!=meta['after']:
        raise SystemExit('Gói cập nhật đã thay đổi: '+name)
    if meta['before'] is None:
        if target.exists(): raise SystemExit('Đã tồn tại '+name+'. Chưa ghi đè; gửi thông báo này để đối chiếu.')
    elif not target.is_file() or sha(target)!=meta['before']:
        raise SystemExit('File khác bản ZIP đã gửi: '+name+'. Chưa sửa file.')
    if source.suffix=='.py': compile(source.read_text(encoding='utf-8'),name,'exec')
lockpath=root/'.review_jobs'/'worker.lock'
lock=None
if lockpath.exists():
    lock=lockpath.open('a+')
    try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: raise SystemExit('Tác vụ UI đang chạy; chờ xong trước khi cập nhật.')
if args.check:
    print('INSTALL_CHECK_OK: file gốc khớp; chưa cài, chưa gọi AI.')
else:
    backup=root/'backups'/('ui_analysis_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir(parents=True)
    for name,meta in spec.items():
        if meta['before'] is not None:
            (backup/name).parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(root/name,backup/name)
    (backup/'installed_files.json').write_text(json.dumps(spec,indent=2))
    changed=[]
    try:
        for name in spec:
            changed.append(name)
            (root/name).parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(package/name,root/name)
    except Exception:
        for name in reversed(changed):
            if spec[name]['before'] is not None: shutil.copy2(backup/name,root/name)
            else: (root/name).unlink(missing_ok=True)
        raise
    print('INSTALL_OK. Sao lưu tại:',backup)
    print('Chỉ cập nhật UI. Backend, kết quả và thẩm định cũ được giữ nguyên.')
if lock is not None: lock.close()
