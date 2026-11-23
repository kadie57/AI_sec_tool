from pathlib import Path
import hashlib, shutil, sys, unittest
from datetime import datetime, timezone
package=Path(__file__).resolve().parent
root=Path.cwd()
expected={'path_triage_v2.py': '138a9c2396cbd7b8d4a48da1d4fb823e30241b84118cad7683fa6a6114e671b5', 'path_guard_check_v1.py': '44046aa661fa7ca6fe03e87ae86a260b6f9f616a6f1c889f576864952949c43f'}
for name,digest in expected.items():
    f=root/name
    if not f.exists() or hashlib.sha256(f.read_bytes()).hexdigest()!=digest:
        raise SystemExit('File khác bản đã đối chiếu: '+name+'. Chưa sửa file.')
new=root/'path_numeric_check_v1.py'
if new.exists(): raise SystemExit('Đã tồn tại path_numeric_check_v1.py; chưa ghi đè.')
for name in ('path_numeric_check_v1.py','path_triage_v2.py'):
    compile((package/name).read_text(),name,'exec')
suite=unittest.defaultTestLoader.discover(str(package),pattern='test_*.py')
if not unittest.TextTestRunner().run(suite).wasSuccessful(): raise SystemExit('Tests failed. Nothing installed.')
backup=root/'backups'/('path_numeric_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
backup.mkdir(parents=True)
shutil.copy2(root/'path_triage_v2.py',backup/'path_triage_v2.py')
shutil.copy2(package/new.name,new)
shutil.copy2(package/'path_triage_v2.py',root/'path_triage_v2.py')
print('INSTALL_OK; backup:',backup)
print('Chưa gọi AI, chưa sửa kết quả cũ.')
