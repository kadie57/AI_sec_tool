"""Install only after exact original-file verification; keep a timestamped backup."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import shutil
import unittest
import sys
package=Path(__file__).resolve().parent
root=Path.cwd()
expected='05a242cf6e77226c426b9c5090d80fc1b4d28ab6de07607d86696f9f0ed19eeb'
p=root/'path_triage_v2.py'
if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:
    raise SystemExit('Backend khác bản đã đối chiếu hoặc đã cài. Chưa sửa file.')
for name in ('path_triage_v2.py','path_guard_check_v1.py'):
    compile((package/name).read_text(),name,'exec')
new=root/'path_guard_check_v1.py'
if new.exists() and new.read_bytes()!=(package/new.name).read_bytes():
    raise SystemExit('Đã có bộ kiểm tra khác; chưa ghi đè.')
suite=unittest.defaultTestLoader.discover(str(package),pattern='test_path_guard_check.py')
if not unittest.TextTestRunner().run(suite).wasSuccessful():
    raise SystemExit('Tests failed; nothing installed.')
stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
backup=root/'backups'/('path_guard_'+stamp)
backup.mkdir(parents=True)
shutil.copy2(p,backup/p.name)
if new.exists(): shutil.copy2(new,backup/new.name)
shutil.copy2(package/new.name,new)
shutil.copy2(package/p.name,p)
print('INSTALL_OK. Bản sao:',backup)
print('Chưa gọi AI; chưa sửa kết quả đã lưu.')
