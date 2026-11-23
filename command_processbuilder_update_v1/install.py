"""Install into the existing project, with hash gates and backup; no services."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import py_compile
import shutil
import sys

OLD = {
 'command_triage_v2.py': '65e7808640c35c349c1cf338f254233808997465e0777d23841ff3daec82ade8',
 'master_pipeline_multi_v1.py': 'a892b15c5e002259e2bc70b87cf5f73d8fec44c7f9426587c3b2df71d0c9b382',
}
PREVIOUS_PAYLOAD = {'command_processbuilder_v1.py': 'bef7f10f9bc2d70fba6ad4895db30abdad1b5c1e81312035e3a96a8a3783aa47', 'command_triage_v2.py': 'a1920175f8a0108a0c6e76dbf562e4c019f864201ab77070a78598f25e5d2bb7', 'master_pipeline_multi_v1.py': 'de0acdd2b72d389ac1db8b6b8bd9bd58b37ec14684937f8891723ed3491c1d39'}
SOURCE_V2_SHA256 = 'db9d53052061939fdd2608cd8094fd3cbd7b5ed300db4d3c05ef8d8867cee0ba'
GUARD = 'ce7a629476266291c3e0e8fa69a6b14d299eba016cf71ac733885c59ef7edc48'

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--project',type=Path,default=Path.home()/'AI_sec_tool')
 parser.add_argument('--check',action='store_true')
 args=parser.parse_args()
 root=args.project.expanduser().resolve(); base=Path(__file__).resolve().parent
 manifest=json.loads((base/'package.json').read_text())
 payload=base/'payload'
 if not root.is_dir(): raise ValueError('Không có thư mục project: '+str(root))
 if not (root/'command_guard_replay_v1.py').is_file() or digest(root/'command_guard_replay_v1.py')!=GUARD:
  raise ValueError('command_guard_replay_v1.py khác bản đã kiểm tra; chưa thay file nào.')
 files=manifest['payload_sha256'];todo=[]
 # Validate every input before modifying a target.
 for name,new_hash in files.items():
  src=payload/name;target=root/name
  if src.parent!=payload or src.suffix!='.py' or digest(src)!=new_hash:
   raise ValueError('Gói cài không khớp: '+name)
  if target.is_symlink(): raise ValueError('Không ghi đè symlink: '+name)
  compile(src.read_text(encoding='utf-8'),str(src),'exec')
  if target.is_file() and digest(target)==new_hash: continue
  if name in OLD:
   if not target.is_file() or digest(target) not in {OLD[name], PREVIOUS_PAYLOAD.get(name)}:
    raise ValueError(name+' khác bản đã nhận. Chưa thay file nào; gửi file đang dùng để ghép đúng bản.')
  elif target.exists() and (not target.is_file() or digest(target) not in {PREVIOUS_PAYLOAD.get(name), SOURCE_V2_SHA256 if name=='command_processbuilder_v1.py' else None}):
   raise ValueError(name+' đã tồn tại và khác gói này. Chưa thay file nào.')
  todo.append(name)
 if args.check:
  print('INSTALL_CHECK_OK:',len(todo),'file cần cập nhật; không gọi dịch vụ, chưa ghi file.')
  return
 if not todo:
  print('Đã cài đúng bản command78-processbuilder-context-v3-bounded-repair; không cần cài lại.')
  return
 backup=root/'backups'/('command_processbuilder_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
 backup.mkdir(parents=True)
 old_present=[];installed=[]
 try:
  for name in todo:
   if (root/name).exists():
    shutil.copy2(root/name,backup/name);old_present.append(name)
  (backup/'install_record.json').write_text(json.dumps({'changed':todo,'previously_present':old_present,'package':manifest},indent=2))
  for name in todo:
   tmp=root/(name+'.install.tmp')
   tmp.write_bytes((payload/name).read_bytes());tmp.replace(root/name);installed.append(name)
 except BaseException:
  for name in installed:
   if name in old_present: shutil.copy2(backup/name,root/name)
   else: (root/name).unlink(missing_ok=True)
  raise
 print('INSTALLED: command78-processbuilder-context-v3-bounded-repair')
 print('BACKUP:',backup)
 print('Đã cập nhật backend hiện có; SQL/Path, mã Java và kết quả cũ được giữ nguyên.')
 print('Dùng resume_command_processbuilder.py --from-run <lượt gần nhất> để chạy tiếp cảnh báo lỗi.')

if __name__=='__main__':
 try: main()
 except (OSError,ValueError,SyntaxError,KeyError) as exc:
  print('[LỖI]',exc,file=sys.stderr);sys.exit(1)
