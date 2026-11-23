"""Update the existing Path module, with guarded backup and restore."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

OLD_HASH = "55d76693202213d5074cc331d3f9171395ac3abb6af0b562f60e1f50197ef556"
MAIN = "path_triage_v2.py"
NAMES = ("PathBranchEvidence.java", "path_branch_evidence_v1.py", MAIN)


def sha(data): return hashlib.sha256(data).hexdigest()


def write(path, raw, mode=0o644):
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent,prefix=".path-update-",delete=False) as stream:
            temporary=Path(stream.name);stream.write(raw);stream.flush();os.fsync(stream.fileno())
        temporary.chmod(mode);temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists(): temporary.unlink()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project',type=Path,default=Path.home()/'AI_sec_tool')
    modes=parser.add_mutually_exclusive_group(required=True)
    for name in ('check','apply','restore'): modes.add_argument('--'+name,action='store_true')
    args=parser.parse_args();root=args.project.expanduser().resolve();package=Path(__file__).resolve().parent
    expected=json.loads((package/'payload_hash.json').read_text())
    candidates={name:(package/'payload'/name).read_bytes() for name in NAMES}
    if any(sha(data)!=expected[name] for name,data in candidates.items()):
        raise ValueError('Gói cập nhật thay đổi; chưa cài.')
    for name,data in candidates.items():
        if name.endswith('.py'):compile(data,name,'exec')
    current={}
    for name in NAMES:
        target=root/name
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise ValueError('Đường dẫn đích không phải file thường: '+name)
        current[name]=target.read_bytes() if target.exists() else None
        allowed=(OLD_HASH,expected[name]) if name==MAIN else (None,expected[name])
        if (sha(current[name]) if current[name] is not None else None) not in allowed:
            raise ValueError('File khác bản đã đối chiếu; không ghi đè: '+name)
    backup=root/'backups/path_context_v7'/OLD_HASH/MAIN
    if not args.restore:
        sys.path.insert(0,str(package/'payload'))
        from path_branch_evidence_v1 import check_runtime
        check_runtime()
    if args.check:
        print('PATCH_CHECK_OK: v7-branch-evidence; JDK và phép tính kiểm tra đạt.')
        print('Chưa sửa code dự án, chưa gọi SonarQube/Joern/AI.')
        return 0
    backup.parent.mkdir(parents=True,exist_ok=True)
    with (backup.parent/'install.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        for name in NAMES:
            target=root/name
            if target.is_symlink() or (target.read_bytes() if target.exists() else None)!=current[name]:
                raise ValueError('File thay đổi trong lúc kiểm tra; chưa ghi đè: '+name)
        mode=stat.S_IMODE((root/MAIN).stat().st_mode)
        if args.restore:
            if sha(current[MAIN])!=OLD_HASH:
                if not backup.is_file() or sha(backup.read_bytes())!=OLD_HASH:
                    raise ValueError('Bản sao lưu v6 thiếu hoặc sai; chưa khôi phục.')
                write(root/MAIN,backup.read_bytes(),mode)
            for name in NAMES[:-1]:
                if current[name] is not None:(root/name).unlink()
            print('ĐÃ KHÔI PHỤC V6:',root/MAIN);return 0
        if sha(current[MAIN])==OLD_HASH:
            if backup.exists() and sha(backup.read_bytes())!=OLD_HASH:
                raise ValueError('Bản sao lưu thay đổi; chưa cài.')
            if not backup.exists():write(backup,current[MAIN],mode)
        for name in NAMES:
            if current[name]!=candidates[name]:write(root/name,candidates[name],mode if name==MAIN else 0o644)
        print('ĐÃ CẬP NHẬT V7:',root/MAIN)
        print('BẢN CŨ:',backup)
        print('Chưa chạy AI; chạy lại riêng hai mẫu Path theo README.')
        return 0


if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,KeyError,SyntaxError) as exc:
        print('LỖI:',exc,file=sys.stderr);sys.exit(1)
