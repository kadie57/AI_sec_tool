"""Install a verified, reversible update into the existing AI_sec_tool project."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
from datetime import datetime, timezone


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, raw, mode=0o644):
    tmp = path.with_name(path.name + ".sql-source-install.tmp")
    try:
        with tmp.open("xb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        tmp.chmod(mode)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.project.resolve()
    package = Path(__file__).resolve().parent
    manifest = json.loads((package / "install_manifest.json").read_text(encoding="utf-8"))
    pending = []
    # Preflight every dependency and payload before making any project changes.
    for name, expected in manifest["unchanged_dependencies"].items():
        path = root / name
        if Path(name).name != name or not path.is_file() or sha(path.read_bytes()) != expected:
            raise ValueError("Dependency khác bản đã đối chiếu: " + name)
    for name, entry in manifest["files"].items():
        if Path(name).name != name:
            raise ValueError("Tên payload không hợp lệ.")
        raw = (package / "payload" / name).read_bytes()
        if sha(raw) != entry["after"]:
            raise ValueError("Gói tải về không khớp hash: " + name)
        ast.parse(raw, filename=name)
        dest = root / name
        if dest.is_symlink():
            raise ValueError("Không ghi đè symlink: " + name)
        before = dest.read_bytes() if dest.exists() else None
        digest = sha(before) if before is not None else None
        if digest == entry["after"]:
            continue
        if digest != entry["before"]:
            raise ValueError("File đã thay đổi hoặc gói trước chưa cài đúng: " + name)
        pending.append((dest, before, raw, dest.stat().st_mode & 0o777 if dest.exists() else 0o644))
    if args.check:
        print(f"INSTALL_CHECK_OK: {len(pending)} file sẽ cập nhật; chưa ghi vào dự án.")
        return 0
    if not pending:
        print("INSTALL_OK: bản này đã được cài; không ghi đè lần nữa.")
        return 0
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = root / "backups" / ("sql_source_fix_v1-" + stamp)
    backup.mkdir(parents=True, exist_ok=False)
    for dest, before, _, _ in pending:
        if before is not None:
            (backup / dest.name).write_bytes(before)
    (backup / "install_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    applied = []
    try:
        for dest, before, raw, mode in pending:
            write(dest, raw, mode)
            applied.append((dest, before, mode))
        if any(sha(dest.read_bytes()) != sha(raw) for dest, _, raw, _ in pending):
            raise ValueError("Hash sau cài không khớp.")
    except BaseException:
        for dest, before, mode in reversed(applied):
            if before is None:
                dest.unlink()
            else:
                write(dest, before, mode)
        raise
    print(f"INSTALL_OK: cập nhật {len(pending)} file trong dự án hiện tại.")
    print("BẢN SAO LƯU:", backup)
    print("Tiếp theo: python3 recheck_sql_source.py --check")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("[LỖI] " + str(exc), file=sys.stderr)
        sys.exit(1)
