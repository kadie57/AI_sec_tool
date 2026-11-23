"""Apply the small update to the existing AI_sec_tool project, with backup."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile

OLD = {
    "master_pipeline.py": "dd0165e2145edc00fa76506a6cb08380d58b2fcf7e97eb957cd5edcda156660c",
    "master_pipeline_multi_v1.py": "c528a4c50f05f5d59eab3481c363992c49c95340c185cae067404fdd92f28b3b",
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_atomic(path, raw):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()


def install(root, package):
    expected = json.loads((package / "payload_sha256.json").read_text())
    if set(expected) != set(OLD) | {"recheck_sql_context.py"}:
        raise ValueError("Danh sách file cập nhật không hợp lệ.")
    changes = []
    for name, wanted in expected.items():
        raw = (package / "payload" / name).read_bytes()
        if digest(raw) != wanted:
            raise ValueError("Gói cập nhật bị thay đổi: " + name)
        compile(raw, name, "exec")
        path = root / name
        if path.is_symlink():
            raise ValueError("File đích là liên kết: " + name)
        previous = path.read_bytes() if path.exists() else None
        if previous is not None and digest(previous) == wanted:
            continue
        if name in OLD:
            if previous is None or digest(previous) != OLD[name]:
                raise ValueError(name + ": khác bản trong ZIP đã kiểm tra; chưa sửa file nào.")
        elif previous is not None:
            raise ValueError(name + " đã tồn tại với nội dung khác; chưa sửa file nào.")
        changes.append((path, previous, raw))
    if not changes:
        print("INSTALL_OK: bản cập nhật đã được cài; không ghi lại.")
        return
    backup = root / "backups" / ("sql_context_fix_v1_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    backup.mkdir(parents=True, exist_ok=False)
    for path, previous, _ in changes:
        if previous is not None:
            (backup / path.name).write_bytes(previous)
    record = {"changed": [p.name for p, _, _ in changes], "new_sha256": expected,
              "old_sha256": {p.name: digest(old) if old is not None else None for p, old, _ in changes}}
    (backup / "update.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    written = []
    try:
        for path, previous, raw in changes:
            write_atomic(path, raw)
            written.append((path, previous))
    except BaseException:
        for path, previous in reversed(written):
            if previous is None:
                path.unlink()
            else:
                write_atomic(path, previous)
        raise
    print("INSTALL_OK: đã cập nhật trực tiếp dự án hiện tại.")
    print("SAO LƯU:", backup)
    print("Giữ nguyên mã Java, dữ liệu đánh giá, prompt và mọi kết quả cũ.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        install(args.root.resolve(), Path(__file__).resolve().parent)
    except Exception as exc:
        raise SystemExit("[LỖI] " + str(exc))
