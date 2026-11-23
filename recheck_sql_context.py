"""Recheck SQL size-gate failures after a documented backend change.

Run in the existing AI_sec_tool project. This is a post-evaluation repair run,
not another untouched holdout. Reference labels are never read by this script.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import zipfile

VERSION = "sql-context-recheck-v1"
DEFAULT_RUN = "runs/multi-owasp-holdout-20261115T151839Z-b04660-f56d1218dcb6"
# Filled when the update package is built; checked before any service calls.
EXPECTED_PATCHES = {'master_pipeline.py': '4e07778cafa6214049f93ad06638d8bb2d23a06f48a3f8bc3e4b68d110b45215', 'master_pipeline_multi_v1.py': '50d051f77bd2bba15937460ac7642707a64d7cc32d768646ee1f85d8c8b1a90a'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def select_items(rows, items):
    if not isinstance(rows, list):
        raise ValueError("ai_results.json phải là danh sách.")
    keys = [r.get("issue_id") for r in rows]
    if any(not isinstance(k, str) or not k for k in keys) or len(keys) != len(set(keys)):
        raise ValueError("Kết quả cũ thiếu hoặc trùng issue_id.")
    by_key = {i["issue"]["key"]: i for i in items}
    selected = []
    for row in rows:
        if row.get("analysis_route") != "sql" or row.get("error_kind") != "CONTEXT_TOO_LARGE":
            continue
        item = by_key.get(row["issue_id"])
        if (not item or item["route"] != "sql"
                or row.get("component") != item["issue"].get("component")
                or row.get("line") != item["issue"].get("line")
                or row.get("source_sha256") != sha(item["raw"])):
            raise ValueError("Cảnh báo SQL cũ không khớp lần quét và mã nguồn.")
        selected.append(item)
    if not selected:
        raise ValueError("Không có cảnh báo SQL bị CONTEXT_TOO_LARGE để chạy lại.")
    return selected


def bundle(output):
    dest = output.parent / (output.name + "-review.zip")
    temporary = dest.with_suffix(".zip.tmp")
    with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(output.rglob("*")):
            if path.is_file() and not path.is_symlink() and path.name != "run.lock":
                z.write(path, str(Path(output.name) / path.relative_to(output)))
    temporary.replace(dest)
    print("ZIP CẦN GỬI:", dest, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-run", type=Path, default=Path(DEFAULT_RUN))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--retry-incomplete", action="store_true")
    args = parser.parse_args()
    root = Path.cwd().resolve()
    if Path(__file__).resolve().parent != root:
        raise ValueError("Chạy từ ~/AI_sec_tool, nơi đã cài bản cập nhật.")
    previous = args.previous_run.resolve()
    old_context = read(previous / "context.json")
    rows = read(previous / "ai_results.json")
    old_manifest = read(previous / "manifest.json")
    if old_manifest.get("result_count") != len(rows) or old_manifest.get("state") not in {"COMPLETED", "FAILED"}:
        raise ValueError("Lượt trước chưa xử lý xong; không dùng làm đối chiếu.")
    if not EXPECTED_PATCHES:
        raise ValueError("Gói cập nhật thiếu dấu vân tay mã nguồn.")
    for name, old_hash in old_context["dependency_sha256"].items():
        if Path(name).name != name:
            raise ValueError("Tên dependency không hợp lệ.")
        expected = EXPECTED_PATCHES.get(name, old_hash)
        if sha((root / name).read_bytes()) != expected:
            raise ValueError(f"{name}: khác bản đã kiểm tra; dừng để tránh trộn thay đổi.")
    for name, digest in EXPECTED_PATCHES.items():
        if sha((root / name).read_bytes()) != digest:
            raise ValueError(f"{name}: bản sửa chưa được cài đúng.")
    # Use the local saved collection, not the other machine's absolute pathname.
    collection = root / "runs" / Path(old_context["collection"]).name
    for name, key in (("manifest.json", "collection_manifest_sha256"),
                      ("issues.json", "collection_issues_sha256")):
        if sha((collection / name).read_bytes()) != old_context[key]:
            raise ValueError("Lượt thu thập SonarQube đã thay đổi: " + name)
    import master_pipeline_multi_v1 as router
    import run_holdout_system as masking
    policy = copy.deepcopy(old_context.get("evaluation_input_policy", {}))
    if (policy.get("version") != masking.VERSION
            or policy.get("script_sha256") != sha(Path(masking.__file__).read_bytes())
            or policy.get("source_policy") != "mask_all_java_comments_keep_lines"):
        raise ValueError("Không khớp cách che chú thích của lượt trước.")
    manifest, items = router.prepare(root, collection)
    items = select_items(rows, items)
    modules, config, code = router.configure(root, {"sql"})
    context = router.context_for(collection, items, config, code)
    context["selection"] = sorted({i["issue"]["component"] for i in items})
    context["evaluation_input_policy"] = policy
    context["repair_evaluation"] = {
        "version": VERSION, "script_sha256": sha(Path(__file__).read_bytes()),
        "previous_run": str(previous), "previous_results_sha256": sha((previous / "ai_results.json").read_bytes()),
        "previous_context_sha256": sha((previous / "context.json").read_bytes()),
        "selection_reason": "SQL CONTEXT_TOO_LARGE in previous completed processing",
        "changed": "Count source characters without unsent CPG text in the preliminary SQL gate",
        "unchanged": ["model/digest", "prompts", "generation options", "source and issue", "comment masking", "verdict policy"],
        "independent_holdout": False, "reference_labels_loaded": False,
    }
    output = root / "runs" / ("multi-" + collection.name + "-" + router.fingerprint(context)[:12])
    if output == previous:
        raise ValueError("Không được ghi đè lượt ban đầu.")
    print(f"SQL_RECHECK: {len(items)} cảnh báo; tối đa {len(items) * 3} lượt sinh AI mới nếu chạy đầy đủ.", flush=True)
    for item in items:
        print("  " + Path(item["relative"]).name, flush=True)
    print("Đây là lượt sửa lỗi sau đánh giá; không tính là bộ holdout độc lập.")
    print("KẾT QUẢ SẼ LƯU:", output)
    if args.check:
        print("SQL_RECHECK_OK: cấu hình và nguồn khớp; chưa gọi SonarQube/Joern/AI, chưa tạo kết quả.")
        return 0
    # Preserve the original comment policy and save the exact sent request.
    import requests
    original_post = requests.post
    counter = 0
    def post(url, *a, **kw):
        nonlocal counter
        if str(url).rstrip("/").endswith("/api/generate"):
            request = kw.get("json")
            count, changed = masking.sanitize(request)
            counter += 1
            from datetime import datetime, timezone
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            router.save(output / "model_request_audit" / f"{stamp}-{counter:04d}.json", {
                "version": masking.VERSION, "request": request, "source_block_count": count,
                "comments_masked_now": changed, "request_sha256": router.fingerprint(request)})
        return original_post(url, *a, **kw)
    requests.post = post
    try:
        result = router.execute(root, collection, manifest, items, modules, config, context, args.retry_incomplete)
    finally:
        requests.post = original_post
    bundle(output)
    return result


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Đã dừng. Giữ checkpoint; chỉ dùng --retry-incomplete nếu có cảnh báo dở dang.")
        sys.exit(130)
    except Exception as exc:
        import os
        message = str(exc)
        token = os.getenv("SONAR_TOKEN")
        if token:
            message = message.replace(token, "[REDACTED]")
        print("[LỖI] " + message, file=sys.stderr)
        sys.exit(1)
