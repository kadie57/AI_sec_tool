"""Recompute the merge policy from saved source/SQL outputs; no model calls."""
import argparse
import copy
import fcntl
import json
from pathlib import Path
import shutil
import sys
from collections import Counter
import zipfile

import triage_v5 as core
import source_audit_v2 as legacy
import sql_source_audit_v4 as audit
import recheck_sql_source as replay

VERSION = "sql-source-merge-offline-v1"
DEFAULT = "experiments/sql_source_recheck_v1/multi-owasp-holdout-20261115T151839Z-b04660-688bdde398e1-47bf30f61290"
EXPECTED_FILES = {'sql_source_audit_v4.py': '4b672801d382b0195ae47d54d125b27ea8eb83d64dda84a0b5e919a1e7f10e06', 'master_pipeline_source_v1.py': 'efe2078caa8ca90ab912e97362cf8b046ff12b12aa117a564f555ca6f7563246', 'master_pipeline_combined_v1.py': '08c2f2a78bb9a9fd38361a764b852f641c8748e0ec2668fd13398217fb5ceab8', 'replay_source_merge.py': 'a2e0d997a9d543f8794fa03cfd7c60506fd43c362436290cc750a98be56cadd0', 'master_pipeline_multi_v1.py': '69c753d064f4921afda2465e69f5d6ba2032d5e81ecb35f55d2c0be0f69d8398', 'recheck_sql_source.py': '1825cc18bb4d3a4e80e0bed4e8689db0af83090660ed29da70af6e723b7d919f', 'triage_v5.py': 'a52fa7d8ea4909644e90036f89150c605469e7a9804f4aeee732db2ef03cab22', 'source_audit_v2.py': 'd352094d47d0b8d5523d573f7996c4616dce45d2db32816f3fd72038a3bf0cf4', 'run_holdout_system.py': '05920f81bc3f2ce0fb685a13b73dbe23190b08acc071820ef2cc72c66fc3bbef'}


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return legacy.sha(path.read_bytes())


def prepare(root, previous):
    for name, expected in EXPECTED_FILES.items():
        if Path(name).name != name or sha(root / name) != expected:
            raise ValueError("Module khác bản đã kiểm tra: " + name)
    if not EXPECTED_FILES or sha(Path(core.__file__)) != legacy.CORE_HASH:
        raise ValueError("Core hoặc gói cập nhật không hợp lệ.")
    context, summary = read(previous / "context.json"), read(previous / "summary.json")
    rows = read(previous / "ai_results.json")
    if (summary.get("state") != "COMPLETED" or not isinstance(rows, list)
            or summary.get("result_count") != len(rows)):
        raise ValueError("Lượt nguồn chưa hoàn tất hoặc số bản ghi không khớp.")
    if context.get("model") != core.MODEL or context.get("model_digest") != legacy.DIGEST:
        raise ValueError("Model/digest của kết quả nguồn không khớp.")
    items = {r["issue_id"]: r for r in context["items"]}
    plan, seen = [], set()
    for row in rows:
        key, artifact = row.get("issue_id"), row.get("artifact_dir")
        if not key or key in seen or key not in items:
            raise ValueError("Issue ID thiếu, trùng hoặc không khớp context.")
        seen.add(key)
        if not isinstance(artifact, str) or Path(artifact).name != artifact:
            raise ValueError("artifact_dir không hợp lệ.")
        folder = (previous / artifact).resolve()
        if not folder.is_relative_to(previous):
            raise ValueError("Artifact ra ngoài thư mục kết quả.")
        source = (folder / "source.java.txt").read_bytes()
        record = read(folder / "llm_source_audit.json")
        stage = read(folder / "llm_stage2.json")
        digest = legacy.sha(source)
        if (digest != row.get("source_sha256") or digest != items[key]["source_sha256"]
                or digest != record.get("source_sha256")
                or sha(folder / "llm_stage2.json") != items[key]["stage2_sha256"]):
            raise ValueError("Nguồn hoặc bước SQL đã bị thay đổi.")
        if (audit.fingerprint(record["request_payload"]) != items[key]["request_sha256"]
                or record.get("issue_line") != row.get("line")
                or record.get("model_digest") != legacy.DIGEST
                or record.get("prompt_version") not in audit.REVIEW_VERSIONS):
            raise ValueError("Đầu vào source audit không khớp context.")
        full, _ = core.parse_model_text(stage["raw_output"])
        if (stage.get("error_kind") or stage["model_assessment"] != full
                or stage["ollama_response"].get("response") != stage["raw_output"]
                or stage["ollama_response"].get("done") is not True
                or stage["decision_policy_version"] != core.PROMPT_VERSION):
            raise ValueError("Không dùng bước SQL chưa hoàn tất hoặc facts đã chỉnh.")
        if record["previous_missing_context"] != full["missing_context"]:
            raise ValueError("Danh sách thiếu không khớp bước SQL.")
        if not record["error"]:
            raw_facts, _ = core.parse_model_text(record["raw_output"])
            if raw_facts != {**record["facts"], "gap_reviews": record["gap_reviews"]}:
                raise ValueError("Source facts không khớp đầu ra nguyên bản.")
        plan.append({"row": row, "stage": stage, "source": source.decode("utf-8"), "folder": folder,
                     "record": record, "request": record["request_payload"]})
    if set(items) != seen:
        raise ValueError("Số cảnh báo không khớp context.")
    provenance = {"version": VERSION, "merge_policy_version": audit.MERGE_POLICY_VERSION,
        "previous_run": str(previous), "previous_context_sha256": sha(previous / "context.json"),
        "previous_results_sha256": sha(previous / "ai_results.json"),
        "script_sha256": sha(Path(__file__)), "dependency_sha256": EXPECTED_FILES,
        "new_model_calls": 0, "reference_labels_loaded": False, "independent_holdout": False,
        "source_records": {p["row"]["issue_id"]: sha(p["folder"] / "llm_source_audit.json") for p in plan}}
    return plan, provenance


def recompute(plan):
    rows = []
    for item in plan:
        row = replay.make_result(item, item["record"])
        # The recorded AI proposal stays separate from the new policy decision.
        row["ai_verdict"] = item["row"].get("ai_verdict", item["row"]["verdict"])
        row["combined_verdict"] = row["verdict"]
        row["decision_origin"] = "SAVED_MODEL_OUTPUTS_WITH_SOURCE_GAP_GUARD"
        row["source_audit_version_reused"] = item["record"]["prompt_version"]
        row["prompt_version"] = item["record"]["prompt_version"]
        row["merge_policy_version"] = audit.MERGE_POLICY_VERSION
        row["new_model_calls"] = 0
        rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-run", type=Path, default=Path(DEFAULT))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--run", action="store_true")
    args = parser.parse_args()
    root, previous = Path.cwd().resolve(), args.previous_run.resolve()
    if root != Path(__file__).resolve().parent:
        raise ValueError("Chạy từ ~/AI_sec_tool.")
    plan, provenance = prepare(root, previous)
    rows = recompute(plan)
    changes = [(Path(a["row"]["component"]).name, a["row"]["verdict"], b["verdict"])
               for a, b in zip(plan, rows) if a["row"]["verdict"] != b["verdict"]]
    print(f"MERGE_CHECK_OK: {len(rows)} bản ghi hợp lệ; {len(changes)} kết luận ghép thay đổi; không gọi AI.")
    for name, before, after in changes:
        print(name + ": " + before + " -> " + after)
    if args.check:
        return 0
    output = root / "experiments" / "sql_source_merge_guard_v1" / (previous.name + "-" + audit.fingerprint(provenance)[:12])
    output.mkdir(parents=True, exist_ok=True)
    with (output / "run.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        context_file = output / "context.json"
        if context_file.exists() and read(context_file) != provenance:
            raise ValueError("Đầu ra khác cấu hình; không ghi đè.")
        audit.save(context_file, provenance)
        for item, row in zip(plan, rows):
            folder = output / row["artifact_dir"]
            folder.mkdir(exist_ok=True)
            for name in ("source.java.txt", "llm_stage2.json", "llm_source_audit.json"):
                shutil.copyfile(item["folder"] / name, folder / name)
            audit.save(folder / "previous_result.json", item["row"])
            audit.save(folder / "result.json", row)
        audit.save(output / "ai_results.json", rows)
        audit.save(output / "summary.json", {"version": VERSION, "state": "COMPLETED", "result_count": len(rows),
            "new_model_calls": 0, "changed_count": len(changes), "verdict_counts": dict(Counter(r["verdict"] for r in rows)),
            "error_count": sum(bool(r["error_kind"]) for r in rows), "provenance": provenance,
            "limitations": ["No new source or SQL semantic analysis was performed.",
                "Nonblank line checks cannot prove that a citation supports a claim.",
                "The legacy gap guard intentionally retains ambiguous wording for review."]})
        dest = output.parent / (output.name + "-review.zip")
        tmp = dest.with_suffix(".zip.tmp")
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
            for path in sorted(output.rglob("*")):
                if path.is_file() and not path.is_symlink() and path.name != "run.lock":
                    z.write(path, str(Path(output.name) / path.relative_to(output)))
        tmp.replace(dest)
        print("KẾT QUẢ:", output)
        print("ZIP CẦN GỬI:", dest)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("[LỖI] " + str(exc), file=sys.stderr)
        sys.exit(1)
