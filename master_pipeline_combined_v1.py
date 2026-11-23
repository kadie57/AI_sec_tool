"""Candidate: original stage 1 + frozen v7 stage 2 + HTTP source audit v4.
--check is offline. Normal invocation runs a new full pipeline, up to 4 AI calls
per eligible issue, with no whole-pipeline resume. All verdicts require review.
"""
import copy
import os
from pathlib import Path
import sys
import master_pipeline_source_v1 as integrated
from check_sql_prompt_controls import extract_suffix

base = integrated.base
core = integrated.core
audit = integrated.audit
pipeline = integrated.pipeline
VERSION = "sql89-v7-stage2-plus-source-http-v4"
STAGE2_VERSION = "sql89-stage2-selfcheck-v7-frozen-1"

def prepare_suffix():
    import json
    def read(path):
        return json.loads(path.read_text(encoding="utf-8"))
    run = Path(audit.DEFAULT_RUN)
    rows = read(run / "ai_results.json")
    comparisons = []
    for name, line in (("Trial04", 20), ("Trial01", 20), ("Trial03", 23), ("Trial05", 19)):
        matches = [r for r in rows if r.get("component", "").endswith("/" + name + ".java")
                   and r.get("line") == line and r.get("processing_status") == "AI_PROPOSED"]
        if len(matches) != 1:
            raise ValueError("Không xác định được baseline " + name)
        row = matches[0]
        stage_path = run / row["artifact_dir"] / "llm_stage2.json"
        old = read(stage_path)
        source = (stage_path.parent / "source.java.txt").read_bytes()
        if audit.sha(source) != row["source_sha256"]:
            raise ValueError("Source hash không khớp")
        root = "v7_stage2_diagnostic" if name == "Trial04" else "v7_sql_controls"
        saved_path = Path("experiments") / root / run.name / (name + ".json")
        saved = read(saved_path)
        meta = saved["metadata"] if name == "Trial04" else saved["identity"]
        hash_key = "baseline_stage2_sha256" if name == "Trial04" else "baseline_sha256"
        if (meta[hash_key] != audit.sha(stage_path.read_bytes())
                or meta["source_sha256"] != row["source_sha256"]
                or meta["model_digest"] != audit.DIGEST
                or saved["result"].get("error_kind") or old.get("error_kind")):
            raise ValueError("Thử nghiệm không khớp baseline " + name)
        request = old["request_payload"]
        if request["model"] != core.MODEL or request["options"] != core.OPTIONS:
            raise ValueError("Model/options baseline không khớp")
        suffix = extract_suffix(request, saved["result"]["request_payload"])
        comparisons.append((name, suffix))
    if len({suffix for _, suffix in comparisons}) != 1:
        raise ValueError("Các mẫu không dùng cùng hướng dẫn bổ sung")
    print("FROZEN_PROMPT_OK: cùng phần hướng dẫn trên Trial04 và 3 mẫu đối chứng.")
    return comparisons[0][1]

def main():
    base.BASELINE, _ = base.experiment.prepare_plan(base.experiment.BASELINE)
    base.TEMPLATE = base.BASELINE["results"][0]["stage1_reused"]["request_payload"]
    base.QUESTIONS = base.TEMPLATE["prompt"].split(base.END + "\n\n", 1)[1]
    base.check_integration()
    suffix = prepare_suffix()
    original_builder = base.v6.make_request
    def frozen_builder(request, draft):
        result = original_builder(request, draft)
        result["prompt"] += suffix
        return result
    # No files modified: install the builder only in this process after v6 checks.
    base.v6.make_request = frozen_builder
    base.v6.PROMPT_VERSION = STAGE2_VERSION
    integrated.VERSION = VERSION
    if "--check" in sys.argv[1:]:
        print("COMBINED_CHECK_OK: cấu hình ghép đã nạp; chưa gọi AI/SonarQube/Joern.")
        return 0
    if "--collect-only" not in sys.argv[1:]:
        if not os.getenv("SONAR_TOKEN"):
            raise ValueError("Cần đặt SONAR_TOKEN")
        if core.model_digest() != audit.DIGEST or base.BASELINE["model_digest"] != audit.DIGEST:
            raise ValueError("Model digest khác baseline")
    pipeline.ask_ollama_local = integrated.ask_integrated
    pipeline.analyze_issue = base.analyze_issue
    pipeline.PROMPT_VERSION = VERSION
    pipeline.PIPELINE_VERSION += "+v7-sql-source-v4-candidate-1"
    print("Bản đánh giá cố định: bước 1 v6, bước 2 thêm hướng dẫn đã thử, bước 3 kiểm tra nguồn.", flush=True)
    print("Tối đa 4 lần gọi AI/cảnh báo đủ điều kiện; mỗi lần chạy tạo lượt mới, chưa có resume.", flush=True)
    print("Nhãn và lời giải thích vẫn cần thẩm định. Không tự đóng cảnh báo.", flush=True)
    return pipeline.main()

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("Đã dừng; giữ artifact đã ghi. Chạy lại pipeline tạo lượt mới.")
    except Exception as exc:
        sys.exit("LỖI: " + str(exc))
