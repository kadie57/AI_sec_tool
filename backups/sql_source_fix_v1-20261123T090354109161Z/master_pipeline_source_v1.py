"""Experimental v6 + independent source audit. Three AI calls per eligible issue.
python3 master_pipeline_source_v1.py --check   # offline; no new analysis
OLLAMA_TIMEOUT=900 python3 master_pipeline_source_v1.py  # fresh full run
No automatic human review or issue closure. Does not fix v6 SQL-effect errors.
"""
import copy
import os
from pathlib import Path
import sys
import time
import master_pipeline_v6 as base
import source_audit_v2 as audit
from replay_source_merge import merge_assessments

core = base.core
pipeline = base.pipeline
VERSION = "sql89-v6-plus-source-audit-v2-explanation-2"

def source_request(numbered, issue_line):
    return {"model": core.MODEL, "system": audit.SYSTEM,
        "prompt": f"Kiểm tra nguồn dữ liệu tới SQL dòng {issue_line}.\n[MÃ NGUỒN]\n{numbered}\n[HẾT MÃ NGUỒN]",
        "format": copy.deepcopy(audit.SCHEMA), "stream": False,
        "options": copy.deepcopy(core.OPTIONS)}

def ask_source(request, source):
    record = {"request_payload": request, "facts": None, "error": None,
        "reference_check": None, "raw_output": "", "ollama_response": None,
        "review_required": True, "prompt_version": audit.VERSION,
        "source_sha256": audit.sha(source.encode("utf-8")),
        "model_digest": audit.DIGEST}
    started = time.perf_counter()
    try:
        url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
        response = core.requests.post(url + "/api/generate", json=request,
            timeout=(5, int(os.getenv("OLLAMA_TIMEOUT", "900"))))
        response.raise_for_status()
        body = response.json()
        record["ollama_response"] = body
        if not isinstance(body, dict) or body.get("error") or body.get("done") is not True:
            raise ValueError("Ollama chưa hoàn tất hoặc trả lỗi")
        if body.get("done_reason") == "length":
            raise ValueError("Đầu ra bị cắt")
        if body.get("prompt_eval_count", 0) + request["options"]["num_predict"] >= request["options"]["num_ctx"]:
            raise ValueError("Ngữ cảnh gần đầy")
        record["raw_output"] = body.get("response", "")
        facts, normalization = core.parse_model_text(record["raw_output"])
        record["facts"] = facts
        record["normalization"] = normalization
        record["reference_check"] = audit.check_facts(facts, source)
        record["resolved_evidence"] = {key: [
            {"line": e["line"], "code": source.splitlines()[e["line"]-1]} for e in facts[key]]
            for key in ("source_evidence", "flow_evidence")}
    except (core.requests.RequestException, ValueError, TypeError, AttributeError) as exc:
        record["error"] = str(exc)
    record["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return record

def ask_integrated(prompt, source_line_count=0):
    # Existing v6 saves both original stages before we audit their source claim.
    result = base.ask_v6(prompt, source_line_count)
    result["baseline_ai_verdict"] = result["verdict"]
    result["prompt_version"] = VERSION
    result["source_audit_status"] = "NOT_RUN"
    if result.get("error_kind"):
        return result
    _, numbered, issue_line = base.make_requests_input(prompt, source_line_count)
    source = (base.ARTIFACT / "source.java.txt").read_text(encoding="utf-8")
    expected = "\n".join(f"{n}: {line}" for n, line in enumerate(source.splitlines(), 1))
    if numbered != expected:
        raise ValueError("Nguồn trong prompt khác artifact; không gọi bước kiểm tra nguồn")
    print("    Bước 3/3: kiểm tra riêng nguồn và bằng chứng...", flush=True)
    request = source_request(numbered, issue_line)
    record = ask_source(request, source)
    pipeline.save_json(base.ARTIFACT / "llm_source_audit.json", record)
    if record["error"]:
        merged = core.unknown_result("Kiểm tra nguồn chưa hợp lệ: " + record["error"],
            "SOURCE_AUDIT_ERROR", requires_review=True,
            decision_basis="SOURCE_AUDIT_FAILED")
        result["source_audit_status"] = "ERROR"
        # Old assessment must not appear to be the new combined assessment.
        result["baseline_model_assessment"] = result.pop("model_assessment", None)
    else:
        merged = merge_assessments(result, record, source)
        result["source_audit_status"] = "PROPOSED_REQUIRES_REVIEW"
    result.update(merged)
    result["prompt_version"] = VERSION
    result["ai_verdict"] = result["verdict"]
    result["review_status"] = "PENDING" if not result.get("error_kind") else "CALL_ERROR"
    result["reviewed_verdict"] = None
    result["requires_review"] = True
    result["elapsed_seconds"] = round(result["elapsed_seconds"] + record["elapsed_seconds"], 3)
    result["request_payload"]["source_audit"] = request
    result["raw_output"]["source_audit"] = record["raw_output"]
    result["ollama_response"]["source_audit"] = record["ollama_response"]
    result["source_audit_facts"] = record["facts"]
    result["source_audit_reference_check"] = record["reference_check"]
    return result

def main():
    base.BASELINE, _ = base.experiment.prepare_plan(base.experiment.BASELINE)
    base.TEMPLATE = base.BASELINE["results"][0]["stage1_reused"]["request_payload"]
    base.QUESTIONS = base.TEMPLATE["prompt"].split(base.END + "\n\n", 1)[1]
    base.check_integration()
    if audit.sha(Path(core.__file__).read_bytes()) != audit.CORE_HASH:
        raise ValueError("Core khác bản đã kiểm tra")
    # Confirm exact request shape matches the standalone diagnostic builder.
    r = source_request("1: sample", 1)
    if r["system"] != audit.SYSTEM or r["format"] != audit.SCHEMA or r["options"] != core.OPTIONS:
        raise ValueError("Cấu hình audit không khớp")
    if "--check" in sys.argv[1:]:
        print("SOURCE_INTEGRATION_CHECK_OK: đã nạp adapter nguồn; chưa gọi dịch vụ hoặc chạy pipeline.")
        return 0
    if "--collect-only" not in sys.argv[1:]:
        if not os.getenv("SONAR_TOKEN"):
            raise ValueError("Cần đặt SONAR_TOKEN")
        if core.model_digest() != audit.DIGEST or base.BASELINE["model_digest"] != audit.DIGEST:
            raise ValueError("Mô hình khác baseline")
    pipeline.ask_ollama_local = ask_integrated
    pipeline.analyze_issue = base.analyze_issue
    pipeline.PROMPT_VERSION = VERSION
    pipeline.PIPELINE_VERSION += "+source-audit-v2-integration-1"
    print("Chạy mới: tối đa 3 lần gọi AI/cảnh báo đủ điều kiện; chưa có resume toàn pipeline.", flush=True)
    print("Bản này chỉ cải tiến nguồn; giữ nguyên cách đánh giá tác động SQL của v6.", flush=True)
    return pipeline.main()

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("Đã dừng. Artifact đã lưu vẫn còn; chạy lại pipeline sẽ tạo lượt mới.")
    except Exception as exc:
        sys.exit("LỖI: " + str(exc))
