"""Pipeline v6 thử nghiệm: kết luận AI cần được thẩm định."""
import copy
import os
import re
import sys

import master_pipeline as pipeline
import validate_v6 as experiment

v6 = experiment.v6
core = experiment.core

BASELINE = None
TEMPLATE = None
QUESTIONS = None
ARTIFACT = None

START = "[MÃ NGUỒN — DỮ LIỆU]\n"
END = "\n[HẾT MÃ NGUỒN]"

original_analyze = pipeline.analyze_issue


def make_requests_input(prompt, line_count):
    if prompt.count(START) != 1 or prompt.count(END) != 1:
        raise ValueError("Không xác định được khối mã nguồn.")

    header, remaining = prompt.split(START, 1)
    numbered = remaining.split(END, 1)[0]
    lines = numbered.splitlines()

    if len(lines) != line_count:
        raise ValueError("Số dòng mã nguồn không khớp.")

    for number, text in enumerate(lines, 1):
        if not text.startswith(f"{number}: "):
            raise ValueError("Mã nguồn đánh số dòng không hợp lệ.")

    match = re.search(r"^Dòng cảnh báo: (\d+)$", header, re.M)
    if not match:
        raise ValueError("Không xác định được dòng cảnh báo.")

    issue_line = int(match.group(1))
    if not 1 <= issue_line <= line_count:
        raise ValueError("Dòng cảnh báo nằm ngoài mã nguồn.")

    request = copy.deepcopy(TEMPLATE)
    request["prompt"] = (
        f"Đánh giá khả năng SQL injection tại dòng {issue_line}.\n\n"
        + START + numbered + END + "\n\n" + QUESTIONS
    )
    return request, numbered, issue_line


def ask_v6(prompt, source_line_count=0):
    request1, numbered, issue_line = make_requests_input(
        prompt, source_line_count
    )

    print("    V6 bước 1/2: đọc và giải thích code...", flush=True)
    first = experiment.ask_prose(request1)
    pipeline.save_json(ARTIFACT / "llm_stage1.json", first)

    second = None
    if first["error_kind"]:
        result = core.unknown_result(
            "Bước phân tích đầu tiên chưa hoàn tất.",
            first["error_kind"],
        )
    else:
        request2 = v6.make_request(
            core.make_request(numbered, issue_line),
            first["raw_output"],
        )
        print("    V6 bước 2/2: đối chiếu và xuất JSON...", flush=True)
        second = core.ask(request2, source_line_count)
        second["prompt_version"] = v6.PROMPT_VERSION
        second["decision_policy_version"] = core.PROMPT_VERSION
        pipeline.save_json(ARTIFACT / "llm_stage2.json", second)

        result = {
            key: value for key, value in second.items()
            if key not in (
                "request_payload", "ollama_response", "raw_output"
            )
        }

    result.update({
        "model": core.MODEL,
        "prompt_version": v6.PROMPT_VERSION,
        "ai_verdict": result["verdict"],
        "review_status": (
            "PENDING" if not result.get("error_kind") else "CALL_ERROR"
        ),
        "reviewed_verdict": None,
        "review_notes": None,
        "requires_review": True,
        "cpg_usage": "eligibility_gate_only_not_sent_to_llm",
        "elapsed_seconds": round(
            first["elapsed_seconds"]
            + (second["elapsed_seconds"] if second else 0), 3
        ),
        "request_payload": {
            "stage1": request1,
            "stage2": second["request_payload"] if second else None,
        },
        "raw_output": {
            "stage1": first["raw_output"],
            "stage2": second["raw_output"] if second else None,
        },
        "ollama_response": {
            "stage1": first["ollama_response"],
            "stage2": second["ollama_response"] if second else None,
        },
    })
    return result


def analyze_issue(issue, project, root, run_dir, image, index):
    global ARTIFACT
    ARTIFACT = run_dir / f"issue-{index:04d}"
    try:
        result = original_analyze(
            issue, project, root, run_dir, image, index
        )
        if result.get("processing_status") == "ANALYZED":
            result["processing_status"] = "AI_PROPOSED"
        return result
    finally:
        ARTIFACT = None


def check_integration():
    for row in BASELINE["results"]:
        old_request = row["stage1_reused"]["request_payload"]
        numbered = old_request["prompt"].split(
            START, 1
        )[1].split(END, 1)[0]

        source = "\n".join(
            line.split(": ", 1)[1] for line in numbered.splitlines()
        ) + "\n"

        prompt = pipeline.build_advanced_iris_prompt(
            "findsecbugs:SQL_INJECTION_JDBC",
            source,
            "OFFLINE_CHECK",
            {"key": row["issue_id"], "line": row["issue_line"]},
        )
        request1, code, issue_line = make_requests_input(
            prompt, len(source.splitlines())
        )
        request2 = v6.make_request(
            core.make_request(code, issue_line),
            row["stage1_reused"]["raw_output"],
        )

        if request1 != old_request:
            raise ValueError(f"{row['sample']}: request bước 1 khác.")
        if request2 != row["triage"]["request_payload"]:
            raise ValueError(f"{row['sample']}: request bước 2 khác.")

    print("CHECK_OK: yêu cầu AI khớp cấu hình v6 trên cả 6 mẫu.")
    print("Chưa quét SonarQube, chưa chạy Joern, chưa gọi AI phân tích.")
    print(
        "SONAR_TOKEN:",
        "đã đặt" if os.getenv("SONAR_TOKEN") else "chưa đặt",
    )


def main():
    global BASELINE, TEMPLATE, QUESTIONS
    BASELINE, _ = experiment.prepare_plan(experiment.BASELINE)
    TEMPLATE = BASELINE["results"][0]["stage1_reused"]["request_payload"]
    QUESTIONS = TEMPLATE["prompt"].split(END + "\n\n", 1)[1]

    check_integration()

    if "--check" in sys.argv[1:]:
        return 0

    if "--collect-only" not in sys.argv[1:]:
        if not os.getenv("SONAR_TOKEN"):
            raise ValueError("Cần đặt SONAR_TOKEN trước khi chạy pipeline.")
        if core.model_digest() != BASELINE["model_digest"]:
            raise ValueError("Mô hình hiện tại khác mô hình đã thử nghiệm.")

    pipeline.ask_ollama_local = ask_v6
    pipeline.analyze_issue = analyze_issue
    pipeline.PROMPT_VERSION = v6.PROMPT_VERSION
    pipeline.PIPELINE_VERSION += "+v6-review-1"

    print("Nhãn AI là đề xuất; reviewed_verdict chưa được xác nhận.")
    return pipeline.main()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nĐã dừng. Các bước đã ghi ra file vẫn được giữ lại.")
        sys.exit(130)
    except Exception as exc:
        print(f"[LỖI] {exc}", file=sys.stderr)
        sys.exit(1)
