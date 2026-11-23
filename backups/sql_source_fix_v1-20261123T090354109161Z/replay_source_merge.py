"""Offline integration of saved v6 SQL facts and source_audit_v2.
No network, no inference, no SonarQube/Joern. Original records are untouched.
Only audited cases are merged. This is NOT a complete pipeline evaluation.
"""
import argparse
import copy
import json
from datetime import datetime, timezone
from pathlib import Path
import triage_v5 as core
import source_audit_v2 as audit

VERSION = "v6-sql-plus-source-audit-v2-explanation-2"

def merge_assessments(stage2, source_record, source):
    """Reusable merge policy. Structural checks do not prove source semantics."""
    if stage2.get("error_kind") or source_record.get("error"):
        raise ValueError("Không ghép kết quả có lỗi; cần thẩm định riêng")
    old = stage2["model_assessment"]
    checked = core.validate_and_decide(old, len(source.splitlines()))
    if checked.get("error_kind") or checked["verdict"] != stage2["verdict"]:
        raise ValueError("Kết quả bước 2 không khớp quy tắc v5")
    sf = source_record["facts"]
    audit.check_facts(sf, source)
    facts = copy.deepcopy(old)
    facts["source_control"] = "CONFIRMED" if sf["source_kind"] == "EXTERNAL_READ" else "UNRESOLVED"
    # Retain all original gaps conservatively; never erase a gap automatically.
    facts["missing_context"] = list(dict.fromkeys(old["missing_context"] + sf["missing_context"]))
    facts["evidence_lines"] = sorted(set(old["evidence_lines"] + [
        e["line"] for key in ("source_evidence", "flow_evidence") for e in sf[key]]))
    # Decide using exactly the same facts and policy before composing prose.
    result = core.validate_and_decide(facts, len(source.splitlines()))
    basis = result.get("decision_basis")
    conclusions = {
        "SOURCE_UNRESOLVED": "Chưa đủ cơ sở kết luận TP/FP: chưa chứng minh người bên ngoài kiểm soát dữ liệu tới SQL.",
        "SQL_EFFECT_UNRESOLVED": "Chưa đủ cơ sở kết luận TP/FP: chưa xác định được tác động của dữ liệu lên cú pháp SQL.",
        "MISSING_CONTEXT": "Chưa đủ cơ sở kết luận TP/FP: còn thiếu ngữ cảnh cần thiết.",
        "PROTECTION_REPORTED": "Có cơ sở đề xuất cảnh báo giả tại truy vấn này: bước phân tích SQL báo cáo cơ chế ngăn đầu vào làm thay đổi cú pháp truy vấn.",
        "EXTERNAL_CONTROL_AND_CHANGEABLE_SQL_REPORTED": "Có cơ sở đề xuất cảnh báo đúng: kiểm tra nguồn báo cáo đầu vào bên ngoài và phân tích SQL báo cáo khả năng thay đổi cú pháp truy vấn.",
    }
    source_meaning = {
        "EXTERNAL_READ": "Kiểm tra nguồn báo cáo có thao tác đọc đầu vào bên ngoài liên quan tới truy vấn.",
        "PARAMETER_ONLY": "Chỉ thấy tham số hàm; chưa có caller hoặc thao tác đọc đầu vào bên ngoài chứng minh nguồn của giá trị.",
        "UNRESOLVED": "Chưa xác định được nguồn hoặc đường đi của dữ liệu trong mã đã cung cấp.",
    }
    sql_meaning = {
        "PROTECTED": "Bước 2 báo cáo có bảo vệ tại truy vấn (PROTECTED).",
        "CHANGEABLE": "Bước 2 báo cáo dữ liệu có thể thay đổi cú pháp SQL (CHANGEABLE). Điều này tự nó chưa chứng minh nguồn do người bên ngoài kiểm soát.",
        "UNRESOLVED": "Bước 2 chưa xác định được tác động lên cú pháp SQL (UNRESOLVED).",
    }
    source_lines = source.splitlines()
    resolved = [{"line": n, "code": source_lines[n-1]} for n in old["evidence_lines"]]
    changed = old["source_control"] != facts["source_control"] or stage2["verdict"] != result["verdict"]
    parts = ["Kết luận: " + result["verdict"] + ". " + conclusions.get(basis, "Cần thẩm định thêm."),
             "Nguồn dữ liệu: " + source_meaning[sf["source_kind"]],
             "Tác động SQL: " + sql_meaning[old["sql_effect"]]]
    if changed:
        parts.append("Bước kiểm tra nguồn đã điều chỉnh nhận định trước đó: "
                     + stage2["verdict"] + " → " + result["verdict"]
                     + ". Nhận định về nguồn trong lời giải thích bước 2 không phải kết luận nguồn cuối.")
    if result["missing_context"]:
        parts.append("Thông tin còn thiếu: " + "; ".join(result["missing_context"]))
    parts.append("Các dòng mã được bước 2 dẫn (cần đối chiếu lập luận):\n" +
                 "\n".join(str(e["line"]) + ": " + e["code"] for e in resolved))
    explanation = "\n\n".join(parts)
    result["explanation"] = explanation
    result["model_assessment"]["explanation"] = explanation
    result.update({
        "explanation_version": "sql-source-merge-explanation-v2",
        "explanation_origin": "DETERMINISTIC_COMPOSITION_OF_MODEL_FACTS",
        "stage2_explanation_original": old["explanation"],
        "source_explanation_original": sf["explanation"],
        "stage2_assessment_original": copy.deepcopy(old),
        "stage2_evidence_resolved": resolved,
        "source_assessment_changed": changed,
        "explanation_limitations": [
            "Việc ghép không thẩm định ngữ nghĩa của nhận định AI hoặc chọn lại dòng bằng chứng.",
            "Giải thích gốc từng bước được lưu riêng; nhận định nguồn bước 2 có thể đã bị sửa."]})
    result.update({"prompt_version": VERSION, "decision_policy_version": core.PROMPT_VERSION,
                   "review_status": "PENDING", "reviewed_verdict": None,
                   "requires_review": True, "ai_verdict": result["verdict"],
                   "baseline_ai_verdict": stage2["verdict"],
                   "source_kind": sf["source_kind"], "sql_effect_reused": old["sql_effect"]})
    return result

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, default=Path(audit.DEFAULT_RUN))
    args = parser.parse_args()
    if audit.sha(Path(core.__file__).read_bytes()) != audit.CORE_HASH:
        raise ValueError("triage_v5.py khác baseline")
    manifest = read(args.run / "manifest.json")
    if manifest.get("state") != "COMPLETED":
        raise ValueError("Baseline chưa hoàn tất")
    rows = read(args.run / "ai_results.json")
    output_rows = []
    for name, line in (("VulnerableLogin.java", 15), ("Trial01.java", 20)):
        matches = [r for r in rows if r.get("component", "").endswith("/" + name)
                   and r.get("line") == line and r.get("processing_status") == "AI_PROPOSED"]
        if len(matches) != 1:
            raise ValueError("Không xác định được duy nhất cảnh báo: " + name)
        row = matches[0]
        folder = args.run / row["artifact_dir"]
        source_raw = (folder / "source.java.txt").read_bytes()
        source = source_raw.decode("utf-8")
        stage_path = folder / "llm_stage2.json"
        stage = read(stage_path)
        audit_path = Path("experiments/source_audit_v2") / args.run.name / (Path(name).stem + ".json")
        saved = read(audit_path)
        identity = saved["identity"]
        if audit.sha(source_raw) != row["source_sha256"] or identity["source_sha256"] != row["source_sha256"]:
            raise ValueError("Mã nguồn giữa hai bước không khớp")
        if identity["script_sha256"] != audit.sha(Path(audit.__file__).read_bytes()):
            raise ValueError("source_audit_v2.py đã thay đổi từ lượt chạy đã lưu")
        if identity["model_digest"] != audit.DIGEST or identity["core_sha256"] != audit.CORE_HASH:
            raise ValueError("Cấu hình source audit không khớp")
        numbered = "\n".join(f"{i}: {s}" for i, s in enumerate(source.splitlines(), 1))
        expected_request = {"model": core.MODEL, "system": audit.SYSTEM,
            "prompt": f"Kiểm tra nguồn dữ liệu tới SQL dòng {line}.\n[MÃ NGUỒN]\n{numbered}\n[HẾT MÃ NGUỒN]",
            "format": audit.SCHEMA, "stream": False, "options": core.OPTIONS}
        if identity["request_payload"] != expected_request:
            raise ValueError("Yêu cầu source audit khác nguồn/dòng/cấu hình")
        old_request = stage["request_payload"]
        block = "[MÃ NGUỒN — DỮ LIỆU]\n" + numbered + "\n[HẾT MÃ NGUỒN]"
        if (old_request["model"] != core.MODEL or block not in old_request["prompt"]
                or not old_request["prompt"].startswith(f"Thẩm định SQL injection tại dòng {line}.")):
            raise ValueError("Bước 2 khác nguồn/dòng/mô hình")
        if row["ai_verdict"] != stage["verdict"]:
            raise ValueError("Nhãn baseline không khớp artifact")
        result = merge_assessments(stage, saved, source)
        output_rows.append({"component": row["component"], "line": line,
            "source_sha256": row["source_sha256"],
            "stage2_path": str(stage_path), "stage2_sha256": audit.sha(stage_path.read_bytes()),
            "audit_path": str(audit_path), "audit_sha256": audit.sha(audit_path.read_bytes()),
            "original_stage2": stage, "source_audit": saved, "merged": result})
    output = Path("experiments/source_merge_replay") / args.run.name
    output.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dest = output / ("merged_" + stamp + ".json")
    summary = {"version": VERSION, "analysis_id": manifest.get("analysis_id"),
        "new_ai_calls": 0, "merged_count": len(output_rows),
        "baseline_ai_proposed_count": sum(r.get("processing_status") == "AI_PROPOSED" for r in rows),
        "scope": "Only two audited cases; not a full pipeline run or accuracy evaluation",
        "limitations": ["Source audit is model output requiring semantic review.",
                       "SQL-effect facts are reused unchanged, including any old mistakes.",
                       "Original explanations retained separately; no human label used to choose verdicts."],
        "results": output_rows}
    with dest.open("x", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    for row in output_rows:
        r = row["merged"]
        print(row["component"].split("/")[-1], "| trước:", r["baseline_ai_verdict"],
              "| sau ghép:", r["verdict"], "| nguồn:", r["source_kind"],
              "| SQL:", r["sql_effect_reused"])
    print("ĐÃ LƯU:", dest)
    print("Không gọi AI; chưa sửa pipeline; cả hai kết quả mới vẫn cần thẩm định.")

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit("LỖI: " + str(exc))
