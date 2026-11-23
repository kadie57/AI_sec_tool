"""Replay one saved path assessment with generic guard-reconciliation guidance.
Place beside path_triage_v1.py. No Sonar/Joern execution; at most one LLM call.
python3 replay_path_guard_v1.py
Optional: --sample PathCase01 --run runs/<path22-run> --check
This is a development diagnostic, not automatic integration or human review.
"""
import argparse
import copy
import fcntl
import json
from pathlib import Path
import sys

import path_triage_v1 as core

VERSION = "path22-guard-reconciliation-v1"
CORE_SHA = "92e51ac15b543fc895e81f49195fee50118462cc3ac6aac51da875b697b15a2b"
SUFFIX = """
Trước khi chốt path_effect, đối chiếu lời giải thích với đường thực thi:
1. Xác định giá trị dùng để mở/đọc file và mọi phép biến đổi trên đường tới đó.
2. Với từng if, regex, allowlist, phép chuyển kiểu hoặc kiểm tra đường dẫn,
   xác định nhánh nào throw/return, nhánh nào tiếp tục; nhánh thoát có bị catch
   rồi tiếp tục tới thao tác file hay không. Nêu điều kiện để thực sự tới đọc file.
3. Nếu có regex, đọc đúng tập ký tự và độ dài được chấp nhận. Phân biệt matches
   toàn chuỗi với tìm chuỗi con. Không coi một giá trị bị guard từ chối là bằng
   chứng đi tới thao tác file. Phải theo dõi việc dữ liệu có đổi sau guard không.
4. Nếu kết luận ESCAPABLE, giải thích cơ chế vượt thư mục còn khả thi SAU các
   kiểm tra. Nếu chỉ thấy luồng Joern, chưa chứng minh luồng có thể khai thác:
   luồng dữ liệu có thể vẫn tồn tại khi code đã có guard chặn giá trị nguy hiểm.
5. CONFINED chỉ khi bằng chứng đáp ứng định nghĩa hệ thống. Nếu phụ thuộc
   filesystem hoặc ngữ cảnh không có, dùng UNRESOLVED và nêu đúng phần thiếu;
   không tự giả định symlink tồn tại, cũng không tự giả định symlink không có.
6. Trong explanation, tóm tắt guard (hoặc việc không có guard), điều kiện tiếp
   tục và tác động lên đường dẫn. evidence_lines phải dẫn các dòng làm cơ sở:
   xây dựng/biến đổi đường dẫn, kiểm tra và nhánh thoát nếu có, mở/đọc file.
   Chỉ dòng cảnh báo tạo đối tượng File không đủ chứng minh các nhận định trên.
Viết lời giải thích bằng tiếng Việt, giữ nguyên tên định danh và enum. Không
đưa ví dụ tấn công chưa đối chiếu guard. Không đoán nhãn từ tên mẫu. Giữ đúng
schema đã yêu cầu; không thêm trường. Đây là phân tích code, không thực thi code.
"""


def prepare(run, sample):
    context = core.read(run / "context.json")
    if core.sha(Path(core.__file__).read_bytes()) != CORE_SHA or context.get("script_sha256") != CORE_SHA:
        raise ValueError("Bản path_triage_v1.py không khớp bản gốc đã đối chiếu; dừng, không sửa tự động.")
    rows = core.read(run / "ai_results.json")
    matches = [r for r in rows if r["component"].endswith("/" + sample + ".java")]
    if len(matches) != 1:
        raise ValueError("Không tìm thấy duy nhất mẫu yêu cầu trong lượt chạy.")
    row = matches[0]
    folder = (run / row["artifact_dir"]).resolve()
    if not folder.is_relative_to(run):
        raise ValueError("Đường dẫn artifact không hợp lệ.")
    raw = (folder / "source.java.txt").read_bytes()
    if core.sha(raw) != row["source_sha256"]:
        raise ValueError("Snapshot nguồn khác kết quả cũ.")
    source = raw.decode("utf-8")
    issue = next(i for i in core.read(run / "issues.json")["issues"] if i["key"] == row["issue_id"])
    flow = core.read(folder / "cpg_evidence.json")
    saved = core.read(folder / "llm_path.json")
    numbered = "\n".join(f"{n}: {line}" for n, line in enumerate(source.splitlines(), 1))
    expected = {"model": core.MODEL, "system": core.PATH_SYSTEM,
        "prompt": f"Rule: {core.RULE}; vùng cảnh báo: {core.span(issue)}.\n[MÃ NGUỒN]\n{numbered}\n[HẾT MÃ NGUỒN]\n"
                  + "[LUỒNG JOERN — CHỈ LÀ ĐƯỜNG TRUYỀN TỪ THAM SỐ]\n" + flow["paths"],
        "format": core.schema("path"), "stream": False, "options": core.OPTIONS}
    if saved["request_payload"] != expected or saved.get("error_kind"):
        raise ValueError("Yêu cầu hoặc kết quả cũ không khớp; dừng để đối chiếu.")
    core.validate(saved["facts"], "path", source)
    return context, row, issue, source, flow, saved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path)
    parser.add_argument("--sample", default="PathCase02", choices=["PathCase01", "PathCase02", "VulnerablePath"])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    run = args.run
    if run is None:
        candidates = sorted(Path("runs").glob("20261008T111154Z-7381f6-path22-*/ai_results.json"))
        if len(candidates) != 1:
            raise ValueError("Cần đúng một lượt gốc; dùng --run runs/<tên-lượt-path22> để chọn rõ.")
        run = candidates[0].parent
    run = run.resolve()
    context, row, issue, source, flow, old = prepare(run, args.sample)
    identity = {"version": VERSION, "run": str(run), "sample": args.sample,
        "source_sha256": row["source_sha256"], "old_request_sha256": core.fingerprint(old["request_payload"]),
        "old_result_sha256": core.fingerprint(old), "model_digest": context["model_digest"],
        "core_sha256": CORE_SHA, "script_sha256": core.sha(Path(__file__).read_bytes())}
    output = Path("experiments/path22_guard_replay_v1") / (args.sample + "-" + core.fingerprint(identity)[:12])
    if args.check:
        print("CHECK_OK: nguồn, request và bản mã gốc khớp; chưa gọi AI, chưa ghi file.")
        return 0
    output.mkdir(parents=True, exist_ok=True)
    with (output / "run.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (output / "experiment.json").exists() and core.read(output / "experiment.json") != identity:
            raise ValueError("Checkpoint không khớp; không ghi đè.")
        if not (output / "llm_path.json").exists():
            digest = next((m["digest"] for m in core.api("/api/tags")["models"] if m.get("name") == core.MODEL), None)
            if digest != context["model_digest"]:
                raise ValueError("Model khác lượt trước; chưa gọi AI.")
        core.save(output / "experiment.json", identity)
        (output / "source.java.txt").write_text(source, encoding="utf-8")
        system = core.PATH_SYSTEM
        try:
            core.PATH_SYSTEM = system + SUFFIX
            result = core.ask("path", source, issue, flow, output)
        finally:
            core.PATH_SYSTEM = system
        expected = copy.deepcopy(old["request_payload"])
        expected["system"] += SUFFIX
        if result["request_payload"] != expected:
            raise ValueError("Replay thay đổi ngoài system prompt; chưa chấp nhận so sánh.")
        summary = {"sample": args.sample, "version": VERSION, "provenance": identity,
            "changed": ["Append generic guard-reconciliation guidance to system prompt"],
            "unchanged": ["Model/digest", "Java source", "Joern flow", "User prompt", "Schema", "Options"],
            "before": old["facts"], "after": result.get("facts"),
            "resolved_evidence": result.get("resolved_evidence"), "error_kind": result["error_kind"],
            "error": result.get("error"), "elapsed_seconds": result["elapsed_seconds"],
            "requires_review": True, "integrated": False,
            "limitations": ["One development sample; no accuracy claim.",
                "No final verdict recomputed; source assessment remains unchanged.",
                "Original run and expert reviews remain unchanged."]}
        core.save(output / "comparison.json", summary)
        print(json.dumps({k: summary[k] for k in ("sample", "before", "after", "error_kind", "error")}, ensure_ascii=False, indent=2))
        print(f"FILE CẦN GỬI: {(output / 'comparison.json').resolve()}")
        return 1 if result["error_kind"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Đã dừng; chạy lại để dùng phần đã lưu.")
        sys.exit(130)
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
        print(f"[LỖI] {exc}", file=sys.stderr)
        sys.exit(1)
