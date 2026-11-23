"""Reuse the exact saved Trial04 v7 suffix on three development controls.
At most 3 new stage-2 calls. No scan, stage 1, source audit, or answer labels.
"""
import argparse
import copy
import fcntl
import json
from pathlib import Path
import triage_v5 as core
import source_audit_v2 as audit

VERSION = "v7-stage2-fixed-suffix-controls-1"

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def extract_suffix(old, new):
    if set(old) != set(new) or any(old[k] != new[k] for k in old if k != "prompt"):
        raise ValueError("Thử nghiệm Trial04 thay đổi ngoài prompt")
    if not new["prompt"].startswith(old["prompt"]):
        raise ValueError("Không xác định được phần hướng dẫn bổ sung")
    suffix = new["prompt"][len(old["prompt"]):]
    if not suffix.strip() or "KIỂM TRA CUỐI TRƯỚC KHI XUẤT JSON:" not in suffix:
        raise ValueError("Thiếu phần tự kiểm tra đã thử")
    return suffix

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    run = Path(audit.DEFAULT_RUN)
    if audit.sha(Path(core.__file__).read_bytes()) != audit.CORE_HASH:
        raise ValueError("Core khác baseline")
    rows = read(run / "ai_results.json")
    def locate(name, line):
        matches = [r for r in rows if r.get("component", "").endswith("/" + name + ".java")
                   and r.get("line") == line and r.get("processing_status") == "AI_PROPOSED"]
        if len(matches) != 1:
            raise ValueError("Không tìm được duy nhất cảnh báo " + name)
        row = matches[0]
        folder = run / row["artifact_dir"]
        raw = (folder / "source.java.txt").read_bytes()
        if audit.sha(raw) != row["source_sha256"]:
            raise ValueError("Mã nguồn không khớp " + name)
        stage_path = folder / "llm_stage2.json"
        stage = read(stage_path)
        if stage.get("error_kind") or stage["verdict"] != row["ai_verdict"]:
            raise ValueError("Bước 2 baseline không hợp lệ")
        source = raw.decode("utf-8")
        numbered = "\n".join(f"{n}: {s}" for n, s in enumerate(source.splitlines(), 1))
        prompt = stage["request_payload"]["prompt"]
        if (not prompt.startswith(f"Thẩm định SQL injection tại dòng {line}.") or
            "[MÃ NGUỒN — DỮ LIỆU]\n" + numbered + "\n[HẾT MÃ NGUỒN]" not in prompt):
            raise ValueError("Request không khớp nguồn/dòng " + name)
        return row, stage, stage_path, len(source.splitlines())
    row04, old04, path04, _ = locate("Trial04", 20)
    trial_path = Path("experiments/v7_stage2_diagnostic") / run.name / "Trial04.json"
    trial = read(trial_path)
    if (trial["metadata"]["source_sha256"] != row04["source_sha256"] or
        trial["metadata"]["baseline_stage2_sha256"] != audit.sha(path04.read_bytes()) or
        trial["metadata"]["model_digest"] != audit.DIGEST or trial["result"].get("error_kind")):
        raise ValueError("Thử nghiệm Trial04 không khớp baseline")
    suffix = extract_suffix(old04["request_payload"], trial["result"]["request_payload"])
    plan = []
    for name, line in (("Trial01", 20), ("Trial03", 23), ("Trial05", 19)):
        row, old, stage_path, count = locate(name, line)
        request = copy.deepcopy(old["request_payload"])
        if request["model"] != core.MODEL or request["options"] != core.OPTIONS:
            raise ValueError("Mô hình/options baseline không khớp")
        request["prompt"] += suffix
        identity = {"version": VERSION, "request_payload": request,
            "source_sha256": row["source_sha256"], "baseline_sha256": audit.sha(stage_path.read_bytes()),
            "trial04_diagnostic_sha256": audit.sha(trial_path.read_bytes()),
            "script_sha256": audit.sha(Path(__file__).read_bytes()), "model_digest": audit.DIGEST}
        plan.append((name, old, count, identity))
    if args.check:
        print("CHECK_OK: 3 mẫu; giữ nguyên hướng dẫn v7 đã lưu; chưa gọi AI.")
        return
    out = Path("experiments/v7_sql_controls") / run.name
    out.mkdir(parents=True, exist_ok=True)
    with (out / "run.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name, old, count, identity in plan:
            dest = out / (name + ".json")
            if dest.exists():
                saved = read(dest)
                if saved["identity"] != identity:
                    raise ValueError("Checkpoint khác cấu hình; không ghi đè")
            else:
                if core.model_digest() != audit.DIGEST:
                    raise ValueError("Model digest thay đổi")
                print("Đang chạy bước 2: " + name, flush=True)
                result = core.ask(identity["request_payload"], count)
                result["prompt_version"] = VERSION
                result["decision_policy_version"] = core.PROMPT_VERSION
                saved = {"identity": identity, "baseline_verdict": old["verdict"], "result": result}
                temp = dest.with_suffix(".tmp")
                temp.write_text(json.dumps(saved, ensure_ascii=False, indent=2), encoding="utf-8")
                temp.replace(dest)
            r = saved["result"]
            print(json.dumps({"file": name, "before": saved["baseline_verdict"],
                "after": r["verdict"], "facts": r.get("model_assessment"),
                "error_kind": r.get("error_kind")}, ensure_ascii=False, indent=2), flush=True)
            print("ĐÃ LƯU:", dest, flush=True)
            if r.get("error_kind"):
                print("Dừng sau lỗi; không tự thử lại.")
                break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Đã dừng; chạy lại bỏ qua kết quả đã lưu.")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit("LỖI: " + str(exc))
