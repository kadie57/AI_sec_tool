"""Read-only local run browser. No pipeline imports, inference, or writes."""
import json
import hashlib
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from flask import Flask, render_template, request, abort

app = Flask(__name__)
ROOT = Path(__file__).resolve().parent.parent
RUN_ROOTS = (("Bộ phát triển", ROOT / "runs"),
             ("Bộ Probe", ROOT / "eval_sql89_new_v1" / "runs"))
STATES = {"COMPLETED": "Hoàn tất", "COLLECTED": "Đã thu thập", "FAILED": "Thất bại",
          "STARTED": "Chưa ghi hoàn tất", "IN_PROGRESS": "Chưa ghi hoàn tất"}

def local_time(value):
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return d.astimezone(ZoneInfo("Asia/Ho_Chi_Minh")).strftime("%d/%m/%Y %H:%M:%S") if d.tzinfo else value
    except (ValueError, TypeError, AttributeError):
        return "Chưa có thời gian"

def load_runs():
    runs, warnings = [], []
    for group_id, (group, folder) in enumerate(RUN_ROOTS):
        if not folder.exists():
            warnings.append(f"Chưa tìm thấy thư mục {folder.relative_to(ROOT)}")
            continue
        for path in folder.glob("*/manifest.json"):
            if not path.resolve().is_relative_to(folder.resolve()):
                continue
            try:
                m = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(m, dict):
                    raise ValueError("manifest không phải object")
                result_path = path.parent / "ai_results.json"
                counts, statuses, available = Counter(), Counter(), False
                if result_path.exists():
                    if not result_path.resolve().is_relative_to(folder.resolve()):
                        raise ValueError("Đường dẫn kết quả nằm ngoài thư mục lượt chạy")
                    results = json.loads(result_path.read_text(encoding="utf-8"))
                    if not isinstance(results, list) or any(not isinstance(r, dict) for r in results):
                        raise ValueError("ai_results phải là danh sách bản ghi")
                    available = True
                    for r in results:
                        status = r.get("processing_status", "UNSPECIFIED")
                        statuses[status] += 1
                        if status in ("AI_PROPOSED", "ANALYZED"):
                            counts[r.get("ai_verdict") or r.get("verdict", "UNKNOWN")] += 1
                state = m.get("state", "UNKNOWN")
                runs.append({"folder": path.parent.name, "relative": str(path.parent.relative_to(ROOT)),
                    "group": group, "group_id": group_id, "project": m.get("project", "Chưa ghi project"),
                    "state": state, "state_label": STATES.get(state, state),
                    "sort": m.get("started_at", ""), "time": local_time(m.get("started_at")),
                    "issues": m.get("issue_count", "—"), "supported": m.get("supported_issue_count", "—"),
                    "ai_count": sum(counts.values()), "counts": counts, "statuses": statuses,
                    "available": available, "analysis_id": m.get("analysis_id", "Chưa có"),
                    "version": m.get("pipeline_version", "Chưa ghi"),
                    "error": m.get("error"), "limitations": m.get("limitations", [])})
            except (OSError, ValueError, TypeError) as exc:
                warnings.append(f"Không đọc được {path.parent.name}: {exc}. Nếu lượt đang ghi, hãy tải lại trang.")
    runs.sort(key=lambda r: str(r["sort"]), reverse=True)
    return runs, warnings

@app.get("/")
def index():
    runs, warnings = load_runs()
    query = request.args.get("q", "").strip()
    filtered = [r for r in runs if query.casefold() in (r["project"] + " " + r["folder"] + " " + r["group"]).casefold()]
    stats = {"total": len(runs), "completed": sum(r["state"] == "COMPLETED" for r in runs),
             "collected": sum(r["state"] == "COLLECTED" for r in runs),
             "other": sum(r["state"] not in ("COMPLETED", "COLLECTED") for r in runs)}
    return render_template("index.html", runs=filtered, stats=stats, warnings=warnings, query=query)

def run_file(folder, name):
    path = (folder / name).resolve()
    if not path.is_relative_to(folder.resolve()):
        raise ValueError("Tệp nằm ngoài thư mục lượt chạy")
    return path

@app.get("/runs/<int:group_id>/<name>")
def run_detail(group_id, name):
    if not 0 <= group_id < len(RUN_ROOTS) or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        abort(404)
    parent = RUN_ROOTS[group_id][1].resolve()
    folder = (parent / name).resolve()
    if not folder.is_relative_to(parent) or not folder.is_dir():
        abort(404)
    warnings, rows = [], []
    try:
        manifest = json.loads(run_file(folder, "manifest.json").read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("Manifest không hợp lệ")
        path = run_file(folder, "ai_results.json")
        if path.exists():
            rows = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
                raise ValueError("Danh sách kết quả không hợp lệ")
        else:
            warnings.append("Lượt này chưa có ai_results.json; có thể mới thu thập hoặc chưa tới bước phân tích.")
    except (OSError, ValueError) as exc:
        return render_template("run.html", manifest={}, name=name, warnings=[str(exc)],
            entries=[], selected=None, source_lines=[], source_note="", stage2=None,
            group_id=group_id, status="", verdict="", total=0), 400
    status = request.args.get("status", "AI")
    verdict = request.args.get("verdict", "")
    entries = []
    for idx, row in enumerate(rows):
        s = row.get("processing_status", "UNSPECIFIED")
        if status == "AI" and s not in ("AI_PROPOSED", "ANALYZED"):
            continue
        if status not in ("", "AI") and s != status:
            continue
        label = row.get("ai_verdict") or row.get("verdict", "UNKNOWN")
        if verdict and label != verdict:
            continue
        entries.append({"idx": idx, "row": row, "label": label,
                        "filename": row.get("component", "Không rõ file").split("/")[-1]})
    selection = request.args.get("issue", type=int)
    selected = next((e for e in entries if e["idx"] == selection), None)
    if selected is None and entries:
        selected = entries[0]
    source_lines, source_note, stage2 = [], "", None
    if selected:
        row = selected["row"]
        artifact = row.get("artifact_dir")
        if isinstance(artifact, str) and re.fullmatch(r"issue-\d+", artifact):
            try:
                raw = run_file(folder, artifact + "/source.java.txt").read_bytes()
                expected = row.get("source_sha256")
                if expected and hashlib.sha256(raw).hexdigest() != expected:
                    source_note = "Hash mã nguồn không khớp kết quả: không hiển thị bằng chứng từ tệp này."
                else:
                    evidence = row.get("evidence_lines") or []
                    source_lines = [{"n": n, "text": line, "evidence": n in evidence,
                                     "sink": n == row.get("line")}
                                    for n, line in enumerate(raw.decode("utf-8").splitlines(), 1)]
                    source_note = "Mã nguồn lưu cùng lượt chạy · hash khớp." if expected else "Mã nguồn lưu cùng lượt chạy · bản ghi không có hash để đối chiếu."
                stage_path = run_file(folder, artifact + "/llm_stage2.json")
                if stage_path.exists():
                    data = json.loads(stage_path.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        stage2 = data.get("explanation") or (data.get("model_assessment") or {}).get("explanation")
            except (OSError, ValueError, AttributeError) as exc:
                warnings.append("Không đọc đủ artifact: " + str(exc))
        else:
            source_note = "Bản ghi không có artifact mã nguồn, thường gặp ở cảnh báo bị bỏ qua."
    return render_template("run.html", manifest=manifest, name=name, warnings=warnings,
        entries=entries, selected=selected, source_lines=source_lines, source_note=source_note,
        stage2=stage2, group_id=group_id, status=status, verdict=verdict, total=len(rows))

@app.after_request
def headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

if __name__ == "__main__":
    print("Đọc dữ liệu tại:", ROOT)
    app.run(host="127.0.0.1", port=5050, debug=False)
