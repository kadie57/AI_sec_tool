"""Read-only local run browser. No pipeline imports, inference, or writes."""
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from flask import Flask, render_template, request

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
    for group, folder in RUN_ROOTS:
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
                    "group": group, "project": m.get("project", "Chưa ghi project"),
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

@app.after_request
def headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

if __name__ == "__main__":
    print("Đọc dữ liệu tại:", ROOT)
    app.run(host="127.0.0.1", port=5050, debug=False)
