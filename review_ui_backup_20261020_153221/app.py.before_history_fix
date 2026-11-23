"""Local run browser with separate, versioned human review records."""
import json
import csv
import io
import hashlib
import re
import secrets
import os
import fcntl
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo
from flask import Flask, render_template, request, abort, session, redirect, url_for, flash, Response

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config.update(MAX_CONTENT_LENGTH=32768, SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_HTTPONLY=True, TRUSTED_HOSTS=["127.0.0.1", "localhost"])
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

def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

def review_data(folder):
    path = run_file(folder, "reviews_ui.json")
    if not path.exists():
        return {"version": 1, "history": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(data, dict) or data.get("version") != 1
            or not isinstance(data.get("history"), list)
            or any(not isinstance(r, dict) for r in data["history"])):
        raise ValueError("Tệp thẩm định không hợp lệ; giữ nguyên để kiểm tra.")
    return data

def review_key(manifest, row):
    return fingerprint({"analysis_id": manifest.get("analysis_id"), "row": row})

def matching_reviews(data, key):
    return [r for r in data["history"] if r.get("record_key") == key]

def check_review_source(folder, manifest, row):
    if manifest.get("state") != "COMPLETED" or not manifest.get("analysis_id"):
        raise ValueError("Chỉ thẩm định lượt đã hoàn tất và có analysis_id.")
    if row.get("processing_status") not in ("AI_PROPOSED", "ANALYZED", "ABSTAINED"):
        raise ValueError("Bản ghi này chưa hỗ trợ thẩm định trên giao diện.")
    artifact = row.get("artifact_dir", "")
    if not isinstance(artifact, str) or not re.fullmatch(r"issue-\d+", artifact):
        raise ValueError("Chưa có mã nguồn để thẩm định.")
    raw = run_file(folder, artifact + "/source.java.txt").read_bytes()
    if hashlib.sha256(raw).hexdigest() != row.get("source_sha256"):
        raise ValueError("Mã nguồn thiếu hash hoặc hash không khớp; chưa cho phép lưu.")

@app.before_request
def csrf_check():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(32)
    if request.method == "POST":
        supplied = request.form.get("csrf", "")
        if not secrets.compare_digest(supplied, session["csrf"]):
            abort(400, "Phiên đã đổi hoặc biểu mẫu không hợp lệ. Tải lại trang rồi thử lại.")

@app.post("/runs/<int:group_id>/<name>/review/<int:idx>")
def save_review(group_id, name, idx):
    if not 0 <= group_id < len(RUN_ROOTS) or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        abort(404)
    parent = RUN_ROOTS[group_id][1].resolve()
    folder = (parent / name).resolve()
    if not folder.is_relative_to(parent) or not folder.is_dir():
        abort(404)
    try:
        with run_file(folder, "reviews_ui.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            manifest = json.loads(run_file(folder, "manifest.json").read_text(encoding="utf-8"))
            rows = json.loads(run_file(folder, "ai_results.json").read_text(encoding="utf-8"))
            if not isinstance(rows, list) or idx >= len(rows):
                raise ValueError("Không tìm thấy cảnh báo.")
            row = rows[idx]
            check_review_source(folder, manifest, row)
            key = review_key(manifest, row)
            data = review_data(folder)
            history = matching_reviews(data, key)
            if request.form.get("record_key") != key or request.form.get("revision") != str(len(history)):
                abort(409, "Dữ liệu hoặc thẩm định đã thay đổi. Tải lại trang trước khi lưu.")
            verdict = request.form.get("reviewed_verdict", "")
            notes = request.form.get("notes", "").strip()
            reviewer = request.form.get("reviewer", "").strip()
            if verdict not in ("LIKELY_TP", "LIKELY_FP", "UNKNOWN"):
                raise ValueError("Hãy chọn kết luận thẩm định.")
            if not 1 <= len(notes) <= 5000 or not 1 <= len(reviewer) <= 100:
                raise ValueError("Cần tên người thẩm định (tối đa 100 ký tự) và lý do (tối đa 5000 ký tự).")
            data["history"].append({"record_key": key, "revision": len(history)+1,
                "analysis_id": manifest["analysis_id"], "issue_id": row.get("issue_id"),
                "component": row.get("component"), "line": row.get("line"),
                "source_sha256": row.get("source_sha256"),
                "ai_verdict": row.get("ai_verdict") or row.get("verdict"),
                "reviewed_verdict": verdict, "review_status": "REVIEWED",
                "notes": notes, "reviewer": reviewer,
                "saved_at": datetime.now(timezone.utc).isoformat()})
            dest = run_file(folder, "reviews_ui.json")
            temp = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=folder, delete=False) as f:
                    temp = Path(f.name)
                    json.dump(data, f, ensure_ascii=False, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(temp, dest)
            finally:
                if temp is not None and temp.exists():
                    temp.unlink()
        flash(f"Đã lưu thẩm định: {row.get('component', '')} · dòng {row.get('line', '—')}. Kết quả AI gốc được giữ nguyên." + (" Bản ghi vừa lưu không còn thuộc bộ lọc Chưa thẩm định." if request.form.get("review") == "PENDING" else ""))
        return redirect(url_for("run_detail", group_id=group_id, name=name, issue=idx, **filter_values(request.form)) + "#review", code=303)
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        abort(400, str(exc))

def filter_values(values):
    status = values.get("status", "AI")
    verdict = values.get("verdict", "")
    review = values.get("review", "")
    return {
        "status": status if status in ("", "AI", "ABSTAINED", "ERROR", "SKIPPED") else "AI",
        "verdict": verdict if verdict in ("", "LIKELY_TP", "LIKELY_FP", "UNKNOWN") else "",
        "review": review if review in ("", "REVIEWED", "PENDING", "UNAVAILABLE") else "",
    }


def build_entries(folder, manifest, rows, data):
    entries = []
    for idx, row in enumerate(rows):
        history = matching_reviews(data, review_key(manifest, row))
        latest = history[-1] if history else None
        block = ""
        try:
            check_review_source(folder, manifest, row)
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            block = str(exc)
        # A saved review is current only when its exact record and source still match.
        state = "UNAVAILABLE" if block else ("REVIEWED" if latest else "PENDING")
        entries.append({"idx": idx, "row": row,
            "label": row.get("ai_verdict") or row.get("verdict", "UNKNOWN"),
            "filename": str(row.get("component") or "Không rõ file").split("/")[-1],
            "review_state": state, "latest": latest, "review_block": block})
    return entries


def filter_entries(entries, filters):
    status, verdict, review = (filters[k] for k in ("status", "verdict", "review"))
    return [e for e in entries
        if (not status or (e["row"].get("processing_status") in ("AI_PROPOSED", "ANALYZED")
                           if status == "AI" else e["row"].get("processing_status") == status))
        and (not verdict or e["label"] == verdict)
        and (not review or e["review_state"] == review)]


def csv_cell(value):
    text = "" if value is None else str(value)
    # Keep untrusted text from being treated as a spreadsheet formula.
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


@app.get("/runs/<int:group_id>/<name>/export.csv")
def export_csv(group_id, name):
    if not 0 <= group_id < len(RUN_ROOTS) or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        abort(404)
    parent = RUN_ROOTS[group_id][1].resolve()
    folder = (parent / name).resolve()
    if not folder.is_relative_to(parent) or not folder.is_dir():
        abort(404)
    try:
        manifest = json.loads(run_file(folder, "manifest.json").read_text(encoding="utf-8"))
        rows = json.loads(run_file(folder, "ai_results.json").read_text(encoding="utf-8"))
        if not isinstance(manifest, dict) or not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
            raise ValueError("Dữ liệu lượt chạy không hợp lệ.")
        entries = filter_entries(build_entries(folder, manifest, rows, review_data(folder)), filter_values(request.args))
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        abort(400, str(exc))
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["run", "analysis_id", "issue_id", "component", "line", "rule", "processing_status",
        "ai_verdict", "review_state", "reviewed_verdict", "reviewer", "review_notes", "reviewed_at",
        "review_revision", "review_block", "source_sha256", "ai_explanation"])
    for e in entries:
        r, latest = e["row"], e["latest"] or {}
        writer.writerow([csv_cell(v) for v in [name, manifest.get("analysis_id"), r.get("issue_id"),
            r.get("component"), r.get("line"), r.get("rule"), r.get("processing_status"), e["label"],
            e["review_state"], latest.get("reviewed_verdict"), latest.get("reviewer"), latest.get("notes"),
            latest.get("saved_at"), latest.get("revision"), e["review_block"], r.get("source_sha256"), r.get("explanation")]])
    return Response("\ufeff" + output.getvalue(), content_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="review_{name}.csv"'})


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
            group_id=group_id, status="", verdict="", review="", review_stats={}, review_error="Dữ liệu lỗi", total=0), 400
    filters = filter_values(request.args)
    status, verdict, review = (filters[k] for k in ("status", "verdict", "review"))
    review_error = ""
    try:
        data = review_data(folder)
    except (OSError, ValueError, TypeError) as exc:
        review_error = "Không đọc được thẩm định: " + str(exc)
        warnings.append(review_error)
        data = {"version": 1, "history": []}
    all_entries = build_entries(folder, manifest, rows, data)
    if review_error:
        for e in all_entries:
            e["review_state"] = "UNAVAILABLE"
            e["review_block"] = review_error
    review_stats = Counter(e["review_state"] for e in all_entries)
    entries = filter_entries(all_entries, filters)
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
    history, record_key, review_block = [], "", ""
    if selected:
        try:
            record_key = review_key(manifest, selected["row"])
            history = matching_reviews(data, record_key)
            if review_error:
                raise ValueError(review_error)
            check_review_source(folder, manifest, selected["row"])
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            review_block = str(exc)
    return render_template("run.html", history=history, record_key=record_key, review_block=review_block,
        manifest=manifest, name=name, warnings=warnings,
        entries=entries, selected=selected, source_lines=source_lines, source_note=source_note,
        stage2=stage2, group_id=group_id, status=status, verdict=verdict, review=review,
        review_stats=review_stats, review_error=review_error, total=len(rows))

@app.after_request
def headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

if __name__ == "__main__":
    print("Đọc dữ liệu tại:", ROOT)
    app.run(host="127.0.0.1", port=5050, debug=False)
