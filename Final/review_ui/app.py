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
import job_runner
import report_export
import priority_queue
import patch_ui
import sys
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

def decision_view(row):
    """Read-only presentation; never mutate the row used by review_key."""
    separated = bool(row.get("decision_origin") or "combined_verdict" in row)
    ai = row.get("ai_verdict")
    if not separated and "ai_verdict" not in row:
        ai = row.get("verdict")
    combined = row.get("combined_verdict") or row.get("verdict") or "UNKNOWN"
    origin = row.get("decision_origin") or "LEGACY_PIPELINE"
    def original(key):
        if "ai_" + key in row:
            return row["ai_" + key]
        return None if separated else row.get(key)
    return {"ai_verdict": ai, "combined_verdict": combined,
            "origin": origin,
            "origin_label": {"STATIC_GUARD": "Kiểm tra bằng luật",
                             "AI_PIPELINE": "Nhánh xử lý AI",
                             "STATIC_GUARD_CONFLICT": "Mâu thuẫn với kiểm tra nhánh thoát",
                             "STATIC_NUMERIC_CONFLICT": "Mâu thuẫn với kiểm tra chuyển kiểu số",
                             "LEGACY_PIPELINE": "Pipeline cũ (chưa ghi riêng nguồn quyết định)"}.get(origin, origin),
            "ai_explanation": original("explanation"),
            "ai_evidence_lines": original("evidence_lines"),
            "ai_missing_context": original("missing_context"),
            "ai_decision_basis": original("decision_basis")}

def explanation_view(row, stage_data):
    """Present saved stages with provenance; do not recompute or edit verdicts."""
    audit = row.get("source_audit_facts")
    audit = audit if isinstance(audit, dict) else {}
    stage = stage_data if isinstance(stage_data, dict) else {}
    facts = stage.get("model_assessment")
    facts = facts if isinstance(facts, dict) else {}
    text = stage.get("explanation") or facts.get("explanation")
    stage_verdict = stage.get("verdict")
    final_verdict = decision_view(row)["combined_verdict"]
    source_lines = sorted({e["line"] for e in audit.get("source_evidence", [])
                           if isinstance(e, dict) and type(e.get("line")) is int})
    return {
        "stage_text": text if isinstance(text, str) else None,
        "stage_verdict": stage_verdict,
        "stage_error": stage.get("error_kind"),
        "stage_lines": stage.get("evidence_lines") or facts.get("evidence_lines") or [],
        "source_text": audit.get("explanation"),
        "source_kind": audit.get("source_kind"),
        "source_lines": source_lines,
        "source_changed": bool(audit and facts.get("source_control") and
            ((facts["source_control"] == "CONFIRMED" and audit.get("source_kind") == "PARAMETER_ONLY") or
             (facts["source_control"] == "UNRESOLVED" and audit.get("source_kind") == "EXTERNAL_READ"))),
        "verdict_changed": bool(stage_verdict and stage_verdict != final_verdict),
        "sql_effect": row.get("sql_effect_reused") or facts.get("sql_effect"),
    }

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
                            counts[decision_view(r)["ai_verdict"] or "NOT_RECORDED"] += 1
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
                "ai_verdict": decision_view(row)["ai_verdict"],
                "combined_verdict": decision_view(row)["combined_verdict"],
                "decision_origin": decision_view(row)["origin"],
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
            "label": decision_view(row)["combined_verdict"],
            "decision": decision_view(row),
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
        "review_revision", "review_block", "source_sha256", "ai_explanation",
        "combined_verdict", "decision_origin", "combined_explanation", "ai_evidence_lines",
        "combined_evidence_lines", "ai_missing_context", "combined_missing_context"])
    for e in entries:
        r, latest = e["row"], e["latest"] or {}
        writer.writerow([csv_cell(v) for v in [name, manifest.get("analysis_id"), r.get("issue_id"),
            r.get("component"), r.get("line"), r.get("rule"), r.get("processing_status"), e["decision"]["ai_verdict"],
            e["review_state"], latest.get("reviewed_verdict"), latest.get("reviewer"), latest.get("notes"),
            latest.get("saved_at"), latest.get("revision"), e["review_block"], r.get("source_sha256"), e["decision"]["ai_explanation"],
            e["label"], e["decision"]["origin"], r.get("explanation"),
            json.dumps(e["decision"]["ai_evidence_lines"], ensure_ascii=False),
            json.dumps(r.get("evidence_lines"), ensure_ascii=False),
            json.dumps(e["decision"]["ai_missing_context"], ensure_ascii=False),
            json.dumps(r.get("missing_context"), ensure_ascii=False)]])
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
                    stage_data = json.loads(stage_path.read_text(encoding="utf-8"))
                    if isinstance(stage_data, dict):
                        stage2 = stage_data
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
        stage2=stage2, explanation=explanation_view(selected["row"], stage2) if selected else {}, group_id=group_id, status=status, verdict=verdict, review=review,
        review_stats=review_stats, review_error=review_error, total=len(rows))

def statistics_data(manifest, entries):
    """Count current rows, not manifest verdict totals or old review revisions."""
    rules = {
        "findsecbugs:SQL_INJECTION_JDBC": "SQL Injection",
        "findbugs:SQL_INJECTION_JDBC": "SQL Injection", "java:S3649": "SQL Injection",
        "findsecbugs:PATH_TRAVERSAL_IN": "Path Traversal",
        "findsecbugs:COMMAND_INJECTION": "Command Injection",
    }
    groups = {}
    for name in ("SQL Injection", "Path Traversal", "Command Injection", "Khác"):
        groups[name] = {"name": name, "total": 0, "proposed": 0,
                        "ai": Counter(), "system": Counter(), "human": Counter()}
    statuses, reviews, origins = Counter(), Counter(), Counter()
    for entry in entries:
        row, decision = entry["row"], entry["decision"]
        group = groups[rules.get(row.get("rule"), "Khác")]
        group["total"] += 1
        status = row.get("processing_status") or "UNSPECIFIED"
        statuses[status] += 1
        reviews[entry["review_state"]] += 1
        if status in ("AI_PROPOSED", "ANALYZED"):
            group["proposed"] += 1
            for key, value in (("ai", decision["ai_verdict"]),
                               ("system", decision["combined_verdict"])):
                group[key][value if value in ("LIKELY_TP", "LIKELY_FP", "UNKNOWN") else "NOT_RECORDED"] += 1
            origins[decision["origin_label"]] += 1
        if entry["review_state"] == "REVIEWED" and entry["latest"]:
            value = entry["latest"].get("reviewed_verdict")
            group["human"][value if value in ("LIKELY_TP", "LIKELY_FP", "UNKNOWN") else "NOT_RECORDED"] += 1
    duration = None
    try:
        start = datetime.fromisoformat(manifest["started_at"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(manifest["finished_at"].replace("Z", "+00:00"))
        if start.tzinfo and end.tzinfo and end >= start:
            seconds = round((end-start).total_seconds())
            duration = f"{seconds // 3600} giờ {(seconds % 3600) // 60} phút {seconds % 60} giây"
    except (KeyError, ValueError, TypeError, AttributeError):
        pass
    return {"groups": list(groups.values()), "statuses": statuses, "reviews": reviews,
            "origins": origins, "duration": duration, "total": len(entries),
            "proposed": sum(g["proposed"] for g in groups.values())}


@app.get("/runs/<int:group_id>/<name>/statistics")
def run_statistics(group_id, name):
    if not 0 <= group_id < len(RUN_ROOTS) or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        abort(404)
    parent = RUN_ROOTS[group_id][1].resolve()
    folder = (parent / name).resolve()
    if not folder.is_relative_to(parent) or not folder.is_dir():
        abort(404)
    warnings = []
    try:
        manifest = json.loads(run_file(folder, "manifest.json").read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("Manifest không hợp lệ")
        path = run_file(folder, "ai_results.json")
        rows = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
        if not path.exists():
            warnings.append("Chưa có kết quả phân tích; số 0 bên dưới không có nghĩa mã an toàn.")
        if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
            raise ValueError("Danh sách kết quả không hợp lệ")
        review_error = ""
        try:
            data = review_data(folder)
        except (OSError, ValueError, TypeError) as exc:
            review_error = "Không đọc được thẩm định: " + str(exc)
            warnings.append(review_error)
            data = {"version": 1, "history": []}
        entries = build_entries(folder, manifest, rows, data)
        if review_error:
            for entry in entries:
                entry["review_state"] = "UNAVAILABLE"
        if manifest.get("result_count") is not None and manifest["result_count"] != len(rows):
            warnings.append("Số bản ghi khác manifest; thống kê đang tính từ ai_results.json hiện có.")
        if manifest.get("state") != "COMPLETED":
            warnings.append("Lượt chưa hoàn tất thành công: đây chỉ là dữ liệu hiện có, không phải kết quả cuối.")
        return render_template("statistics.html", name=name, group_id=group_id,
                               manifest=manifest, warnings=warnings,
                               stats=statistics_data(manifest, entries))
    except (OSError, ValueError, TypeError) as exc:
        return str(exc), 400


@app.get("/runs/<int:group_id>/<name>/report", defaults={"fmt": "preview"})
@app.get("/runs/<int:group_id>/<name>/report.<fmt>")
def run_report(group_id, name, fmt):
    if fmt not in ("preview", "html", "pdf"):
        abort(404)
    if not 0 <= group_id < len(RUN_ROOTS) or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        abort(404)
    parent = RUN_ROOTS[group_id][1].resolve()
    folder = (parent / name).resolve()
    if not folder.is_relative_to(parent) or not folder.is_dir():
        abort(404)
    try:
        # The shared lock gives the export one consistent revision of UI reviews.
        with run_file(folder, "reviews_ui.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            manifest_raw = run_file(folder, "manifest.json").read_bytes()
            result_raw = run_file(folder, "ai_results.json").read_bytes()
            manifest, rows = json.loads(manifest_raw), json.loads(result_raw)
            if not isinstance(manifest, dict) or not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
                raise ValueError("Dữ liệu lượt chạy không hợp lệ.")
            data = review_data(folder)
            hashes = {"manifest.json": report_export.sha(manifest_raw),
                      "ai_results.json": report_export.sha(result_raw)}
            review_path = run_file(folder, "reviews_ui.json")
            if review_path.exists():
                hashes["reviews_ui.json"] = report_export.sha(review_path.read_bytes())
            report = report_export.prepare(sys.modules[__name__], folder, name, manifest, rows, data, hashes)
        if fmt == "pdf":
            try:
                body = report_export.to_pdf(report)
            except ModuleNotFoundError:
                abort(503, "Thiếu thư viện xuất PDF. Cài requirements-report.txt trong gói ui_report_v1 rồi mở lại giao diện.")
            response = Response(body, content_type="application/pdf")
        else:
            css = (Path(__file__).parent / "static" / "report.css").read_text(encoding="utf-8")
            body = render_template("report.html", report=report, css=css, toolbar=fmt == "preview", group_id=group_id)
            response = Response(body, content_type="text/html; charset=utf-8")
            response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
        if fmt != "preview":
            response.headers["Content-Disposition"] = f'attachment; filename="report_{name}.{fmt}"'
        return response
    except FileNotFoundError:
        abort(409, "Chưa đủ file kết quả để xuất báo cáo. Mở lượt đã phân tích xong.")
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        abort(409, "Chưa thể xuất báo cáo: " + str(exc))


@app.after_request
def headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.get("/scan")
def scan_home():
    error = None
    try:
        config = job_runner.scan_config(ROOT)
    except ValueError as exc:
        config, error = None, str(exc)
    return render_template("scan.html", config=config, error=error,
                           active=job_runner.active_id(ROOT))

@app.post("/scan/start")
def scan_start():
    try:
        job_id = job_runner.start_scan(ROOT, request.form.get("project", ""),
                                      request.form.get("sonar_token", ""))
    except (OSError, ValueError) as exc:
        flash(str(exc))
        return redirect(url_for("scan_home"), code=303)
    return redirect(url_for("analysis_job", job_id=job_id), code=303)

@app.get("/analysis")
def analysis_home():
    collections = job_runner.catalog(ROOT)
    selected = next((c for c in collections if c["key"] == request.args.get("collection")), None)
    if selected is None and collections:
        selected = collections[0]
    return render_template("analysis.html", collections=collections, selected=selected,
                           jobs=job_runner.list_jobs(ROOT))

@app.post("/analysis/start")
def analysis_start():
    try:
        job_id = job_runner.start_job(ROOT, request.form.get("collection", ""),
                                     request.form.getlist("components"), request.form.get("mode", ""))
    except (OSError, ValueError) as exc:
        flash(str(exc))
        return redirect(url_for("analysis_home", collection=request.form.get("collection", "")), code=303)
    return redirect(url_for("analysis_job", job_id=job_id), code=303)

@app.get("/analysis/jobs/<job_id>")
def analysis_job(job_id):
    try:
        job = job_runner.get_job(ROOT, job_id)
    except (OSError, ValueError, KeyError):
        abort(404)
    return render_template("job.html", job=job)

priority_queue.register(app, sys.modules[__name__])
patch_ui.register(app, sys.modules[__name__])

if __name__ == "__main__":
    print("Đọc dữ liệu tại:", ROOT)
    app.run(host="127.0.0.1", port=5050, debug=False)
