"""Store manual assessments separately from saved model results."""

from collections import defaultdict
from contextlib import closing
import csv
from datetime import datetime, timezone
from io import StringIO
import json
import re
import sqlite3
from time import time

from common.ollama_review import VERDICTS, digest

DECISIONS = {
    "confirmed": "Cảnh báo đúng",
    "dismissed": "Cảnh báo nhầm",
    "needs_review": "Cần kiểm tra thêm",
}
REASON_LIMIT = 2000
CITATION_LIMIT = 200
LINE_REF = re.compile(r"(F\d+):([1-9]\d{0,8})")


def case_revision(run, case):
    if case["status"] in VERDICTS:
        return digest({
            "request_sha256": case["item"]["request_sha256"],
            "model_digest": run["manifest"].get("model_digest"),
            "assessment": case["assessment"],
        })


def review_fields(form, visible_lines):
    decision = form.get("decision", "")
    reason = form.get("reason", "").strip()
    citation_input = form.get("citations", "").strip()
    if decision not in DECISIONS:
        raise ValueError("Chọn một kết luận thẩm định.")
    if not reason or len(reason) > REASON_LIMIT:
        raise ValueError(f"Nhập lý do trong khoảng 1–{REASON_LIMIT} ký tự.")
    if len(citation_input) > CITATION_LIMIT:
        raise ValueError(f"Dẫn chứng tối đa {CITATION_LIMIT} ký tự.")
    refs = {}
    for token in filter(None, re.split(r"[\s,;]+", citation_input)):
        match = LINE_REF.fullmatch(token)
        if not match or (match[1], int(match[2])) not in visible_lines:
            raise ValueError(f"Dẫn chứng {token} phải trỏ tới một dòng mã đang hiển thị, ví dụ F0:42.")
        file_id, line = match[1], int(match[2])
        refs[file_id, line] = {"file_id": file_id, "line": line}
    return decision, reason, list(refs.values())


def append_review(database, run_name, issue_id, revision, decision, reason, citations):
    database.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("""CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY,
            run_name TEXT NOT NULL,
            issue_id TEXT NOT NULL,
            case_revision TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL,
            citations TEXT NOT NULL,
            saved_at INTEGER NOT NULL
        )""")
        db.execute("CREATE INDEX IF NOT EXISTS reviews_by_run ON reviews(run_name, id)")
        db.execute(
            """INSERT INTO reviews (run_name, issue_id, case_revision, decision, reason, citations, saved_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (run_name, issue_id, revision, decision, reason, json.dumps(citations), int(time())),
        )


def history_for_run(database, run, cases):
    if not database.exists():
        return {}
    revisions = {case["key"]: case_revision(run, case) for case in cases}
    history = defaultdict(list)
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        if not db.execute("SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'reviews'").fetchone():
            return {}
        rows = db.execute("SELECT * FROM reviews WHERE run_name = ? ORDER BY id DESC", (run["name"],))
        for row in rows:
            key = row["issue_id"]
            if revisions.get(key) == row["case_revision"]:
                history[key].append({**dict(row), "citations": json.loads(row["citations"])})
    return history


def citation_text(citations):
    return ", ".join(f"{ref['file_id']}:{ref['line']}" for ref in citations)


def csv_cell(value):
    text = "" if value is None else str(value)
    # Keep untrusted text from being treated as a spreadsheet formula.
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def csv_for_run(run, cases, history):
    output = StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(("run", "cwe", "issue_id", "java_file", "sonarqube_rule", "start_line", "end_line",
                     "qwen_verdict", "human_decision", "human_reason", "human_citations", "reviewed_at_utc"))
    for case in cases:
        latest = history.get(case["key"], [{}])[0]
        alert = case["alert"]
        reviewed_at = latest.get("saved_at")
        timestamp = datetime.fromtimestamp(reviewed_at, timezone.utc).isoformat() if reviewed_at is not None else ""
        writer.writerow([csv_cell(value) for value in (
            run["name"], run["cwe"], case["key"], case["file"], alert.get("rule"),
            alert.get("start_line"), alert.get("end_line"), case["assessment"].get("verdict"),
            DECISIONS.get(latest.get("decision")), latest.get("reason"),
            citation_text(latest.get("citations", [])), timestamp,
        )])
    return "\ufeff" + output.getvalue()
