"""Browse saved SonarQube, Java, Joern and Qwen evidence on localhost."""

from datetime import datetime
from pathlib import Path
from secrets import compare_digest, token_urlsafe
import sqlite3
from zoneinfo import ZoneInfo

from flask import Flask, Response, abort, flash, redirect, render_template, request, session, url_for

from . import human_reviews as review
from . import run_data as data


def create_app(runs_root=None, reviews_db=None):
    app = Flask(__name__)
    app.config.update(
        TRUSTED_HOSTS=["127.0.0.1", "localhost"],
        SECRET_KEY=token_urlsafe(),
        SESSION_COOKIE_NAME="security_review_session",
        SESSION_COOKIE_SAMESITE="Strict",
        MAX_CONTENT_LENGTH=16384,
    )
    root = Path(runs_root or Path(__file__).resolve().parents[1] / "runs").resolve()
    database = Path(reviews_db or Path(__file__).parent / "instance" / "reviews.sqlite3").absolute()
    states = {*data.VERDICTS, "pending", "error"}
    labels = {"LIKELY_TP": "LIKELY_TP", "LIKELY_FP": "LIKELY_FP", "UNKNOWN": "UNKNOWN",
              "pending": "Chờ phản hồi", "error": "Lỗi kết quả"}

    @app.template_filter()
    def local_time(timestamp):
        return datetime.fromtimestamp(timestamp, ZoneInfo("Asia/Ho_Chi_Minh")).strftime("%d/%m/%Y %H:%M")

    @app.after_request
    def local_response(response):
        if response.mimetype == "text/html":
            response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/")
    def index():
        runs = data.list_runs(root)
        cwe = request.args.get("cwe", "")
        query = request.args.get("q", "").strip()
        visible = [run for run in runs if (not cwe or run["cwe"] == cwe)
                   and (not query or query.casefold() in run["name"].casefold())]
        return render_template("index.html", runs=visible, cwe=cwe, query=query,
                               categories=data.CATEGORIES, all_count=len(runs),
                               complete=sum(run["saved"] == run["total"] for run in runs),
                               incomplete=sum(run["saved"] < run["total"] for run in runs))

    @app.route("/runs/<name>", methods=["GET", "POST"])
    def run_detail(name):
        run = data.run_info(root, name)
        if run is None:
            abort(404)
        cases, summary = data.load_cases(run)
        status = request.args.get("status", "")
        status = status if status in states else ""
        filtered = [case for case in cases if not status or case["status"] == status]
        number = request.args.get("case", type=int)
        if (request.method == "POST" and number is None) or (number is not None and not 1 <= number <= len(cases)):
            abort(404)
        case = cases[number - 1] if number is not None else next(iter(filtered), None)
        prompt = data.prompt_for(run, case) if case else {}
        sources = data.request_sources(prompt)
        visible_lines = {(source["id"], n) for source in sources for n, _ in source["lines"]}
        revision = review.case_revision(run, case) if case else None
        review_error, response_status = "", 200
        if request.method == "POST":
            token = session.get("review_token")
            submitted_token = request.form.get("review_token", "")
            if not token or not compare_digest(token.encode(), submitted_token.encode()):
                abort(400)
            if not revision or request.form.get("case_revision") != revision:
                abort(409, "Cảnh báo đã thay đổi. Tải lại trang và kiểm tra kết quả mới nhất.")
            try:
                decision, reason, citations = review.review_fields(request.form, visible_lines)
                review.append_review(database, name, case["key"], revision, decision, reason, citations)
            except ValueError as error:
                review_error, response_status = str(error), 400
            except (OSError, sqlite3.Error):
                app.logger.exception("Cannot save manual review")
                review_error, response_status = "Chưa lưu được thẩm định. Hãy thử lại.", 503
            else:
                flash("Đã lưu thẩm định.", "human-review")
                return redirect(url_for("run_detail", name=name, case=number, status=status or None,
                                        compare=request.args.get("compare"), _anchor="human-review"), code=303)

        history = review.history_for_run(database, run, cases)
        case_history = history.get(case["key"], []) if case else []
        latest = case_history[0] if case_history else {}
        if revision and "review_token" not in session:
            session["review_token"] = token_urlsafe()
        review_form = request.form if review_error else {
            "decision": latest.get("decision", ""),
            "reason": latest.get("reason", ""),
            "citations": review.citation_text(latest.get("citations", [])),
        }
        comparable = [other for other in data.list_runs(root)
                      if other["name"] != name and other["cwe"] == run["cwe"]
                      and data.warning_scope(other) == data.warning_scope(run)]
        comparison = next((other for other in comparable if other["name"] == request.args.get("compare")), None)
        comparison_totals, previous = None, None
        if comparison:
            earlier, earlier_summary = data.load_cases(comparison)
            comparison_totals = data.totals(earlier, earlier_summary)
            if case:
                previous = next((entry for entry in earlier if entry["key"] == case["key"]), None)
        groups, facts = data.evidence_view(prompt)
        return render_template(
            "run.html", run=run, cases=filtered, case=case, status=status,
            counts=data.totals(cases, summary), labels=labels, sources=sources,
            groups=groups, facts=facts, visible_lines=visible_lines,
            comparable=comparable, comparison=comparison, comparison_totals=comparison_totals,
            previous=previous, prompt=prompt, sonar=summary.get("sonarqube") or {},
            history=history, case_history=case_history, latest_review=latest, decisions=review.DECISIONS,
            review_form=review_form, review_error=review_error, review_revision=revision,
            reason_limit=review.REASON_LIMIT, citation_limit=review.CITATION_LIMIT,
        ), response_status

    @app.get("/runs/<name>/export.csv")
    def export_csv(name):
        run = data.run_info(root, name)
        if run is None:
            abort(404)
        cases, _ = data.load_cases(run)
        history = review.history_for_run(database, run, cases)
        return Response(
            review.csv_for_run(run, cases, history), content_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="review_{name}.csv"',
                     "Cache-Control": "no-store"},
        )

    return app


app = create_app()
