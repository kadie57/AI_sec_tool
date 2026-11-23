"""Operational work queue from saved decisions, not a severity or CVSS model."""
import csv
import io
import json
import re
from flask import abort, render_template, request, Response

POLICY_VERSION = "review-work-queue-v1"
VERDICTS = {"LIKELY_TP", "LIKELY_FP", "UNKNOWN"}
GROUPS = (
    ("act", "1 · Xử lý trước", "Cảnh báo có cơ sở là lỗi thật: sửa sau thẩm định, hoặc thẩm định sớm nếu mới là đề xuất."),
    ("clarify", "2 · Cần làm rõ", "Thiếu bằng chứng, có mâu thuẫn hoặc kết quả chưa đủ điều kiện sử dụng."),
    ("verify_fp", "3 · Xác minh cảnh báo giả", "Hệ thống đề xuất LIKELY_FP nhưng chưa có thẩm định hợp lệ."),
    ("reviewed_fp", "4 · Đã thẩm định cảnh báo giả", "Theo dõi khi mã nguồn hoặc ngữ cảnh thay đổi; không tự đóng cảnh báo SonarQube."),
    ("outside", "Ngoài phạm vi tự động", "Bị bỏ qua hoặc rule chưa hỗ trợ. Cần xem riêng trong SonarQube."),
)


def classify(entry):
    row, decision = entry["row"], entry["decision"]
    human = entry.get("latest") or {}
    valid_review = entry["review_state"] == "REVIEWED" and human.get("reviewed_verdict") in VERDICTS
    label = human["reviewed_verdict"] if valid_review else entry["label"]
    # Skipped rows must never acquire a reassuring priority from a default label.
    if row.get("processing_status") == "SKIPPED" or row.get("error_kind") == "UNSUPPORTED_RULE":
        group, basis, reason, action = (
            "outside", "Trạng thái xử lý", "Bản ghi chưa được nhánh phân tích hỗ trợ xử lý.",
            "Mở cảnh báo trong SonarQube để kiểm tra riêng.")
    elif entry["review_state"] == "UNAVAILABLE":
        group, basis, reason, action = (
            "clarify", "Tình trạng dữ liệu", entry.get("review_block") or "Chưa đủ dữ liệu để sử dụng kết luận.",
            "Kiểm tra lượt chạy và mã nguồn; chưa dùng thẩm định cũ để hạ ưu tiên.")
    elif entry["review_state"] == "REVIEWED" and not valid_review:
        group, basis, reason, action = (
            "clarify", "Tình trạng thẩm định", "Bản thẩm định mới nhất không có nhãn hợp lệ.",
            "Mở bằng chứng và lưu lại thẩm định hợp lệ.")
    elif valid_review:
        basis = "Thẩm định hợp lệ"
        if label == "LIKELY_TP":
            group, reason, action = "act", "Người thẩm định đã xác nhận có cơ sở là cảnh báo đúng.", "Lập phương án sửa, kiểm thử và quét lại sau khi sửa."
        elif label == "LIKELY_FP":
            group, reason, action = "reviewed_fp", "Người thẩm định đã xác nhận có cơ sở là cảnh báo giả.", "Giữ bằng chứng; xem lại khi mã nguồn hoặc ngữ cảnh thay đổi."
        else:
            group, reason, action = "clarify", "Người thẩm định vẫn chưa đủ cơ sở kết luận.", "Bổ sung thông tin còn thiếu và thẩm định lại."
    elif row.get("error_kind") or row.get("processing_status") not in ("AI_PROPOSED", "ANALYZED"):
        group, basis, reason, action = (
            "clarify", "Trạng thái xử lý", "Phân tích bị lỗi hoặc chưa tạo được đề xuất đáng sử dụng.",
            "Xem lỗi và bằng chứng trước khi quyết định chạy lại hoặc bổ sung ngữ cảnh.")
    elif label == "LIKELY_TP":
        group, basis, reason, action = (
            "act", "Đề xuất hệ thống", "Hệ thống đề xuất LIKELY_TP; chưa có xác nhận của người thẩm định.",
            "Đọc bằng chứng và thẩm định sớm trước khi lập phương án sửa.")
    elif (row.get("model_static_disagreement") or "CONFLICT" in str(decision.get("origin", ""))
          or (decision.get("ai_verdict") in VERDICTS and decision["ai_verdict"] != label)):
        group, basis, reason, action = (
            "clarify", "Khác biệt giữa các kết quả", "Nhãn AI và hệ thống khác nhau hoặc có mâu thuẫn được ghi nhận.",
            "Đối chiếu cả hai giải thích với mã nguồn, rồi lưu thẩm định.")
    elif label == "LIKELY_FP":
        group, basis, reason, action = (
            "verify_fp", "Đề xuất hệ thống", "Mới có đề xuất LIKELY_FP, chưa được người thẩm định xác nhận.",
            "Kiểm tra cơ chế bảo vệ tại đúng thao tác và lưu kết luận.")
    else:
        group, basis, reason, action = (
            "clarify", "Đề xuất chưa đủ cơ sở", "Kết quả còn UNKNOWN hoặc chưa có nhãn hợp lệ.",
            "Xem thông tin còn thiếu, bổ sung ngữ cảnh và thẩm định.")
    return {"entry": entry, "group": group, "basis": basis, "reason": reason,
            "action": action, "human_label": human.get("reviewed_verdict") if valid_review else None,
            "reviewer": human.get("reviewer") if valid_review else None,
            "human_valid": valid_review}


def build_queue(entries):
    groups = [{"key": key, "title": title, "description": desc, "items": []} for key, title, desc in GROUPS]
    lookup = {group["key"]: group for group in groups}
    for entry in entries:
        item = classify(entry)
        lookup[item["group"]]["items"].append(item)
    # Confirmed true positives precede unreviewed proposals in the first group.
    # Other ties use component/line, not an invented risk score.
    def order(item):
        row = item["entry"]["row"]
        line = row.get("line")
        return (0 if item["human_label"] == "LIKELY_TP" else 1,
                str(row.get("component", "")).casefold(), line if type(line) is int else 0, item["entry"]["idx"])
    for group in groups:
        group["items"].sort(key=order)
    return groups


def load_queue(ui, group_id, name):
    if not 0 <= group_id < len(ui.RUN_ROOTS) or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        abort(404)
    parent = ui.RUN_ROOTS[group_id][1].resolve()
    folder = (parent / name).resolve()
    if not folder.is_relative_to(parent) or not folder.is_dir():
        abort(404)
    try:
        manifest = json.loads(ui.run_file(folder, "manifest.json").read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("Manifest không hợp lệ.")
        path = ui.run_file(folder, "ai_results.json")
        rows = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("Danh sách kết quả không hợp lệ.")
        warnings = []
        if not path.exists():
            warnings.append("Chưa có kết quả phân tích. Danh sách trống không có nghĩa mã nguồn an toàn.")
        review_error = None
        try:
            data = ui.review_data(folder)
        except (OSError, ValueError, TypeError) as exc:
            review_error = "Không đọc được thẩm định: " + str(exc)
            data = {"version": 1, "history": []}
            warnings.append(review_error)
        entries = ui.build_entries(folder, manifest, rows, data)
        if review_error:
            for entry in entries:
                entry.update(review_state="UNAVAILABLE", review_block=review_error)
        if manifest.get("state") != "COMPLETED":
            warnings.append("Lượt chưa hoàn tất: các bản ghi đang chờ kiểm tra dữ liệu, chưa dùng để lập phương án sửa.")
        if manifest.get("result_count") is not None and manifest["result_count"] != len(rows):
            warnings.append("Số bản ghi khác manifest; danh sách chỉ gồm kết quả hiện đọc được.")
        return manifest, build_queue(entries), warnings
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        abort(409, "Chưa thể lập danh sách ưu tiên: " + str(exc))


def register(app, ui):
    @app.get("/runs/<int:group_id>/<name>/priority", defaults={"fmt": "html"}, endpoint="run_priority")
    @app.get("/runs/<int:group_id>/<name>/priority.csv", defaults={"fmt": "csv"}, endpoint="run_priority_csv")
    def priority(group_id, name, fmt):
        manifest, groups, warnings = load_queue(ui, group_id, name)
        selected = request.args.get("group", "")
        if selected and selected not in {g["key"] for g in groups}:
            abort(400, "Nhóm ưu tiên không hợp lệ.")
        visible = [g for g in groups if not selected or g["key"] == selected]
        if fmt == "csv":
            output = io.StringIO(newline="")
            writer = csv.writer(output)
            writer.writerow(["run", "analysis_id", "policy_version", "group", "priority_basis", "reason", "next_action",
                             "issue_id", "component", "line", "rule", "processing_status", "error_kind", "ai_verdict",
                             "combined_verdict", "decision_origin", "review_state", "valid_reviewed_verdict", "reviewer", "review_block"])
            for group in visible:
                for item in group["items"]:
                    entry = item["entry"]; row = entry["row"]; decision = entry["decision"]
                    writer.writerow([ui.csv_cell(value) for value in (
                        name, manifest.get("analysis_id"), POLICY_VERSION, group["title"], item["basis"], item["reason"], item["action"],
                        row.get("issue_id"), row.get("component"), row.get("line"), row.get("rule"), row.get("processing_status"),
                        row.get("error_kind"), decision["ai_verdict"], entry["label"], decision["origin"], entry["review_state"],
                        item["human_label"], item["reviewer"], entry["review_block"])])
            return Response("\ufeff" + output.getvalue(), content_type="text/csv; charset=utf-8",
                            headers={"Content-Disposition": f'attachment; filename="priority_{name}.csv"'})
        return render_template("priority.html", name=name, group_id=group_id, manifest=manifest, warnings=warnings,
                               groups=groups, visible=visible, selected=selected, policy_version=POLICY_VERSION,
                               total=sum(len(g["items"]) for g in groups))
