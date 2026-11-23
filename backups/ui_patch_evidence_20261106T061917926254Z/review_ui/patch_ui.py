"""Flask routes for retained AI repair proposals."""
from pathlib import PurePosixPath
from flask import abort, flash, redirect, render_template, request, Response, url_for
import patch_core as core


def register(app, ui):
    def context_for(group_id, name, idx):
        try:
            return core.read_context(ui.ROOT, group_id, name, idx)
        except FileNotFoundError:
            abort(404, "Không tìm thấy dữ liệu cảnh báo.")
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            abort(409, str(exc))

    @app.get("/runs/<int:group_id>/<name>/patch/<int:idx>")
    def patch_home(group_id, name, idx):
        context = context_for(group_id, name, idx)
        error, result, selected = "", None, None
        history = core.history(ui.ROOT, context)
        job_id = request.args.get("job")
        selected = next((j for j in history if j["id"] == job_id), None) if job_id else next(iter(history), None)
        if job_id and selected is None:
            abort(404, "Bản đề xuất không thuộc cảnh báo này hoặc đã nằm ngoài 20 lượt gần nhất.")
        if selected and selected["state"] in ("DRAFT_READY", "NEEDS_CONTEXT"):
            try:
                result = core.load_result(ui.ROOT, selected)
            except (OSError, ValueError, TypeError) as exc:
                error = str(exc)
        current = bool(result and context["eligible"] and result.get("binding") == context["binding"])
        config_error = ""
        try:
            config = core.settings()
        except ValueError as exc:
            config, config_error = {"model": "Cấu hình chưa hợp lệ", "timeout": 0}, str(exc)
        return render_template("patch.html", context=context, group_id=group_id, name=name, idx=idx,
            filename=PurePosixPath(context["relative"]).name or str(context["row"].get("component", "")),
            history=history, job=selected, result=result, current=current, error=error,
            config=config, config_error=config_error, running=bool(selected and selected.get("running")))

    @app.post("/runs/<int:group_id>/<name>/patch/<int:idx>/start")
    def patch_start(group_id, name, idx):
        context = context_for(group_id, name, idx)
        try:
            job_id = core.start(ui.ROOT, context, request.form.get("binding", ""))
        except (OSError, ValueError, TypeError) as exc:
            flash(str(exc))
            return redirect(url_for("patch_home", group_id=group_id, name=name, idx=idx), code=303)
        return redirect(url_for("patch_home", group_id=group_id, name=name, idx=idx, job=job_id), code=303)

    @app.get("/runs/<int:group_id>/<name>/patch/<int:idx>/download/<job_id>/<kind>")
    def patch_download(group_id, name, idx, job_id, kind):
        if kind not in ("patch", "source", "json"):
            abort(404)
        context = context_for(group_id, name, idx)
        job = next((j for j in core.history(ui.ROOT, context) if j["id"] == job_id), None)
        if not job or job["state"] != "DRAFT_READY":
            abort(404)
        try:
            result = core.load_result(ui.ROOT, job)
            if not context["eligible"] or result.get("binding") != context["binding"]:
                raise ValueError("Nguồn hoặc thẩm định đã đổi; cần tạo đề xuất từ kết quả hiện tại.")
        except (OSError, ValueError, TypeError) as exc:
            abort(409, str(exc))
        import json
        filename = PurePosixPath(context["relative"]).name
        if kind == "patch":
            body, filename = result["diff"], filename + ".patch"
        elif kind == "source":
            body = result["proposal"]["updated_source"]
        else:
            body, filename = json.dumps(result, ensure_ascii=False, indent=2), filename + ".proposal.json"
        return Response(body, content_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'})
