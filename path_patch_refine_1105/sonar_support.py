"""SonarQube API helpers reused from the successful three-version rescan.

Imported by run.py; this module does not initiate a scan itself.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
VERSION = "pathcase01-three-way-sonar-v1-api2"
RULE = "findsecbugs:PATH_TRAVERSAL_IN"
SOURCE_PATH = "Clean_Code/pilot_path22/PathCase01.java"
HASHES = {
    "original": "cd52945fba3047ebbffb2e963993d05f26acad1be5843c5c3b203034978550a2",
    "proposed": "725820a7cf3ed4c0c949153cd59a3659efb5a2fba5e4e04e600dea08c55ec5f6",
    "reviewed": "5f35eb48c083cb2d1cabef5ec6937c447f7397b3df6936d6083b3e15d7bba9d5",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(data):
    return sha(json.dumps(data, ensure_ascii=False, sort_keys=True).encode())


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def clean(text, token=""):
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    text = text or ""
    if token:
        text = text.replace(token, "[REDACTED]")
    return re.sub(r"\bsq[apu]_[A-Za-z0-9]+", "[REDACTED]", text)


class ApiError(RuntimeError):
    def __init__(self, endpoint, status):
        self.status = status
        advice = ""
        if status in (401, 403):
            advice = " Cần User token có quyền đọc project_1, tạo/quét project và gán Quality Profile."
        super().__init__(f"SonarQube HTTP {status}: {endpoint}.{advice}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class API:
    def __init__(self, url, token):
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme not in ("http", "https") or parsed.hostname not in
                ("127.0.0.1", "localhost", "::1") or parsed.username or parsed.password
                or parsed.query or parsed.fragment):
            raise ValueError("Gói này chỉ dùng SonarQube trên localhost; kiểm tra SONAR_URL.")
        self.url, self.token = url.rstrip("/"), token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.services = {}

    def call(self, endpoint, params=None, post=False, raw=False):
        encoded = urllib.parse.urlencode(params or {}).encode()
        url = self.url + endpoint + ("?" + encoded.decode() if encoded and not post else "")
        headers = {"Authorization": "Bearer " + self.token}
        if post:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = urllib.request.Request(url, data=encoded if post else None, headers=headers)
        try:
            with self.opener.open(request, timeout=30) as response:
                body = response.read(20_000_001)
        except urllib.error.HTTPError as exc:
            raise ApiError(endpoint, exc.code) from None
        except urllib.error.URLError:
            raise RuntimeError("Không kết nối được SonarQube. Kiểm tra container và SONAR_URL.") from None
        if len(body) > 20_000_000:
            raise ValueError("Phản hồi API vượt giới hạn; dừng để kiểm tra.")
        if raw:
            return body.decode("utf-8")
        if not body:
            return {}
        value = json.loads(body)
        if not isinstance(value, dict):
            raise ValueError("API không trả JSON object: " + endpoint)
        return value

    def discover(self):
        # Match the explicit public-contract request used in api_diagnostic.json.
        value = self.call("/api/webservices/list", {"include_internals": "false"})
        self.services = {}
        for service in value.get("webServices", []):
            for action in service.get("actions", []):
                endpoint = "/" + service["path"].strip("/") + "/" + action["key"]
                if endpoint in self.services:
                    raise ValueError("API contract chứa endpoint trùng: " + endpoint)
                self.services[endpoint] = action
        required = {
            "/api/projects/create": {"project", "name", "visibility"},
            "/api/qualityprofiles/add_project": {"project", "language", "qualityProfile"},
            "/api/rules/search": {"activation", "qprofile", "p", "ps", "f"},
            "/api/issues/search": {"p", "ps"},
        }
        for endpoint, names in required.items():
            actual = {p["key"] for p in self.services.get(endpoint, {}).get("params", [])}
            if not names <= actual:
                save(HERE / "work/api_contract_error.json", {
                    "endpoint": endpoint, "required_params": sorted(names),
                    "observed_action": self.services.get(endpoint),
                    "service_count": len(value.get("webServices", [])),
                })
                raise ValueError("API chưa khớp: " + endpoint + "; thiếu "
                                 + ", ".join(sorted(names - actual))
                                 + ". Gửi work/api_contract_error.json để kiểm tra.")
        issue_params = {p["key"] for p in self.services["/api/issues/search"]["params"]}
        # SonarQube 10.2+ advertises 'components'; old versions used 'componentKeys'.
        self.issue_component_param = next((p for p in ("components", "componentKeys")
                                          if p in issue_params), None)
        if not self.issue_component_param:
            raise ValueError("API issues/search thiếu bộ lọc project; không quét khi chưa xác định được phạm vi.")
        for endpoint in ("/api/projects/create", "/api/qualityprofiles/add_project"):
            if self.services[endpoint].get("post") is not True:
                raise ValueError("API không xác nhận phương thức POST: " + endpoint)
        visibility = next(p for p in self.services["/api/projects/create"]["params"]
                          if p["key"] == "visibility")
        if "private" not in visibility.get("possibleValues", []):
            raise ValueError("API không xác nhận khả năng tạo project private; chưa tạo project.")
        return value

    def profile(self, project):
        action = self.services.get("/api/qualityprofiles/search", {})
        params = {p["key"] for p in action.get("params", [])}
        key = "project" if "project" in params else "projectKey" if "projectKey" in params else None
        if not key:
            raise ValueError("Không tìm được API lấy Quality Profile theo project.")
        value = self.call("/api/qualityprofiles/search", {key: project})
        profiles = [p for p in value.get("profiles", []) if p.get("language") == "java"]
        if len(profiles) != 1 or not profiles[0].get("key") or not profiles[0].get("name"):
            raise ValueError("Không xác định được duy nhất Java Quality Profile: " + project)
        return profiles[0]

    def rules(self, key):
        rows, seen, total_seen = [], set(), None
        for page in range(1, 101):
            params = {"activation": "true", "qprofile": key, "p": page, "ps": 100, "f": "actives"}
            value = self.call("/api/rules/search", params,
                              post=bool(self.services["/api/rules/search"].get("post")))
            batch, total = value.get("rules"), value.get("total", value.get("paging", {}).get("total"))
            if not isinstance(batch, list) or type(total) is not int or (total_seen is not None and total != total_seen):
                raise ValueError("Danh sách rule thay đổi hoặc thiếu dữ liệu.")
            total_seen = total
            for rule in batch:
                name = rule.get("key")
                active = [a for a in value.get("actives", {}).get(name, []) if a.get("qProfile") == key]
                if not name or name in seen or len(active) != 1:
                    raise ValueError("Không xác minh được trạng thái active của rule.")
                seen.add(name)
                a = active[0]
                rows.append({"key": name, "severity": a.get("severity"),
                             "params": sorted(a.get("params", []), key=lambda x: x["key"])})
            if len(rows) == total:
                return sorted(rows, key=lambda x: x["key"])
            if not batch or len(rows) > total:
                break
        raise ValueError("Không lấy đủ danh sách active rules.")

    def snapshot(self, project):
        profile = self.profile(project)
        rules = self.rules(profile["key"])
        if RULE not in {r["key"] for r in rules}:
            raise ValueError(f"Profile {profile['name']} chưa bật {RULE}; chưa tạo project/quét.")
        status = self.call("/api/system/status")
        if status.get("status") != "UP":
            raise ValueError("SonarQube chưa sẵn sàng.")
        return {"profile_key": profile["key"], "profile_name": profile["name"],
                "server_version": status.get("version"), "server_id": status.get("id"),
                "active_rules_sha256": fingerprint(rules), "active_rules": rules}


def command(args, cwd, logfile, token="", timeout=120, env=None):
    process = subprocess.Popen(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate()
        logfile.write_text(clean(output, token), encoding="utf-8")
        raise RuntimeError("Công cụ đã dừng giữa chừng; xem " + str(logfile)) from None
    output = clean(output, token)
    logfile.write_text(output, encoding="utf-8")
    if process.returncode:
        raise RuntimeError(f"Công cụ trả mã {process.returncode}; xem {logfile}")
    return output


def wait_task(api, task_id, project, folder):
    for _ in range(150):
        task = api.call("/api/ce/task", {"id": task_id}).get("task", {})
        save(folder / "analysis_task.json", task)
        if task.get("componentKey") != project:
            raise ValueError("Background task không thuộc project kiểm chứng.")
        if task.get("status") == "SUCCESS" and task.get("analysisId"):
            return task["analysisId"]
        if task.get("status") not in ("PENDING", "IN_PROGRESS"):
            raise ValueError("Background task: " + str(task.get("status")))
        time.sleep(2)
    raise RuntimeError("Chưa hoàn tất background task; chạy lại cùng lệnh để tiếp tục chờ.")


def latest_analysis(api, project, analysis_id):
    value = api.call("/api/project_analyses/search", {"project": project, "p": 1, "ps": 1})
    analyses = value.get("analyses", [])
    if len(analyses) != 1 or analyses[0].get("key") != analysis_id:
        raise ValueError("Lượt phân tích trên server khác checkpoint hoặc chưa được lập chỉ mục; chạy lại để kiểm tra.")


def collect(api, project, analysis_id, folder, source):
    latest_analysis(api, project, analysis_id)
    tree = api.call("/api/components/tree", {"component": project, "qualifiers": "FIL", "p": 1, "ps": 100})
    files = tree.get("components", [])
    if tree.get("paging", {}).get("total") != 1 or len(files) != 1 or files[0].get("path") != SOURCE_PATH:
        raise ValueError("Kết quả quét không chứa đúng một PathCase01.java; không diễn giải số cảnh báo 0.")
    uploaded = api.call("/api/sources/raw", {"key": files[0]["key"]}, raw=True)
    normal = lambda text: text.replace("\r\n", "\n").rstrip("\n")
    if normal(uploaded) != normal(source.decode()):
        raise ValueError("Mã nguồn trên SonarQube không khớp bản đang so sánh.")
    issues, seen, total_seen = [], set(), None
    for page in range(1, 101):
        value = api.call("/api/issues/search", {api.issue_component_param: project, "p": page, "ps": 100})
        save(folder / f"issues-page-{page}.json", value)
        batch = value.get("issues")
        total = value.get("paging", {}).get("total", value.get("total"))
        if not isinstance(batch, list) or type(total) is not int or (total_seen is not None and total != total_seen):
            raise ValueError("Danh sách cảnh báo thay đổi hoặc thiếu dữ liệu.")
        total_seen = total
        for issue in batch:
            key = issue.get("key")
            if not key or key in seen or issue.get("component") != files[0]["key"]:
                raise ValueError("Cảnh báo trùng hoặc không thuộc tệp được quét.")
            seen.add(key)
            issues.append(issue)
        if len(issues) == total:
            break
        if not batch or len(issues) > total:
            raise ValueError("Không lấy đủ cảnh báo.")
    else:
        raise ValueError("Số trang cảnh báo vượt giới hạn.")
    latest_analysis(api, project, analysis_id)
    save(folder / "issues.json", {"issues": issues, "total": len(issues)})
    return {"analysis_id": analysis_id, "source_confirmed_on_server": True,
            "source_sha256": sha(source), "total_issues": len(issues),
            "rule_counts": dict(sorted(Counter(i["rule"] for i in issues).items())),
            "target_rule_count": sum(i["rule"] == RULE for i in issues), "issues": issues}

