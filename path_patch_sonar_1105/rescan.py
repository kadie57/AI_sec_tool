"""Compare three frozen PathCase01 versions on isolated local SonarQube projects.

Run: python3 rescan.py
Local checks only: python3 rescan.py --check
Requires a user token with project creation, analysis and profile association rights.
Never changes project_1, its profile, Clean_Code, the application or AI results.
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


def local_inputs():
    sources = {}
    for variant, expected in HASHES.items():
        data = (HERE / "sources" / (variant + ".java.txt")).read_bytes()
        if sha(data) != expected:
            raise ValueError("Mã nguồn khác bản đã kiểm tra: " + variant)
        sources[variant] = data
    verification = read(HERE / "verification_results_supplied.json")
    for variant, field in (("original", "source_sha256"), ("proposed", "proposed_sha256"), ("reviewed", "reviewed_sha256")):
        if verification.get(field) != HASHES[variant]:
            raise ValueError("Kết quả kiểm thử không thuộc đúng mã nguồn.")
    checks = verification.get("checks", [])
    controlled = verification.get("controlled_interleavings", [])
    if (len(checks) != 12 or not all(c.get("passed") is True for c in checks)
            or {(c.get("variant"), c.get("scenario")) for c in controlled} !=
            {(v, s) for v in ("proposed", "reviewed") for s in ("file_replacement", "directory_replacement")}
            or not all(c.get("blocked_without_output") is True for c in controlled if c["variant"] == "reviewed")):
        raise ValueError("Thiếu kết quả kiểm chứng bản hiệu chỉnh.")
    java = shutil.which("java")
    javac = shutil.which("javac")
    if not java:
        raise ValueError("Cần JDK Java; không tự cài phần mềm.")
    scanner = os.getenv("SONAR_SCANNER_PATH") or shutil.which("sonar-scanner")
    if not scanner:
        candidate = Path.home() / "Downloads/sonar-scanner-8.0.1.6346-linux-x64/bin/sonar-scanner"
        if candidate.is_file():
            scanner = str(candidate)
    if not scanner or not Path(scanner).is_file() or not os.access(scanner, os.X_OK):
        raise ValueError("Không thấy SonarScanner. Đặt SONAR_SCANNER_PATH trỏ tới bin/sonar-scanner đang dùng.")
    return sources, verification, [javac] if javac else [java, "com.sun.tools.javac.Main"], str(Path(scanner).resolve())


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


def run(args):
    print("RESCAN_VERSION:", VERSION, flush=True)
    sources, verification, compiler, scanner = local_inputs()
    print("LOCAL_CHECK_OK: 3 mã nguồn và kết quả kiểm chứng khớp; đã tìm thấy JDK/SonarScanner.", flush=True)
    if args.check:
        print("Chưa gọi SonarQube; chưa tạo project hoặc chạy quét.")
        return 0
    work = HERE / "work"
    work.mkdir(exist_ok=True)
    with (work / "run.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Gói kiểm chứng đang chạy ở Terminal khác.") from None
        token = os.getenv("SONAR_TOKEN") or getpass.getpass("Nhập SonarQube User token (không hiện ký tự): ")
        if not token.strip():
            raise ValueError("Chưa có token.")
        api = API(args.sonar_url, token)
        spec = api.discover()
        current = api.snapshot(args.reference_project)
        signature = {"version": VERSION, "script_sha256": sha(Path(__file__).read_bytes()),
                     "source_hashes": HASHES, "verification_sha256": fingerprint(verification),
                     "sonar_url": api.url, "reference_project": args.reference_project,
                     "scanner": scanner}
        state_file = work / "state.json"
        if state_file.exists():
            state = read(state_file)
            if state["signature"] != signature or state["baseline"] != current:
                raise ValueError("Cấu hình/mã nguồn/bộ rule khác checkpoint. Giữ kết quả cũ; gửi thông báo để đối chiếu.")
        else:
            tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:12]
            state = {"signature": signature, "baseline": current, "experiment_id": tag,
                     "started_at": datetime.now(timezone.utc).isoformat(), "variants": {
                         v: {"project_key": "pathpatch_" + tag + "_" + v, "created": False}
                         for v in sources}}
            save(state_file, state)
            save(work / "api_contract.json", spec)
        if state.get("finished_at"):
            print("Đã hoàn tất lượt này. FILE CẦN GỬI:", work / "comparison.json")
            return 0
        print("Bộ rule Java:", current["profile_name"], "|", len(current["active_rules"]), "rule đang bật.", flush=True)
        env = os.environ.copy()
        env["SONAR_TOKEN"] = token
        env.pop("SONAR_SCANNER_JSON_PARAMS", None)
        env.pop("SONARQUBE_SCANNER_PARAMS", None)
        # Prepare/compile all variants before creating any remote project.
        for variant, source in sources.items():
            folder = work / variant
            folder.mkdir(exist_ok=True)
            dest = folder / SOURCE_PATH
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists() and dest.read_bytes() != source:
                raise ValueError("Bản sao đã bị chỉnh sửa: " + str(dest))
            dest.write_bytes(source)
            if not state["variants"][variant].get("scan_started"):
                classes = Path(tempfile.mkdtemp(prefix="classes-", dir=folder))
                command(compiler + ["-g", "-encoding", "UTF-8", "-d", str(classes), str(dest)], folder, folder / "javac.log")
                state["variants"][variant]["classes"] = str(classes)
            (folder / "sonar-project.properties").write_text("# Isolated experiment; options supplied explicitly.\n")
        save(state_file, state)
        command([scanner, "--version"], work, work / "scanner-version.log", token, env=env)
        command(compiler + ["-version"], work, work / "compiler-version.log")
        for number, (variant, source) in enumerate(sources.items(), 1):
            row, folder = state["variants"][variant], work / variant
            project = row["project_key"]
            if project == args.reference_project or not project.startswith("pathpatch_" + state["experiment_id"] + "_"):
                raise ValueError("Project đích không phải project kiểm chứng riêng.")
            if api.snapshot(args.reference_project) != state["baseline"]:
                raise ValueError("Bộ rule thay đổi trong lượt quét; không tiếp tục so sánh.")
            if row.get("result"):
                print(f"[{number}/3] {variant}: đã lưu kết quả, bỏ qua quét.", flush=True)
                continue
            if not row["created"]:
                created = api.call("/api/projects/create", {"project": project,
                                   "name": "Path patch " + variant + " " + state["experiment_id"],
                                   "visibility": "private"}, post=True)
                if created.get("project", {}).get("key") != project:
                    raise ValueError("Không xác nhận được project vừa tạo; chưa quét.")
                row["created"] = True
                save(state_file, state)
            api.call("/api/qualityprofiles/add_project", {"project": project, "language": "java",
                     "qualityProfile": current["profile_name"]}, post=True)
            if api.profile(project)["key"] != current["profile_key"]:
                raise ValueError("Project kiểm chứng chưa dùng đúng Quality Profile.")
            task_file = folder / "report-task.txt"
            if not row.get("scan_started"):
                if task_file.exists():
                    raise ValueError("Có report-task ngoài checkpoint; dừng để tránh đọc kết quả cũ.")
                row["scan_started"] = True
                save(state_file, state)
                print(f"[{number}/3] Đang quét {variant} → {project}...", flush=True)
                command([scanner, "-Dsonar.host.url=" + api.url, "-Dsonar.projectKey=" + project,
                         "-Dsonar.projectVersion=" + state["experiment_id"],
                         "-Dsonar.sources=Clean_Code", "-Dsonar.inclusions=**/*.java",
                         "-Dsonar.exclusions=", "-Dsonar.sourceEncoding=UTF-8",
                         "-Dsonar.scm.disabled=true", "-Dsonar.java.binaries=" + row["classes"],
                         "-Dsonar.scanner.metadataFilePath=" + str(task_file)],
                        folder, folder / "scanner.log", token, timeout=900, env=env)
            if not task_file.exists():
                raise RuntimeError("Scanner bị ngắt trước khi lưu task. Không tự quét trùng; gửi work/state.json và scanner.log.")
            properties = dict(line.split("=", 1) for line in task_file.read_text().splitlines() if "=" in line)
            if properties.get("projectKey") != project or not properties.get("ceTaskId"):
                raise ValueError("report-task.txt không khớp project hoặc thiếu ceTaskId.")
            if row.get("task_id") and row["task_id"] != properties["ceTaskId"]:
                raise ValueError("Task ID khác checkpoint.")
            row["task_id"] = properties["ceTaskId"]
            save(state_file, state)
            analysis_id = wait_task(api, row["task_id"], project, folder)
            result = collect(api, project, analysis_id, folder, source)
            if api.snapshot(args.reference_project) != state["baseline"]:
                raise ValueError("Bộ rule/server thay đổi trong lượt quét; kết quả chưa được ghép.")
            if api.profile(project)["key"] != current["profile_key"]:
                raise ValueError("Quality Profile đích đã thay đổi trong lượt quét.")
            if variant == "original" and result["target_rule_count"] == 0:
                save(folder / "baseline_not_reproduced.json", result)
                raise ValueError("Mẫu gốc không tái hiện PATH_TRAVERSAL_IN. Dừng; chưa thể đánh giá hai bản sửa bằng lượt này.")
            row["result"] = result
            save(state_file, state)
            print(f"  {RULE}: {result['target_rule_count']} | tổng cảnh báo: {result['total_issues']}", flush=True)
        summary = {"experiment": VERSION, "state": "COMPLETED", "target_rule": RULE,
                   "reference_project": args.reference_project,
                   "profile": {k: v for k, v in current.items() if k != "active_rules"},
                   "source_path": SOURCE_PATH, "started_at": state["started_at"],
                   "finished_at": datetime.now(timezone.utc).isoformat(),
                   "runtime_verification": verification, "variants": state["variants"],
                   "limitations": ["Issue API only; separate Security Hotspots are not collected.",
                       "A missing warning does not prove a vulnerability is fixed; sink recognition may differ.",
                       "Reviewed code is an assisted revision, not unedited Qwen output.",
                       "Controlled interleavings are synthetic tests, not natural race success rates.",
                       "No LLM calls, no application changes, no modification of the original project."]}
        save(work / "comparison.json", summary)
        state["finished_at"] = summary["finished_at"]
        save(state_file, state)
        print("HOÀN TẤT. FILE CẦN GỬI:", work / "comparison.json", flush=True)
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--sonar-url", default=os.getenv("SONAR_URL", "http://127.0.0.1:9000"))
    parser.add_argument("--reference-project", default="project_1")
    args = parser.parse_args()
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\nĐã dừng; checkpoint được giữ lại.", file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print("LỖI: " + clean(str(exc), os.getenv("SONAR_TOKEN", "")), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
