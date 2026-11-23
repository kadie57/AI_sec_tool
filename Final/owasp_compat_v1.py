"""Six-case OWASP compatibility collection. No Joern, LLM or accuracy scoring.

Place in ~/AI_sec_tool. First use --check, then --collect.
Uses a separate SonarQube project and the Java profile assigned to project_1.
Unchanged source is copied into experiments/owasp_compat_v1/inputs/<commit>.
These six cases are development/compatibility cases, excluded from final testing.
"""
import argparse
import ast
import base64
from collections import Counter
import csv
from datetime import datetime, timezone
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

VERSION = "owasp-compat-six-v1"
COMMIT = "a452b3aafd232245d0753e54eb243d6651f8ef96"
PROJECT = "thesis_owasp_compat_v1"
PREFIX = Path("src/main/java/org/owasp/benchmark/testcode")
# First lexicographic true and false case in each target category, chosen BEFORE scans.
CASES = ("BenchmarkTest00008", "BenchmarkTest00052", "BenchmarkTest00001",
         "BenchmarkTest00063", "BenchmarkTest00006", "BenchmarkTest00051")
EXPECTED = {"BenchmarkTest00008": ("sqli", "true", "89"),
            "BenchmarkTest00052": ("sqli", "false", "89"),
            "BenchmarkTest00001": ("pathtraver", "true", "22"),
            "BenchmarkTest00063": ("pathtraver", "false", "22"),
            "BenchmarkTest00006": ("cmdi", "true", "78"),
            "BenchmarkTest00051": ("cmdi", "false", "78")}
MODULE_HASHES = {
    "master_pipeline.py": "dd0165e2145edc00fa76506a6cb08380d58b2fcf7e97eb957cd5edcda156660c",
    "master_pipeline_multi_v1.py": "a892b15c5e002259e2bc70b87cf5f73d8fec44c7f9426587c3b2df71d0c9b382",
    "path_triage_v2.py": "d122b0cacb92beb006ff764498dec89b52c1295630b62c2a474449d0eced9004",
    "command_triage_v2.py": "65e7808640c35c349c1cf338f254233808997465e0777d23841ff3daec82ade8",
}
ROUTES = {"findsecbugs:SQL_INJECTION_JDBC": "sql", "findbugs:SQL_INJECTION_JDBC": "sql",
          "java:S3649": "sql", "findsecbugs:PATH_TRAVERSAL_IN": "path",
          "findsecbugs:COMMAND_INJECTION": "command"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def redact(value, token=""):
    value = str(value)
    if token:
        value = value.replace(token, "[REDACTED]")
    return re.sub(r"\bsq[apu]_[A-Za-z0-9]+", "[REDACTED]", value)


def run(cmd, cwd, log=None, timeout=300, env=None, token=""):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                           errors="replace", timeout=timeout, env=env)
    except subprocess.TimeoutExpired as exc:
        if log:
            chunks = (exc.stdout or "", exc.stderr or "")
            text = "\n".join(c.decode("utf-8", errors="replace") if isinstance(c, bytes) else c
                             for c in chunks)
            log.write_text(redact(text, token), encoding="utf-8")
        raise ValueError("Công cụ quá thời gian; xem log đã lưu.") from None
    text = redact(p.stdout + "\n" + p.stderr, token)
    if log:
        log.write_text(text, encoding="utf-8")
    if p.returncode:
        raise ValueError(f"{Path(cmd[0]).name} trả mã {p.returncode}; xem {log or text[:500]}.")
    return p.stdout.strip()


def preflight(root, repo, scanner):
    for exe in ("git", "javac", "mvn"):
        if not shutil.which(exe):
            raise ValueError("Thiếu công cụ: " + exe)
    if not scanner.is_file() or not os.access(scanner, os.X_OK):
        raise ValueError("Không tìm thấy SonarScanner; đặt SONAR_SCANNER_PATH tới file thực thi.")
    if run(["git", "rev-parse", "HEAD"], repo) != COMMIT:
        raise ValueError("Commit OWASP khác bản đã đối chiếu. Không tự đổi checkout; gửi mã commit để kiểm tra.")
    if run(["git", "status", "--porcelain", "--untracked-files=no"], repo):
        raise ValueError("Mã OWASP đã thay đổi so với commit. Gửi git diff --stat; chưa quét.")
    for name, expected in MODULE_HASHES.items():
        if not (root / name).is_file() or sha((root / name).read_bytes()) != expected:
            raise ValueError(name + " thiếu hoặc khác bản đã gửi; chưa sửa pipeline, chưa quét.")
    rows = list(csv.reader(line for line in (repo / "expectedresults-1.2.csv").read_text().splitlines()
                           if line.strip() and not line.startswith("#")))
    refs = {r[0]: tuple(r[1:4]) for r in rows}
    result = []
    for name in CASES:
        if refs.get(name) != EXPECTED[name]:
            raise ValueError("Nhãn tham chiếu không khớp commit: " + name)
        raw = (repo / PREFIX / (name + ".java")).read_bytes()
        if b"\r" in raw:
            raise ValueError("Nguồn không dùng LF; không tự đổi số dòng/hash.")
        classfile = repo / "target/classes/org/owasp/benchmark/testcode" / (name + ".class")
        if not classfile.is_file():
            raise ValueError("Thiếu .class của " + name + "; cần mvn compile thành công.")
        result.append({"sample": name, "category": refs[name][0],
                       "source_sha256": sha(raw), "raw": raw})
    helper = repo / "target/classes/org/owasp/benchmark/helpers/Utils.class"
    if not helper.is_file():
        raise ValueError("Thiếu bytecode thư viện hỗ trợ OWASP.")
    return result


class Client:
    def __init__(self, url, token):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("SONAR_URL không hợp lệ.")
        self.url, self.token = url.rstrip("/"), token
        self.auth = "Basic " + base64.b64encode((token + ":").encode()).decode()
        # Avoid following redirects with a token to an unexpected destination.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        self.opener = urllib.request.build_opener(NoRedirect)

    def call(self, endpoint, params=None, post=False, missing_ok=False):
        encoded = urllib.parse.urlencode(params or {}).encode()
        url = self.url + endpoint
        if not post and encoded:
            url += "?" + encoded.decode()
        req = urllib.request.Request(url, data=encoded if post else None,
                                     headers={"Authorization": self.auth})
        try:
            with self.opener.open(req, timeout=30) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            if missing_ok and exc.code == 404:
                return None
            detail = redact(exc.read().decode(errors="replace"), self.token)[:400]
            raise ValueError(f"SonarQube {endpoint}: HTTP {exc.code}: {detail}") from None
        return json.loads(raw) if raw.strip() else {}

    def java_profile(self, project):
        profiles = self.call("/api/qualityprofiles/search", {"project": project}).get("profiles", [])
        java = [p for p in profiles if p.get("language") == "java"]
        if len(java) != 1:
            raise ValueError("Không xác định được một Java Quality Profile của " + project)
        return java[0]

    def paged(self, endpoint, params, field):
        result, seen, total_first, page = [], set(), None, 1
        while True:
            body = self.call(endpoint, {**params, "p": page, "ps": 100})
            batch = body.get(field)
            total = body.get("paging", {}).get("total", body.get("total"))
            if type(total) is not int or not isinstance(batch, list):
                raise ValueError("Phân trang không hợp lệ: " + endpoint)
            if total_first is not None and total != total_first:
                raise ValueError("Dữ liệu thay đổi khi lấy trang; dừng để tránh số liệu thiếu.")
            total_first = total
            for item in batch:
                key = item.get("key")
                if not key or key in seen:
                    raise ValueError("Thiếu key hoặc trùng key khi lấy trang.")
                seen.add(key)
                result.append(item)
            if len(result) == total:
                return result
            if not batch or len(result) > total:
                raise ValueError("Phân trang chưa đầy đủ.")
            page += 1

    def rules(self, key):
        rows = self.paged("/api/rules/search", {"activation": "true", "qprofile": key}, "rules")
        return sorted(r["key"] for r in rows)

    def wait(self, task_id):
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            task = self.call("/api/ce/task", {"id": task_id})["task"]
            if task.get("status") == "SUCCESS":
                return task
            if task.get("status") not in ("PENDING", "IN_PROGRESS"):
                raise ValueError("SonarQube task không thành công: " + str(task.get("status")))
            time.sleep(2)
        raise ValueError("Hết thời gian chờ SonarQube. Không lấy cảnh báo của lần quét cũ.")


def command_gate(root):
    # Extract exactly the current guard and span functions, never import the analyzers.
    tree = ast.parse((root / "command_triage_v2.py").read_text())
    funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ("execution_guard", "span")]
    if len(funcs) != 2:
        raise ValueError("Không đọc được bộ nhận dạng Command hiện có.")
    space = {"re": re}
    exec(compile(ast.Module(body=funcs, type_ignores=[]), "current_command_guard", "exec"), space)
    return space["execution_guard"]


def inventory(issues, rows, root):
    sources = {r["relative"]: r["raw"].decode("utf-8") for r in rows}
    guard = command_gate(root)
    details = []
    for issue in issues:
        rel = issue.get("component", "").removeprefix(PROJECT + ":")
        route = ROUTES.get(issue.get("rule"))
        entry = {"issue_id": issue["key"], "rule": issue["rule"], "component": issue["component"],
                 "line": issue.get("line"), "message": issue.get("message"), "route": route}
        if route == "command" and rel in sources:
            try:
                entry["current_execution_guard"] = guard(sources[rel], issue)
            except (ValueError, IndexError, KeyError, TypeError) as exc:
                entry["current_execution_guard"] = {"supported": False, "reason": str(exc)}
        details.append(entry)
    return {"rule_counts": dict(Counter(i["rule"] for i in issues)),
            "route_counts": dict(Counter(ROUTES.get(i["rule"], "unsupported") for i in issues)),
            "issues": details,
            "note": "Rule routed does not prove a matching Joern sink/flow. No AI ran; no accuracy is computed."}


def collect(root, repo, scanner, rows, url, token, profile_project):
    work = root / "experiments/owasp_compat_v1"
    work.mkdir(parents=True, exist_ok=True)
    with (work / "collect.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return collect_locked(root, repo, scanner, rows, url, token, profile_project, work)


def collect_locked(root, repo, scanner, rows, url, token, profile_project, work):
    out = root / "runs" / ("owasp-compat-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6])
    out.mkdir(parents=True)
    manifest = {"state": "STARTED", "pipeline_version": VERSION, "project": PROJECT,
                "started_at": datetime.now(timezone.utc).isoformat(), "benchmark_commit": COMMIT,
                "purpose": "compatibility_development_only", "excluded_from_final_evaluation": list(CASES),
                "collector_sha256": sha(Path(__file__).read_bytes()), "pipeline_hashes": MODULE_HASHES,
                "limitations": ["Six compatibility samples, not a final accuracy dataset.",
                                "Only issues API; hotspots are not collected.",
                                "Original benchmark labels and identifiers retained in source; no LLM called.",
                                "Existing analyzers use single-file context and bounded sink support."]}
    save(out / "manifest.json", manifest)
    print("KẾT QUẢ:", out, flush=True)
    try:
        print("[1/4] Đối chiếu SonarQube và Quality Profile...", flush=True)
        client = Client(url, token)
        status = client.call("/api/system/status")
        if status.get("status") != "UP":
            raise ValueError("SonarQube chưa UP; khởi động xong rồi chạy lại.")
        if not client.call("/api/authentication/validate").get("valid"):
            raise ValueError("Token không hợp lệ.")
        profile = client.java_profile(profile_project)
        before_rules = client.rules(profile["key"])
        if not set(before_rules).intersection(ROUTES):
            raise ValueError("Quality Profile gốc chưa bật rule nào pipeline hỗ trợ.")
        marker = work / "project_owner.json"
        owner = {"url": url.rstrip("/"), "project": PROJECT, "root": str(root)}
        found = client.call("/api/components/show", {"component": PROJECT}, missing_ok=True)
        if found is not None:
            if not marker.is_file() or json.loads(marker.read_text()) != owner:
                raise ValueError("Project kiểm tra đã tồn tại nhưng không có dấu tạo của script; không quét đè.")
        else:
            client.call("/api/projects/create", {"project": PROJECT, "name": "Thesis OWASP compatibility v1", "visibility": "private"}, post=True)
            save(marker, owner)
        client.call("/api/qualityprofiles/add_project", {"language": "java", "qualityProfile": profile["name"], "project": PROJECT}, post=True)
        if client.java_profile(PROJECT)["key"] != profile["key"]:
            raise ValueError("Project mới chưa dùng cùng Java Quality Profile.")
        save(out / "sonar_environment.json", {"system": status, "source_project": profile_project,
             "java_profile": profile, "active_rule_keys": before_rules,
             "note": "Rule-key inventory only; not a hash of rule parameters or analyzer binaries."})
        print("[2/4] Chuẩn bị thư viện và biên dịch riêng sáu mẫu...", flush=True)
        clean_env = os.environ.copy()
        clean_env.pop("SONAR_TOKEN", None)
        cp_file = out / "dependency_classpath.txt"
        run(["mvn", "-B", "org.apache.maven.plugins:maven-dependency-plugin:3.11.0:build-classpath",
             "-Dmdep.outputFile=" + str(cp_file)], repo, out / "maven_classpath.log", 600, clean_env)
        jars = [Path(x) for x in cp_file.read_text().strip().split(os.pathsep) if x]
        if not jars or any(not x.is_file() or x.suffix != ".jar" for x in jars):
            raise ValueError("Danh sách thư viện Maven không hợp lệ.")
        libraries = [repo / "target/classes", *jars]
        if any("," in str(p) for p in libraries):
            raise ValueError("Đường dẫn thư viện chứa dấu phẩy; chưa hỗ trợ.")
        srcroot = work / "inputs" / COMMIT / "src/main/java"
        for row in rows:
            target = work / "inputs" / COMMIT / PREFIX / (row["sample"] + ".java")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and target.read_bytes() != row["raw"]:
                raise ValueError("Bản sao benchmark đã thay đổi; không ghi đè.")
            if not target.exists():
                target.write_bytes(row["raw"])
            row["relative"] = target.relative_to(root).as_posix()
        manifest["source_hashes"] = {r["relative"]: r["source_sha256"] for r in rows}
        save(out / "manifest.json", manifest)
        classes = out / "classes"
        classes.mkdir()
        empty_sourcepath = out / "empty_sourcepath"
        empty_sourcepath.mkdir()
        run(["javac", "--release", "8", "-g", "-encoding", "UTF-8", "-sourcepath", str(empty_sourcepath),
             "-cp", os.pathsep.join(map(str, libraries)), "-d", str(classes),
             *[str(root / r["relative"]) for r in rows]], root, out / "javac.log", 300, clean_env)
        save(out / "dependency_hashes.json", {str(p): sha(p.read_bytes()) for p in [*jars, *(repo / "target/classes").rglob("*.class")]})
        print("[3/4] Quét sáu mẫu bằng SonarQube; chưa gọi AI...", flush=True)
        task_file = out / "report-task.txt"
        # Prevent a root-level sonar-project.properties from changing scope.
        settings = out / "sonar-project.properties"
        settings.write_text("# Isolated six-source OWASP collection; options are explicit.\n", encoding="utf-8")
        scanner_env = os.environ.copy()
        scanner_env.pop("SONAR_SCANNER_JSON_PARAMS", None)
        scanner_env["SONAR_TOKEN"] = token
        run([str(scanner), "-Dproject.settings=" + str(settings),
             "-Dsonar.projectBaseDir=" + str(root), "-Dsonar.host.url=" + url,
             "-Dsonar.projectKey=" + PROJECT, "-Dsonar.sources=" + str(srcroot.relative_to(root)),
             "-Dsonar.inclusions=**/*.java", "-Dsonar.sourceEncoding=UTF-8", "-Dsonar.java.source=8",
             "-Dsonar.scm.exclusions.disabled=true", "-Dsonar.scm.disabled=true",
             "-Dsonar.java.binaries=" + str(classes), "-Dsonar.java.libraries=" + ",".join(map(str, libraries)),
             "-Dsonar.working.directory=" + str(out / "scannerwork"),
             "-Dsonar.scanner.metadataFilePath=" + str(task_file)], root, out / "scanner.log", 900, scanner_env, token)
        props = dict(line.split("=", 1) for line in task_file.read_text().splitlines() if "=" in line)
        task = client.wait(props["ceTaskId"])
        if task.get("componentKey") != PROJECT or not task.get("analysisId"):
            raise ValueError("Background task không thuộc project/lượt phân tích mong đợi.")
        save(out / "analysis_task.json", task)
        manifest["analysis_id"] = task["analysisId"]
        print("[4/4] Lấy đủ cảnh báo và kiểm tra phạm vi...", flush=True)
        def check_latest():
            analyses = client.call("/api/project_analyses/search", {"project": PROJECT, "ps": 1}).get("analyses", [])
            if not analyses or analyses[0].get("key") != task["analysisId"]:
                raise ValueError("Có lượt phân tích khác trên project; chưa công nhận dữ liệu lượt này.")
        check_latest()
        issues = client.paged("/api/issues/search", {"componentKeys": PROJECT, "resolved": "false"}, "issues")
        for issue in issues:
            rel = issue.get("component", "").removeprefix(PROJECT + ":")
            if not issue.get("component", "").startswith(PROJECT + ":") or rel not in manifest["source_hashes"]:
                raise ValueError("Cảnh báo ngoài sáu nguồn đã chọn; cần kiểm tra phạm vi quét.")
        if client.java_profile(PROJECT)["key"] != profile["key"] or client.rules(profile["key"]) != before_rules:
            raise ValueError("Profile hoặc tập rule đổi trong lúc quét; chưa công nhận lượt thu thập.")
        check_latest()
        preflight(root, repo, scanner)
        if any(sha((root / r["relative"]).read_bytes()) != r["source_sha256"] for r in rows):
            raise ValueError("Nguồn đã thay đổi trong lúc quét.")
        save(out / "issues.json", {"issues": issues, "total": len(issues)})
        metadata = {rule: client.call("/api/rules/show", {"key": rule}) for rule in sorted({i["rule"] for i in issues})}
        save(out / "rule_metadata.json", metadata)
        report = inventory(issues, rows, root)
        save(out / "compatibility_report.json", report)
        save(out / "sample_inventory.json", [{k: v for k, v in r.items() if k != "raw"} for r in rows])
        # Labels are kept in a separate file; not a prompt or a verdict.
        save(out / "reference_labels.json", {name: {"category": v[0], "has_target_vulnerability": v[1] == "true", "cwe": v[2]} for name, v in EXPECTED.items()})
        manifest.update(state="COLLECTED", issue_count=len(issues), supported_issue_count=sum(i["rule"] in ROUTES for i in issues),
                        result_count=0, ai_calls=0, error=None)
        print("ĐỊNH TUYẾN RULE:", report["route_counts"])
        for item in report["issues"]:
            if item.get("route"):
                gate = item.get("current_execution_guard")
                print(item["component"].rsplit("/", 1)[-1], "|", item["rule"], "| dòng", item["line"],
                      "| guard=" + str(gate.get("supported")) if gate else "")
    except BaseException as exc:
        manifest.update(state="FAILED", error=redact(exc, token))
        raise
    finally:
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        save(out / "manifest.json", manifest)
        # Bounded review bundle: no token, binaries, dependency cache or scanner internals.
        names = ["manifest.json", "sonar_environment.json", "analysis_task.json", "issues.json", "rule_metadata.json",
                 "compatibility_report.json", "sample_inventory.json", "reference_labels.json", "maven_classpath.log", "javac.log", "scanner.log"]
        bundle = out / "owasp_compat_review.zip"
        with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as z:
            for name in names:
                p = out / name
                if p.is_file():
                    z.writestr(name, redact(p.read_text(), token))
        print("FILE CẦN GỬI:", bundle, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--collect", action="store_true")
    parser.add_argument("--benchmark", type=Path, default=Path.home() / "AI_sec_benchmarks/BenchmarkJava")
    parser.add_argument("--profile-project", default="project_1")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    repo = args.benchmark.expanduser().resolve()
    scanner = Path(os.getenv("SONAR_SCANNER_PATH") or shutil.which("sonar-scanner") or
                   str(Path.home() / "Downloads/sonar-scanner-8.0.1.6346-linux-x64/bin/sonar-scanner")).expanduser().resolve()
    rows = preflight(root, repo, scanner)
    print("LOCAL_CHECK_OK: commit, bốn module và sáu mẫu khớp; có bytecode và công cụ.", flush=True)
    print("Mẫu tương thích:", ", ".join(CASES), flush=True)
    if args.check:
        print("Chưa ghi kết quả, chưa gọi Maven build/SonarQube/Joern/AI.")
        return 0
    url = os.getenv("SONAR_URL", "http://127.0.0.1:9000").rstrip("/")
    token = os.getenv("SONAR_TOKEN") or getpass.getpass("Nhập SonarQube User token (không hiện ký tự): ")
    if not token.strip():
        raise ValueError("Token trống.")
    collect(root, repo, scanner, rows, url, token, args.profile_project)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Đã dừng. Giữ lại log; không gọi AI.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print("LỖI:", redact(exc, os.getenv("SONAR_TOKEN", "")), file=sys.stderr)
        sys.exit(1)
