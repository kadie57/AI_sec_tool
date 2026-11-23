"""Collect SonarQube issues for Khanh's already fixed 60-case OWASP plan.

Place directly in ~/AI_sec_tool. Run --check, then --collect.
Reuses the installed scanner/API utilities; does not modify any backend file,
call Ollama/Joern, choose replacement samples, or supply reference labels to AI.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import fcntl
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import uuid
import zipfile

VERSION = "owasp-holdout-collection-v1"
PROJECT = "thesis_owasp_holdout_v1"
COMMIT = "a452b3aafd232245d0753e54eb243d6651f8ef96"
PLAN_SHA256 = "2e6bc2bd5ccd03c13463be32e87a4a00e60ffc944e414e273cfdb99732575436"
DEPENDENCIES = {
    "prepare_owasp_holdout.py": "af563a6e1c4b83970a6db2c7374ac2a446f42c88b2a79c0e46710f6a612f4612",
    "owasp_compat_v1.py": "1b2e23ab94d01c12d354931b6b6ea4c93846282f245854b427b3da8d5e309f14",
}
WORK = Path("experiments/owasp_holdout_v1")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fingerprint(value):
    return sha(json.dumps(value, sort_keys=True, ensure_ascii=False).encode())


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def stamp():
    return datetime.now(timezone.utc).isoformat()


def load_helpers(root):
    loaded = []
    for name, digest in DEPENDENCIES.items():
        path = root / name
        if not path.is_file() or sha(path.read_bytes()) != digest:
            raise ValueError(name + " thiếu hoặc khác bản đã đối chiếu; chưa quét.")
        spec = importlib.util.spec_from_file_location("holdout_" + path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        loaded.append(module)
    return tuple(loaded)


def validate_sources(root, repo, planner):
    work = root / WORK
    if sha((work / "plan.json").read_bytes()) != PLAN_SHA256:
        raise ValueError("Danh sách mẫu khác kế hoạch đã đối chiếu; không tự chọn lại.")
    plan = planner.verify(root, work)
    if plan.get("benchmark_commit") != COMMIT or plan.get("sample_count") != 60:
        raise ValueError("Kế hoạch/commit không khớp.")
    if planner.git(repo, "rev-parse", "HEAD").decode().strip() != COMMIT:
        raise ValueError("Checkout OWASP khác commit đã chốt.")
    if planner.git(repo, "status", "--porcelain", "--untracked-files=no").strip():
        raise ValueError("Checkout OWASP có thay đổi; chưa quét.")
    srcroot = work / "inputs" / COMMIT / "src/main/java"
    expected = set()
    for row in plan["samples"]:
        path = (root / row["project_path"]).resolve()
        if not path.is_relative_to(srcroot.resolve()) or path.suffix != ".java":
            raise ValueError("Nguồn nằm ngoài thư mục mẫu đã chọn.")
        raw = path.read_bytes()
        if sha(raw) != row["source_sha256"] or raw != planner.git(repo, "show", COMMIT + ":" + row["repository_path"]):
            raise ValueError("Nguồn khác commit: " + row["sample"])
        expected.add(path)
    actual = {p.resolve() for p in srcroot.rglob("*.java")}
    if len(expected) != 60 or actual != expected:
        raise ValueError("Thư mục quét không chứa đúng 60 tệp đã chọn.")
    return plan


def preflight(root, repo, scanner, planner):
    plan = validate_sources(root, repo, planner)
    for name in ("git", "javac", "java", "mvn"):
        if not shutil.which(name):
            raise ValueError("Thiếu công cụ: " + name)
    if not scanner.is_file() or not os.access(scanner, os.X_OK):
        raise ValueError("Thiếu SonarScanner; đặt SONAR_SCANNER_PATH tới file thực thi đã dùng.")
    if not (repo / "target/classes/org/owasp/benchmark/helpers/Utils.class").is_file():
        raise ValueError("Thiếu bytecode OWASP. Chạy mvn -B -DskipTests compile trong BenchmarkJava trước.")
    return plan


def profile_rules(client, key):
    """Capture keys plus activation severity/params where the server exposes them."""
    rules, seen, page, total_first, complete = [], set(), 1, None, True
    while True:
        body = client.call("/api/rules/search", {"activation": "true", "qprofile": key,
                           "f": "actives,params,severity", "ps": 100, "p": page})
        batch = body.get("rules")
        total = body.get("paging", {}).get("total", body.get("total"))
        if not isinstance(batch, list) or type(total) is not int or (total_first is not None and total != total_first):
            raise ValueError("Phân trang rules không nhất quán.")
        total_first = total
        for item in batch:
            rule = item.get("key")
            if not rule or rule in seen:
                raise ValueError("Rule thiếu key hoặc lặp giữa các trang.")
            seen.add(rule)
            activations = body.get("actives")
            activations = activations if isinstance(activations, dict) else {}
            activation = [a for a in activations.get(rule, []) if a.get("qProfile") == key]
            complete = complete and len(activation) == 1
            rules.append({"key": rule,
                          "default_params": sorted(item.get("params", []), key=lambda p: p.get("key", "")),
                          "activations": [{"severity": a.get("severity"), "inherit": a.get("inherit"),
                                           "params": sorted(a.get("params", []), key=lambda p: p.get("key", ""))}
                                          for a in activation]})
        if len(rules) == total:
            return {"rules": sorted(rules, key=lambda r: r["key"]), "activation_details_complete": complete}
        if not batch or len(rules) > total:
            raise ValueError("Không lấy đủ rule đang bật.")
        page += 1


def sonar_snapshot(client, profile_project):
    system = client.call("/api/system/status")
    if system.get("status") != "UP":
        raise ValueError("SonarQube chưa UP; đợi khởi động hoàn tất.")
    profile = client.java_profile(profile_project)
    rules = profile_rules(client, profile["key"])
    try:
        plugins = client.call("/api/plugins/installed").get("plugins")
        if not isinstance(plugins, list):
            raise ValueError("Không có danh sách plugin.")
        plugins = {"available": True, "plugins": sorted(
            [{k: p.get(k) for k in ("key", "name", "version", "hash")} for p in plugins], key=lambda p: p["key"])}
    except ValueError as exc:
        plugins = {"available": False, "reason": str(exc)}
    return {"system": system, "source_project": profile_project,
            "java_profile": {k: profile.get(k) for k in ("key", "name", "language", "rulesUpdatedAt")},
            "active_rules": rules, "plugins": plugins,
            "limitations": ["Plugin metadata is not a cryptographic snapshot of server analyzer binaries.",
                            "Missing activation/plugin details remain explicit in this record."]}


def check_latest(client, analysis_id):
    analyses = client.call("/api/project_analyses/search", {"project": PROJECT, "ps": 1}).get("analyses", [])
    if not analyses or analyses[0].get("key") != analysis_id:
        raise ValueError("Có lượt quét khác trên project; không dùng dữ liệu lẫn lượt.")


def inventory(plan, issues, routes):
    samples = []
    for row in plan["samples"]:
        component = PROJECT + ":" + row["project_path"]
        found = [i for i in issues if i["component"] == component]
        supported = [i for i in found if i["rule"] in routes]
        target_route = {"sqli": "sql", "pathtraver": "path", "cmdi": "command"}[row["category"]]
        target = [i for i in supported if routes[i["rule"]] == target_route]
        samples.append({**row, "component": component, "issue_count": len(found),
                        "supported_issue_count": len(supported), "target_issue_count": len(target),
                        "target_issue_ids": [i["key"] for i in target],
                        "rule_counts": dict(Counter(i["rule"] for i in found)),
                        "collection_status": "TARGET_WARNING" if target else "NO_SUPPORTED_TARGET_WARNING"})
    return {"sample_count": len(samples), "samples_with_target_warning": sum(r["target_issue_count"] > 0 for r in samples),
            "rule_counts": dict(Counter(i["rule"] for i in issues)),
            "route_counts": dict(Counter(routes.get(i["rule"], "unsupported") for i in issues)),
            "samples": samples, "note": "No AI called. No warning/unsupported rule is not a safe-code verdict."}


def make_bundle(out, utility, token):
    names = ("manifest.json", "sonar_environment.json", "sonar_environment_after.json", "analysis_task.json",
             "issues.json", "rule_metadata.json", "sample_inventory.json", "scan_components.json",
             "plan.json", "dependency_hashes.json", "tool_versions.json", "maven_classpath.log", "javac.log", "scanner.log")
    dest = out / "owasp_holdout_collection_review.zip"
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for name in names:
            path = out / name
            if path.is_file():
                z.writestr(name, utility.redact(path.read_text(encoding="utf-8"), token))
    return dest


def collect(root, repo, scanner, plan, planner, utility, url, token, profile_project):
    work = root / WORK
    with (work / "collect.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Một lượt thu thập bộ mẫu này đang chạy ở Terminal khác.") from None
        done = work / "collection_complete.json"
        if done.exists():
            marker = read(done)
            out = (root / marker["run"]).resolve()
            if not out.is_relative_to(root / "runs"):
                raise ValueError("Đường dẫn lượt đã lưu không hợp lệ.")
            for name, digest in marker["files"].items():
                if sha((out / name).read_bytes()) != digest:
                    raise ValueError("Kết quả thu thập đã lưu bị thay đổi: " + name)
            print("ĐÃ CÓ LƯỢT THU THẬP: giữ kết quả, không quét lại.")
            print("ZIP CẦN GỬI:", out / "owasp_holdout_collection_review.zip")
            return out
        return collect_new(root, repo, scanner, plan, planner, utility, url, token, profile_project, done)


def collect_new(root, repo, scanner, plan, planner, utility, url, token, profile_project, done):
    work = root / WORK
    out = root / "runs" / ("owasp-holdout-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6])
    out.mkdir(parents=True)
    manifest = {"state": "STARTED", "pipeline_version": VERSION, "project": PROJECT,
                "started_at": stamp(), "benchmark_commit": COMMIT, "purpose": "fixed_case_heldout_evaluation",
                "collector_sha256": sha(Path(__file__).read_bytes()), "collector_dependencies": DEPENDENCIES,
                "plan_sha256": PLAN_SHA256, "planned_sample_count": 60,
                "backend_snapshot_sha256": sha((work / "backend_snapshot.json").read_bytes()),
                "source_hashes": {r["project_path"]: r["source_sha256"] for r in plan["samples"]},
                "ai_calls": 0, "result_count": 0,
                "limitations": ["Collection only; no accuracy result and no AI analysis yet.",
                                "Only Issues API; Security Hotspots are outside this evaluation.",
                                "Case-held-out synthetic benchmark; not proof of generalization to enterprise code.",
                                "No runtime LLM/Joern freeze yet. Check prompts/configuration before generation."]}
    utility.save(out / "manifest.json", manifest)
    utility.save(out / "plan.json", plan)
    print("KẾT QUẢ:", out, flush=True)
    try:
        print("[1/4] Kiểm tra SonarQube và lưu cấu hình rule/plugin...", flush=True)
        client = utility.Client(url, token)
        if not client.call("/api/authentication/validate").get("valid"):
            raise ValueError("SonarQube token không hợp lệ.")
        before = sonar_snapshot(client, profile_project)
        profile = before["java_profile"]
        if not set(utility.ROUTES).intersection(r["key"] for r in before["active_rules"]["rules"]):
            raise ValueError("Quality Profile chưa bật rule nào được hệ thống hỗ trợ.")
        utility.save(out / "sonar_environment.json", before)
        owner = {"url": url.rstrip("/"), "server_id": before["system"].get("id"),
                 "project": PROJECT, "root": str(root), "plan_sha256": PLAN_SHA256}
        marker = work / "sonar_project_owner.json"
        found = client.call("/api/components/show", {"component": PROJECT}, missing_ok=True)
        if found is not None:
            if not marker.is_file() or read(marker) != owner:
                raise ValueError("Project đích đã tồn tại nhưng không thuộc lượt chuẩn bị này; không quét đè.")
        else:
            client.call("/api/projects/create", {"project": PROJECT, "name": "Thesis OWASP held-out 60 v1", "visibility": "private"}, post=True)
            utility.save(marker, owner)
        client.call("/api/qualityprofiles/add_project", {"language": "java", "qualityProfile": profile["name"], "project": PROJECT}, post=True)
        if client.java_profile(PROJECT)["key"] != profile["key"]:
            raise ValueError("Project chưa dùng đúng Java Quality Profile.")
        print("[2/4] Biên dịch riêng 60 mẫu đã chọn...", flush=True)
        clean_env = os.environ.copy()
        clean_env.pop("SONAR_TOKEN", None)
        versions = {}
        for executable, args in (("javac", ["-version"]), ("java", ["-version"]), ("mvn", ["-version"])):
            log = out / (executable + "_version.txt")
            utility.run([executable, *args], root, log, 30, clean_env)
            versions[executable] = log.read_text()
        versions["scanner_path"] = str(scanner)
        versions["scanner_launcher_sha256"] = sha(scanner.read_bytes())
        utility.save(out / "tool_versions.json", versions)
        cp_file = out / "dependency_classpath.txt"
        utility.run(["mvn", "-B", "org.apache.maven.plugins:maven-dependency-plugin:3.11.0:build-classpath",
                     "-Dmdep.outputFile=" + str(cp_file)], repo, out / "maven_classpath.log", 600, clean_env)
        jars = [Path(p) for p in cp_file.read_text().strip().split(os.pathsep) if p]
        if not jars or any(not p.is_file() or p.suffix != ".jar" for p in jars):
            raise ValueError("Classpath Maven không hợp lệ.")
        libraries = [repo / "target/classes", *jars]
        if any("," in str(p) for p in libraries):
            raise ValueError("Đường dẫn thư viện chứa dấu phẩy; chưa hỗ trợ.")
        classes = out / "classes"
        empty_sourcepath = out / "empty_sourcepath"
        classes.mkdir(); empty_sourcepath.mkdir()
        utility.run(["javac", "--release", "8", "-g", "-encoding", "UTF-8", "-sourcepath", str(empty_sourcepath),
                     "-cp", os.pathsep.join(map(str, libraries)), "-d", str(classes),
                     *[str(root / r["project_path"]) for r in plan["samples"]]], root, out / "javac.log", 300, clean_env)
        dependency_paths = [*jars, *sorted((repo / "target/classes").rglob("*.class")),
                            *sorted(classes.rglob("*.class"))]
        dependency_hashes = {str(p): sha(p.read_bytes()) for p in dependency_paths}
        utility.save(out / "dependency_hashes.json", dependency_hashes)
        print("[3/4] Quét SonarQube; chưa gọi AI...", flush=True)
        task_file = out / "report-task.txt"
        settings = out / "sonar-project.properties"
        settings.write_text("# Explicit fixed 60-case scope; no root project settings.\n")
        scanner_env = clean_env.copy()
        scanner_env.pop("SONAR_SCANNER_JSON_PARAMS", None)
        scanner_env["SONAR_TOKEN"] = token
        srcroot = WORK / "inputs" / COMMIT / "src/main/java"
        utility.run([str(scanner), "-Dproject.settings=" + str(settings), "-Dsonar.projectBaseDir=" + str(root),
                     "-Dsonar.host.url=" + url, "-Dsonar.projectKey=" + PROJECT, "-Dsonar.sources=" + srcroot.as_posix(),
                     "-Dsonar.inclusions=**/*.java", "-Dsonar.sourceEncoding=UTF-8", "-Dsonar.java.source=8",
                     "-Dsonar.scm.exclusions.disabled=true", "-Dsonar.scm.disabled=true",
                     "-Dsonar.java.binaries=" + str(classes), "-Dsonar.java.libraries=" + ",".join(map(str, libraries)),
                     "-Dsonar.working.directory=" + str(out / "scannerwork"),
                     "-Dsonar.scanner.metadataFilePath=" + str(task_file)], root, out / "scanner.log", 1200, scanner_env, token)
        props = dict(line.split("=", 1) for line in task_file.read_text().splitlines() if "=" in line)
        task = client.wait(props["ceTaskId"])
        if task.get("componentKey") != PROJECT or not task.get("analysisId"):
            raise ValueError("Background task không thuộc đúng project/lượt phân tích.")
        utility.save(out / "analysis_task.json", task)
        manifest["analysis_id"] = task["analysisId"]
        print("[4/4] Lấy đủ cảnh báo và thống kê cả mẫu không có cảnh báo...", flush=True)
        check_latest(client, task["analysisId"])
        components = client.paged("/api/components/tree", {"component": PROJECT, "qualifiers": "FIL", "strategy": "leaves"}, "components")
        utility.save(out / "scan_components.json", components)
        expected_components = {PROJECT + ":" + r["project_path"] for r in plan["samples"]}
        if {c.get("key") for c in components} != expected_components:
            raise ValueError("SonarQube không ghi nhận đúng 60 tệp; không coi tệp bị bỏ sót là không có cảnh báo.")
        issues = client.paged("/api/issues/search", {"componentKeys": PROJECT, "resolved": "false"}, "issues")
        if any(i.get("component") not in expected_components for i in issues):
            raise ValueError("Có cảnh báo ngoài bộ mẫu đã chọn.")
        utility.save(out / "issues.json", {"issues": issues, "total": len(issues)})
        metadata = {rule: client.call("/api/rules/show", {"key": rule}) for rule in sorted({i["rule"] for i in issues})}
        utility.save(out / "rule_metadata.json", metadata)
        report = inventory(plan, issues, utility.ROUTES)
        utility.save(out / "sample_inventory.json", report)
        after = sonar_snapshot(client, profile_project)
        utility.save(out / "sonar_environment_after.json", after)
        if after != before or client.java_profile(PROJECT)["key"] != profile["key"]:
            raise ValueError("Cấu hình SonarQube/profile/plugin thay đổi trong lượt quét.")
        check_latest(client, task["analysisId"])
        validate_sources(root, repo, planner)
        if any(not Path(p).is_file() or sha(Path(p).read_bytes()) != digest for p, digest in dependency_hashes.items()):
            raise ValueError("Bytecode/thư viện phụ thuộc đổi trong lượt quét.")
        manifest.update(state="COLLECTED", issue_count=len(issues), supported_issue_count=sum(i["rule"] in utility.ROUTES for i in issues),
                        scanned_sample_count=len(components), sonar_environment_sha256=fingerprint(before), error=None)
        print("ĐỊNH TUYẾN RULE:", report["route_counts"])
        print("MẪU CÓ CẢNH BÁO ĐÚNG NHÓM:", report["samples_with_target_warning"], "/ 60")
    except BaseException as exc:
        manifest.update(state="FAILED", error=utility.redact(exc, token))
        raise
    finally:
        manifest["finished_at"] = stamp()
        utility.save(out / "manifest.json", manifest)
        bundle = make_bundle(out, utility, token)
        print("ZIP CẦN GỬI:", bundle, flush=True)
    utility.save(done, {"run": out.relative_to(root).as_posix(), "files": {
        name: sha((out / name).read_bytes()) for name in ("manifest.json", "issues.json", "sample_inventory.json", "owasp_holdout_collection_review.zip")}})
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--collect", action="store_true")
    parser.add_argument("--benchmark", type=Path, default=Path.home() / "AI_sec_benchmarks/BenchmarkJava")
    parser.add_argument("--profile-project", default="project_1")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    repo = args.benchmark.expanduser().resolve()
    planner, utility = load_helpers(root)
    scanner = Path(os.getenv("SONAR_SCANNER_PATH") or shutil.which("sonar-scanner") or
                   str(Path.home() / "Downloads/sonar-scanner-8.0.1.6346-linux-x64/bin/sonar-scanner")).expanduser().resolve()
    plan = preflight(root, repo, scanner, planner)
    print("HOLDOUT_CHECK_OK: đúng 60 mẫu, commit và mã đã chốt; có công cụ/bytecode.", flush=True)
    if args.check:
        print("Chưa quét, chưa gọi Maven build/SonarQube/Joern/AI, chưa tạo kết quả.")
        return 0
    token = os.getenv("SONAR_TOKEN") or getpass.getpass("Nhập SonarQube User token (không hiện ký tự): ")
    if not token.strip():
        raise ValueError("Token trống.")
    url = os.getenv("SONAR_URL", "http://127.0.0.1:9000").rstrip("/")
    collect(root, repo, scanner, plan, planner, utility, url, token, args.profile_project)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Đã dừng; kết quả/log đã ghi được giữ lại.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        # Shared transport already redacts its token, including interactive input.
        message = str(exc)
        token = os.getenv("SONAR_TOKEN")
        if token:
            message = message.replace(token, "[REDACTED]")
        print("LỖI:", message, file=sys.stderr)
        sys.exit(1)
