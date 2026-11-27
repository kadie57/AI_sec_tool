"""Run the frozen 20-case OWASP Path Traversal evaluation locally."""

import argparse
from datetime import datetime, timezone
from getpass import getpass
from hashlib import sha256
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from uuid import uuid4
from zipfile import ZipFile

import requests

from common.joern_project import java_dependencies
from common.ollama_review import URL, digest, read, run_requests
from common.run_io import redact, run_command, save_json
from common.sonar_collection import SonarClient

from .path_llm_experiment import (
    MODEL, OPERAND_FIRST_LAYOUT, OPTIONS, PATH_SCHEMA, PROMPT, assess_response, plan, score,
)
from .path_project_flow_experiment import export_project_flows, stage_helpers
from .prepare_path_evidence import RULES, export_evidence

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "datasets/owasp/splits/path22-holdout20"
SOURCES = DATASET / "sources"
REFERENCE = DATASET / "reference_labels.json"
BENCHMARK = Path.home() / "AI_sec_benchmarks/BenchmarkJava"
SONAR_URL = "http://127.0.0.1:9000"
SCANNER_RELEASE = "8.0.1.6346"
SCANNER_BUNDLE = f"sonar-scanner-{SCANNER_RELEASE}-linux-x64"
SCANNER_ZIP = Path.home() / "Downloads" / f"sonar-scanner-cli-{SCANNER_RELEASE}-linux-x64.zip"


def file_sha(path):
    return sha256(path.read_bytes()).hexdigest()


def check_inputs(frozen):
    actual = {path.relative_to(SOURCES).as_posix(): file_sha(path) for path in SOURCES.rglob("*.java")}
    if actual != frozen["source_hashes"] or len(actual) != 20:
        raise ValueError("Mã nguồn khác tập OWASP CWE-22 đã chốt.")
    if file_sha(REFERENCE) != frozen["reference_labels_sha256"]:
        raise ValueError("Nhãn tham chiếu khác bản đã chốt.")
    jars = [Path(entry["path"]) for entry in frozen["support_classpath"]]
    if java_dependencies(jars) != frozen["support_classpath"]:
        raise ValueError("Thư viện Java khác bản đã chốt.")
    expected = {"model": MODEL, "options": OPTIONS, "prompt_sha256": digest(PROMPT),
                "schema_sha256": digest(PATH_SCHEMA), "evidence_layout": OPERAND_FIRST_LAYOUT}
    if any(frozen["review"][key] != value for key, value in expected.items()):
        raise ValueError("Cấu hình Qwen khác bản operand-first đã chốt.")
    return jars


def compile_sources(frozen, jars, work):
    files = {path: {"sha256": value} for path, value in frozen["source_hashes"].items()}
    helper_root = work / "helpers"
    helpers = stage_helpers(BENCHMARK, frozen["benchmark_commit"], files, helper_root)
    classes = work / "classes"
    classes.mkdir()
    run_command(["javac", "--release", "8", "-encoding", "UTF-8", "-proc:none", "-g",
                 "-cp", os.pathsep.join(map(str, jars)), "-d", str(classes),
                 *[str(SOURCES / path) for path in files], *[str(helper_root / path) for path in helpers]],
                work / "javac.log", 180)
    return classes


def scanner_command(work):
    launcher = os.getenv("SONAR_SCANNER_PATH") or shutil.which("sonar-scanner")
    if launcher:
        return [str(Path(launcher).expanduser().resolve())]
    jar_path = f"lib/sonar-scanner-cli-{SCANNER_RELEASE}.jar"
    if not SCANNER_ZIP.is_file():
        raise ValueError(f"Cần SONAR_SCANNER_PATH hoặc bản Scanner tại {SCANNER_ZIP}")
    with ZipFile(SCANNER_ZIP) as bundle:
        jar = work / Path(jar_path).name
        jar.write_bytes(bundle.read(f"{SCANNER_BUNDLE}/{jar_path}"))
    return ["java", "-Djava.awt.headless=true", "-cp", str(jar), "org.sonarsource.scanner.cli.Main"]


def post(client, endpoint, **fields):
    response = client.session.post(client.url + endpoint, data=fields, timeout=(5, 30), allow_redirects=False)
    response.raise_for_status()


def verify_profile(client, expected, rule, project=None):
    filters = {"language": "java"}
    if project:
        filters["project"] = project
    profiles = client.get("/api/qualityprofiles/search", filters)["profiles"]
    match = next((item for item in profiles if item.get("key") == expected["key"]), None)
    if not match:
        raise ValueError(f"Không tìm thấy Java Quality Profile {expected['name']}.")
    if not project:
        page = 1
        while True:
            response = client.get("/api/rules/search", {
                "activation": "true", "qprofile": match["key"], "ps": 100, "p": page,
            })
            if any(item.get("key") == rule for item in response["rules"]):
                break
            total = response.get("paging", {}).get("total", response.get("total"))
            if not response["rules"] or (type(total) is int and page * 100 >= total):
                raise ValueError(f"Quality Profile chưa bật {rule}.")
            page += 1
    return {key: match.get(key) for key in expected}


def collect(frozen, jars, classes, scanner, output, project):
    token = os.getenv("SONAR_TOKEN") or getpass("Nhập SonarQube User token (không hiện ký tự): ")
    if not token:
        raise ValueError("Cần SonarQube User token.")
    expected_profile = frozen["sonar_java_profile"]
    client = SonarClient(SONAR_URL, token)
    with client.session:
        client.session.trust_env = False
        if not client.get("/api/authentication/validate").get("valid"):
            raise ValueError("SonarQube User token không hợp lệ.")
        profile = verify_profile(client, expected_profile, frozen["sonar_path_rule"])
        post(client, "/api/projects/create", project=project, name=project, visibility="private")
        post(client, "/api/qualityprofiles/add_project",
             language="java", qualityProfile=profile["name"], project=project)
        if verify_profile(client, expected_profile, frozen["sonar_path_rule"], project) != profile:
            raise ValueError("Java Quality Profile của project khác cấu hình đã kiểm tra.")

        task_file = output / "report-task.txt"
        previous_token = os.environ.get("SONAR_TOKEN")
        os.environ["SONAR_TOKEN"] = token
        try:
            run_command([*scanner, f"-Dsonar.host.url={SONAR_URL}", f"-Dsonar.projectKey={project}",
                         f"-Dsonar.projectBaseDir={SOURCES}", "-Dsonar.sources=src/main/java",
                         "-Dsonar.inclusions=**/*.java", "-Dsonar.java.source=8", "-Dsonar.sourceEncoding=UTF-8",
                         "-Dsonar.scm.disabled=true", "-Dsonar.scm.exclusions.disabled=true",
                         f"-Dsonar.java.binaries={classes}", f"-Dsonar.java.libraries={','.join(map(str, jars))}",
                         f"-Dsonar.working.directory={output / 'scannerwork'}",
                         f"-Dsonar.scanner.metadataFilePath={task_file}"],
                        output / "scanner.log", 1200, SOURCES)
        finally:
            if previous_token is None:
                os.environ.pop("SONAR_TOKEN", None)

        properties = dict(line.split("=", 1) for line in task_file.read_text().splitlines() if "=" in line)
        task = client.wait_for_analysis(properties["ceTaskId"])
        if task.get("componentKey") != project or not task.get("analysisId"):
            raise ValueError("Background task khác project đã quét.")
        save_json(output / "analysis_task.json", task)
        expected_files = {f"{project}:{path}" for path in frozen["source_hashes"]}
        scanned = client.get("/api/components/tree", {
            "component": project, "qualifiers": "FIL", "strategy": "leaves", "ps": 100,
        })["components"]
        if {item["key"] for item in scanned} != expected_files:
            raise ValueError("SonarQube chưa ghi nhận đầy đủ 20 tệp đã chốt.")
        issues = client.fetch_issues(project, output)
        if any(item.get("component") not in expected_files for item in issues):
            raise ValueError("SonarQube trả cảnh báo ngoài 20 tệp đã chốt.")
        latest = client.get("/api/project_analyses/search", {"project": project, "ps": 1})["analyses"]
        if not latest or latest[0]["key"] != task["analysisId"]:
            raise ValueError("SonarQube đã nhận một lượt phân tích khác cho project này.")
        if verify_profile(client, expected_profile, frozen["sonar_path_rule"], project) != profile:
            raise ValueError("Java Quality Profile thay đổi trong lúc quét.")
        check_inputs(frozen)
        save_json(output / "scan_components.json", scanned)
        save_json(output / "issues.json", {"issues": issues, "total": len(issues)})
        path_warnings = sum(item["rule"] in RULES for item in issues)
        save_json(output / "manifest.json", {
            "state": "COLLECTED", "analysis_id": task["analysisId"], "project": project,
            "benchmark_commit": frozen["benchmark_commit"], "source_hashes": frozen["source_hashes"],
            "sonar_java_profile": profile, "sonar_path_rule": frozen["sonar_path_rule"],
            "sonar_server_version": client.get("/api/system/status").get("version"),
            "scanned_sample_count": len(expected_files), "issue_count": len(issues),
            "cwe22_warning_count": path_warnings,
        })
    return path_warnings


def check_model(expected):
    with requests.Session() as session:
        session.trust_env = False
        response = session.get(f"{URL}/api/tags", timeout=(5, 10), allow_redirects=False)
        response.raise_for_status()
        if not any((item.get("name") or item.get("model")) == MODEL and item.get("digest") == expected
                   for item in response.json()["models"]):
            raise ValueError(f"Ollama cần đúng digest đã chốt cho {MODEL}.")


def reuse_collection(previous, destination, frozen):
    source = previous / "collection"
    saved = read(source / "manifest.json")
    if (saved.get("state") != "COLLECTED" or not saved.get("analysis_id")
            or any(saved.get(key) != frozen[key] for key in ("source_hashes", "benchmark_commit", "sonar_path_rule"))
            or saved.get("scanned_sample_count") != len(frozen["source_hashes"])):
        raise ValueError("Lượt cũ phải có bộ cảnh báo SonarQube từ đúng 20 mẫu đã chốt.")
    evidence_manifest = previous / "evidence" / "manifest.json"
    expected_hashes = read(evidence_manifest).get("collection_hashes", {}) if evidence_manifest.is_file() else {}
    for name in ("manifest.json", "issues.json"):
        raw = (source / name).read_bytes()
        if name in expected_hashes and sha256(raw).hexdigest() != expected_hashes[name]:
            raise ValueError(f"Cảnh báo lưu tại {source} đã thay đổi sau lần dựng bằng chứng.")
        (destination / name).write_bytes(raw)
    return saved["cwe22_warning_count"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Kiểm tra dữ liệu, biên dịch Java và thử trình quét.")
    mode.add_argument("--prepare-only", action="store_true", help="Dừng sau khi chuẩn bị bằng chứng và dry-run.")
    parser.add_argument("--from-run", type=Path, help="Dùng lại cảnh báo SonarQube của lượt chạy đã lưu.")
    args = parser.parse_args()
    frozen = read(DATASET / "plan.json")
    jars = check_inputs(frozen)
    if args.check:
        with TemporaryDirectory(prefix="owasp-path22-build-") as tmp:
            work = Path(tmp)
            scanner = scanner_command(work)
            run_command([*scanner, "--version"], work / "scanner-version.log", 30)
            classes = compile_sources(frozen, jars, work)
            print(f"OK: 20 mẫu đã chốt; biên dịch được {len(list(classes.rglob('*.class')))} lớp Java.")
        return

    key = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:6]
    out = ROOT / "runs" / f"owasp-cwe22-holdout20-{key}"
    out.mkdir()
    save_json(out / "plan.json", frozen)
    print(f"Lượt chạy: {out}", flush=True)
    collection = out / "collection"
    collection.mkdir()
    if args.from_run:
        print("[1/4] Dùng lại cảnh báo SonarQube của lượt đã lưu...", flush=True)
        warnings = reuse_collection(args.from_run.resolve(), collection, frozen)
    else:
        print("[1/4] Biên dịch tập mẫu và thu thập cảnh báo SonarQube...", flush=True)
        with TemporaryDirectory(prefix="owasp-path22-build-") as tmp:
            scanner = scanner_command(Path(tmp))
            classes = compile_sources(frozen, jars, out)
            warnings = collect(frozen, jars, classes, scanner, collection, f"thesis_owasp_cwe22_holdout20_{key}")
    print(f"SonarQube: {warnings} cảnh báo CWE-22 trên 20 mẫu.", flush=True)
    if not warnings:
        print("Đã lưu lượt quét. Không có cảnh báo CWE-22 để gửi Qwen.")
        return

    print("[2/4] Tạo bằng chứng Java và Joern...", flush=True)
    evidence, base = out / "evidence", out / "base-evidence"
    export_evidence(collection, SOURCES, base, jars)
    export_project_flows(base / "path_evidence.jsonl", collection, SOURCES, evidence,
                         frozen["joern_image_id"], BENCHMARK, jars, value_facts=True)
    evidence_file = evidence / "path_evidence.jsonl"
    config, items = plan(evidence_file, evidence_layout=OPERAND_FIRST_LAYOUT)
    print("[3/4] Dựng và kiểm tra yêu cầu gửi Qwen...", flush=True)
    run_requests(items, out / "dry-run", 900, config.copy(), PROMPT, PATH_SCHEMA, assess_response, dry_run=True)
    if args.prepare_only:
        return

    print("[4/4] Chạy Qwen và chấm theo nhãn OWASP...", flush=True)
    check_model(frozen["review"]["model_digest"])
    run_requests(items, out / "llm", 900, config, PROMPT, PATH_SCHEMA, assess_response)
    if config["model_digest"] != frozen["review"]["model_digest"]:
        raise ValueError("Digest Qwen khác phiên bản đã chốt.")
    report = score(evidence_file, out / "llm", collection, REFERENCE)
    save_json(out / "summary.json", report)
    print(report["qwen"], flush=True)
    print(out / "summary.json")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, requests.RequestException, subprocess.SubprocessError) as exc:
        raise SystemExit(redact(str(exc))) from None
