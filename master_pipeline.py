"""Research prototype: SonarQube -> issue-specific Joern -> local LLM.

Run from the directory containing Clean_Code. Start with --collect-only.
No SonarQube issue is automatically closed or marked false positive.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
import requests

from cwe_mapper import get_cwe_info, MAPPING_VERSION
from iris_prompter import build_advanced_iris_prompt, ask_ollama_local, unknown_result, PROMPT_VERSION

PIPELINE_VERSION = "baseline-repair-1+sql-no-flow-gate-v1+sql-source-size-v2"
# Enabled only by the updated multi adapter after its configuration checks.
SQL_NO_FLOW_FALLBACK = False
# Enable only for adapters whose model requests omit the CPG text.
# This is a source-character cap, NOT an estimate of model tokens.
SQL_SIZE_GATE_SOURCE_ONLY = False


def save_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def redact(text):
    text = text or ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    token = os.getenv("SONAR_TOKEN")
    if token:
        text = text.replace(token, "REDACTED")
    return re.sub(r"\bsq[apu]_[A-Za-z0-9]+", "REDACTED", text)


def run_command(cmd, log_path, timeout, cwd=None):
    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                                errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        Path(log_path).write_text(redact(exc.stdout) + "\n" + redact(exc.stderr), encoding="utf-8")
        raise RuntimeError(f"Hết thời gian chạy công cụ; xem {log_path}") from None
    Path(log_path).write_text(redact(result.stdout) + "\n[STDERR]\n" + redact(result.stderr), encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"Công cụ trả mã {result.returncode}; xem {log_path}")
    return result.stdout


class SonarClient:
    def __init__(self, url, token):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (token, "")

    def get(self, endpoint, params=None):
        response = self.session.get(self.url + endpoint, params=params, timeout=(5, 30))
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict):
            raise RuntimeError(f"API {endpoint} không trả object JSON.")
        return body

    def wait_for_analysis(self, task_id, timeout=300):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            task = self.get("/api/ce/task", {"id": task_id}).get("task", {})
            status = task.get("status")
            if status == "SUCCESS":
                return task
            if status in ("FAILED", "CANCELED"):
                raise RuntimeError(f"SonarQube background task: {status}.")
            if status not in ("PENDING", "IN_PROGRESS"):
                raise RuntimeError(f"Trạng thái background task không hợp lệ: {status!r}")
            time.sleep(2)
        raise RuntimeError("Hết thời gian chờ SonarQube phân tích; không lấy cảnh báo cũ.")

    def fetch_issues(self, project, run_dir):
        issues, seen = [], set()
        page = 1
        while True:
            # No type filter: plugin security rules may be classified differently.
            body = self.get("/api/issues/search", {
                "componentKeys": project, "resolved": "false", "p": page, "ps": 100,
            })
            save_json(run_dir / f"issues-page-{page}.json", body)
            batch = body.get("issues")
            paging = body.get("paging", {})
            total = paging.get("total", body.get("total"))
            if not isinstance(batch, list) or type(total) is not int:
                raise RuntimeError("API issues thiếu danh sách hoặc tổng số; không dùng kết quả thiếu.")
            for issue in batch:
                key = issue.get("key")
                if not key or key in seen:
                    raise RuntimeError("Phân trang có cảnh báo trùng/thiếu key; chạy lại khi project không bị quét đồng thời.")
                seen.add(key)
                issues.append(issue)
            if len(issues) >= total:
                if len(issues) != total:
                    raise RuntimeError("Tổng số cảnh báo thay đổi trong lúc phân trang.")
                break
            if not batch:
                raise RuntimeError("API trả trang rỗng trước khi lấy đủ cảnh báo.")
            page += 1
        return issues


def resolve_issue_path(issue, project, root):
    component = issue.get("component", "")
    prefix = project + ":"
    if not component.startswith(prefix):
        raise ValueError("Component không thuộc project đã cấu hình.")
    relative = Path(component[len(prefix):])
    if relative.is_absolute():
        raise ValueError("Đường dẫn component phải tương đối.")
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()) or candidate.suffix != ".java":
        raise ValueError("Component không phải file Java trong project.")
    if not candidate.is_file():
        raise ValueError("Không tìm thấy file của cảnh báo.")
    return candidate


def issue_range(issue):
    span = issue.get("textRange") or {}
    start = span.get("startLine", issue.get("line"))
    end = span.get("endLine", start)
    if type(start) is not int or type(end) is not int or start < 1 or end < start:
        raise ValueError("Cảnh báo thiếu vùng dòng hợp lệ.")
    return start, end


def parse_joern_output(stdout):
    # Legacy evidence remains readable, but cannot authorize no-flow fallback.
    blocks = re.findall(r"CPG_RESULT_BEGIN\s*\nFLOW_COUNT=(\d+)\s*\n(.*?)\nCPG_RESULT_END", stdout, re.S)
    if len(blocks) != 1:
        raise ValueError("Joern không trả đúng một khối kết quả; xem joern.log.")
    count, paths = int(blocks[0][0]), blocks[0][1].strip()
    if bool(count) != bool(paths):
        raise ValueError("Số flow và bằng chứng Joern không nhất quán.")
    diagnostics = re.findall(
        r"CPG_GATE_BEGIN\nSINK_CALL_COUNT=(\d+)\nSINK_ARGUMENT_COUNT=(\d+)\nCPG_GATE_END",
        stdout.replace("\r\n", "\n"))
    if len(diagnostics) > 1 or ("CPG_GATE_BEGIN" in stdout and len(diagnostics) != 1):
        raise ValueError("Khối kiểm tra sink không hợp lệ.")
    calls, arguments = map(int, diagnostics[0]) if diagnostics else (None, None)
    if calls is not None and (arguments > calls or (count > 0 and not arguments)):
        raise ValueError("Số sink và flow không nhất quán.")
    return {"flow_count": count, "paths": paths, "scope": "single_file",
            "sink_call_count": calls, "sink_argument_count": arguments,
            "source_policy": "all_non_receiver_parameters_are_candidates"}


def run_joern_slicing(file_path, issue, root, artifact, image):
    start, end = issue_range(issue)
    container_file = "/project/" + file_path.relative_to(root).as_posix()
    # Exact issue range; never fall back to unrelated sinks elsewhere in file.
    script = f'''@main def exec() = {{
  importCode({json.dumps(container_file)})
  def source = cpg.method.parameter.filter(_.index > 0)
  def sinkCalls = cpg.call.name("executeQuery|executeUpdate|execute|prepareStatement|prepareCall")
    .filter(c => c.lineNumber.exists(n => n >= {start} && n <= {end}))
  def sink = sinkCalls.argument(1)
  val paths = sink.reachableByFlows(source).l
  println("CPG_GATE_BEGIN")
  println("SINK_CALL_COUNT=" + sinkCalls.size)
  println("SINK_ARGUMENT_COUNT=" + sink.size)
  println("CPG_GATE_END")
  println("CPG_RESULT_BEGIN")
  println("FLOW_COUNT=" + paths.size)
  println(paths.iterator.p.mkString("\\n"))
  println("CPG_RESULT_END")
}}
'''
    (artifact / "slice.sc").write_text(script, encoding="utf-8")
    container_name = "thesis-joern-" + uuid.uuid4().hex[:12]
    try:
        output = run_command([
            "docker", "run", "--rm", "--name", container_name, "--pull=never", "--network=none",
            "-v", f"{root}:/project:ro", "-v", f"{artifact}:/work", "-w", "/work",
            image, "joern", "--script", "/work/slice.sc",
        ], artifact / "joern.log", int(os.getenv("JOERN_TIMEOUT", "300")))
    finally:
        # Killing a timed-out docker CLI may leave its container running.
        # Remove only this invocation's uniquely named container.
        try:
            subprocess.run(["docker", "rm", "-f", container_name],
                           capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            pass
    result = parse_joern_output(output)
    save_json(artifact / "cpg_evidence.json", result)
    return result


def analyze_issue(issue, project, root, run_dir, image, index):
    info = get_cwe_info(issue.get("rule"))
    base = {"issue_id": issue.get("key"), "rule": issue.get("rule"),
            "component": issue.get("component"), "line": issue.get("line"),
            "type": issue.get("type"), "message": issue.get("message"),
            "cwe_id": info["cwe_id"], "mapping": info}
    if not info["supported"]:
        return {**base, **unknown_result(info["reason"], "UNSUPPORTED_RULE"),
                "processing_status": "SKIPPED"}
    artifact = run_dir / f"issue-{index:04d}"
    artifact.mkdir()
    started = time.perf_counter()
    try:
        path = resolve_issue_path(issue, project, root)
        raw = path.read_text(encoding="utf-8")
        (artifact / "source.java.txt").write_text(raw, encoding="utf-8")
        base["source_sha256"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        evidence = run_joern_slicing(path, issue, root, artifact, image)
        base["flow_count"] = evidence["flow_count"]
        fallback = (SQL_NO_FLOW_FALLBACK and evidence["flow_count"] == 0
                    and evidence.get("sink_call_count") == 1
                    and evidence.get("sink_argument_count") == 1)
        base.update(sql_gate_version="sql-no-flow-gate-v1",
                    sink_call_count=evidence.get("sink_call_count"),
                    sink_argument_count=evidence.get("sink_argument_count"),
                    analysis_mode=("SOURCE_ONLY_NO_FLOW" if fallback else
                                   "FLOW_PRESENT" if evidence["flow_count"] else "NOT_ANALYZED"),
                    llm_invoked=False)
        size_chars = len(raw) + (0 if SQL_SIZE_GATE_SOURCE_ONLY else len(evidence["paths"]))
        base["context_size_gate"] = {
            "version": "sql-source-size-v2" if SQL_SIZE_GATE_SOURCE_ONLY else "legacy-source-plus-cpg-v1",
            "source_chars": len(raw), "cpg_chars": len(evidence["paths"]),
            "counted_chars": size_chars, "limit_chars": 10000,
            "is_token_count": False,
        }
        if not evidence["flow_count"] and not fallback:
            result = unknown_result("Không có flow phù hợp vùng dòng cảnh báo; chưa đủ kết luận an toàn.", "NO_MATCHING_FLOW")
        elif size_chars > 10000:
            result = unknown_result("Đầu vào vượt giới hạn ký tự sơ bộ; cần kiểm tra ngữ cảnh trước khi phân tích.", "CONTEXT_TOO_LARGE")
        else:
            prompt_issue = {**issue, "line": issue_range(issue)[0]}
            prompt = build_advanced_iris_prompt(issue["rule"], raw, evidence["paths"], prompt_issue)
            (artifact / "prompt.txt").write_text(prompt, encoding="utf-8")
            base["llm_invoked"] = True
            result = ask_ollama_local(prompt, len(raw.splitlines()))
            result["analysis_mode"] = base["analysis_mode"]
            result["cpg_usage"] = ("sink_location_gate_only_no_flow_not_sent_to_llm" if fallback
                                   else result.get("cpg_usage", "flow_evidence_available"))
            result["requires_review"] = True
            result["analysis_limitations"] = ([
                "Joern found one call and its first argument at the issue range, but no parameter-to-sink flow.",
                "AI assessed source code; absence of a flow is not evidence of safety.",
                "Call-name matching is not full Java type resolution."
            ] if fallback else [])
            save_json(artifact / "llm_result.json", result)
            # Do not duplicate full source/prompt/envelope in the summary.
            result = {k: v for k, v in result.items() if k not in ("request_payload", "ollama_response", "raw_output")}
    except (OSError, ValueError, RuntimeError) as exc:
        result = unknown_result(redact(str(exc)), "PROCESSING_ERROR")
    kind = result.get("error_kind")
    status = ("ABSTAINED" if kind in {"NO_MATCHING_FLOW", "CONTEXT_TOO_LARGE", "CONTEXT_LIMIT", "INSUFFICIENT_EVIDENCE"}
              else "ERROR" if kind else "ANALYZED")
    return {**base, **result, "artifact_dir": artifact.name,
            "processing_status": status,
            "total_seconds": round(time.perf_counter() - started, 3)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collect-only", action="store_true", help="Chỉ quét và lưu cảnh báo/metadata, chưa chạy Joern/LLM")
    args = parser.parse_args()
    root = Path.cwd().resolve()
    run_dir = root / "runs" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6])
    run_dir.mkdir(parents=True)
    manifest = {"pipeline_version": PIPELINE_VERSION, "prompt_version": PROMPT_VERSION,
                "mapping_version": MAPPING_VERSION, "collect_only": args.collect_only,
                "state": "STARTED", "started_at": datetime.now(timezone.utc).isoformat(),
                "limitations": ["Single-file CPG; JDBC sinks at issue line only.",
                    "No Security Hotspots API in this version.",
                    "No concurrent scans of the same SonarQube project.",
                    "Line-reference validation does not prove semantic correctness."]}
    save_json(run_dir / "manifest.json", manifest)
    try:
        token = os.getenv("SONAR_TOKEN")
        if not token:
            raise RuntimeError("Thiếu SONAR_TOKEN. Đặt biến môi trường trước khi chạy.")
        url = os.getenv("SONAR_URL", "http://127.0.0.1:9000")
        project = os.getenv("SONAR_PROJECT_KEY", "project_1")
        scanner = os.getenv("SONAR_SCANNER_PATH", "/home/khanh/Downloads/sonar-scanner-8.0.1.6346-linux-x64/bin/sonar-scanner")
        source_dir = root / "Clean_Code"
        java_files = sorted(source_dir.rglob("*.java"))
        if not java_files:
            raise RuntimeError("Không tìm thấy Clean_Code/*.java trong thư mục hiện tại.")
        manifest.update({"project": project, "sonar_url": url,
                         "source_hashes": {str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest() for f in java_files}})
        binary_dir = run_dir / "classes"
        binary_dir.mkdir()
        print("[1/4] Biên dịch Java...")
        # Fresh output directory prevents stale .class files from masking failure.
        run_command(["javac", "-g", "-d", str(binary_dir)] + [str(f) for f in java_files],
                    run_dir / "javac.log", 120, root)
        print("[2/4] Quét SonarQube...")
        task_file = run_dir / "report-task.txt"
        run_command([scanner, f"-Dsonar.host.url={url}", f"-Dsonar.projectKey={project}",
                     "-Dsonar.sources=./Clean_Code", "-Dsonar.inclusions=**/*.java",
                     f"-Dsonar.java.binaries={binary_dir}",
                     f"-Dsonar.scanner.metadataFilePath={task_file}"],
                    run_dir / "scanner.log", 600, root)
        # SonarScanner inherits SONAR_TOKEN; never place it in command arguments.
        properties = dict(line.split("=", 1) for line in task_file.read_text().splitlines() if "=" in line)
        task_id = properties.get("ceTaskId")
        if not task_id:
            raise RuntimeError("Scanner không xuất ceTaskId; không thể xác minh lần quét.")
        sonar = SonarClient(url, token)
        print("[3/4] Chờ background task và lấy đủ các trang cảnh báo...")
        task = sonar.wait_for_analysis(task_id, int(os.getenv("SONAR_WAIT_TIMEOUT", "300")))
        save_json(run_dir / "analysis_task.json", task)
        manifest["analysis_id"] = task.get("analysisId")
        issues = sonar.fetch_issues(project, run_dir)
        save_json(run_dir / "issues.json", {"issues": issues, "total": len(issues)})
        rules = {}
        for rule in sorted({i["rule"] for i in issues}):
            try:
                rules[rule] = sonar.get("/api/rules/show", {"key": rule})
            except (requests.RequestException, ValueError, RuntimeError):
                rules[rule] = {"metadata_error": "Không lấy được metadata; cần kiểm tra trên SonarQube."}
        save_json(run_dir / "rule_metadata.json", rules)
        inventory = [{"rule": rule, "count": count, **get_cwe_info(rule)}
                     for rule, count in Counter(i["rule"] for i in issues).items()]
        save_json(run_dir / "rule_inventory.json", inventory)
        for row in inventory:
            print(f"  {row['rule']}: {row['count']} | hỗ trợ={row['supported']}")
        results = []
        if not args.collect_only:
            image = os.getenv("JOERN_IMAGE", "ghcr.io/joernio/joern:nightly")
            supported = any(get_cwe_info(i.get("rule"))["supported"] for i in issues)
            image_error = None
            if supported:
                try:
                    # Resolve mutable nightly tag to an immutable local image ID for this run.
                    details = json.loads(run_command(["docker", "image", "inspect", image], run_dir / "joern_image.log", 30))
                    image = details[0]["Id"]
                    manifest["joern_image_id"] = image
                except (OSError, ValueError, RuntimeError, KeyError, IndexError) as exc:
                    image_error = redact(str(exc))
                try:
                    r = requests.get(os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/") + "/api/tags", timeout=(5, 10))
                    r.raise_for_status()
                    save_json(run_dir / "ollama_models.json", r.json())
                except (requests.RequestException, ValueError):
                    manifest["ollama_metadata_error"] = True
            print("[4/4] Phân tích cảnh báo SQL Injection...")
            for index, issue in enumerate(issues, 1):
                if image_error and get_cwe_info(issue.get("rule"))["supported"]:
                    result = {"issue_id": issue.get("key"), "rule": issue.get("rule"),
                              "component": issue.get("component"), "line": issue.get("line"),
                              "cwe_id": "CWE-89", "processing_status": "ERROR",
                              **unknown_result(image_error, "JOERN_UNAVAILABLE")}
                else:
                    result = analyze_issue(issue, project, root, run_dir, image, index)
                results.append(result)
                save_json(run_dir / "ai_results.json", results)
                print(f"  {result['issue_id']}: {result['verdict']} ({result['processing_status']})")
            save_json(run_dir / "ai_results.json", results)
        manifest.update({"state": "COLLECTED" if args.collect_only else "COMPLETED",
                         "issue_count": len(issues),
                         "supported_issue_count": sum(get_cwe_info(i.get("rule"))["supported"] for i in issues),
                         "result_count": len(results),
                         "verdict_counts": dict(Counter(r["verdict"] for r in results)),
                         "processing_status_counts": dict(Counter(r["processing_status"] for r in results))})
        print(f"Kết quả: {run_dir}")
        if not manifest["supported_issue_count"]:
            print("Chưa có rule SQL Injection được hỗ trợ. Xem rule_inventory.json và rule_metadata.json; đây không phải kết luận code an toàn.")
        return 0
    except (OSError, RuntimeError, ValueError, requests.RequestException) as exc:
        manifest.update({"state": "FAILED", "error": redact(str(exc))})
        print(f"[LỖI] {redact(str(exc))}\nXem log trong {run_dir}", file=sys.stderr)
        return 1
    finally:
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        save_json(run_dir / "manifest.json", manifest)


if __name__ == "__main__":
    sys.exit(main())
