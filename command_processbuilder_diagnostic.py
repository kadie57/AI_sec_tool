"""Inspect Joern's ProcessBuilder representation using saved Sonar warnings.

Run inside ~/AI_sec_tool:
  python3 command_processbuilder_diagnostic.py --from-run runs/<owasp-collection>
Add --check for offline input verification only. Requires an existing Docker/
Joern image for actual collection. No Ollama, Sonar API, or Java program execution.
Only creates diagnostic artifacts. Does not change pipeline code or verdicts.
"""
import argparse
import base64
from collections import Counter
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid
import zipfile

VERSION = "command-processbuilder-diagnostic-v1"
RULE = "findsecbugs:COMMAND_INJECTION"
BEGIN = "COMMAND_DIAGNOSTIC_V1_BEGIN"
END = "COMMAND_DIAGNOSTIC_V1_END"

SCRIPT = r'''@main def exec() = {
  importCode("/work/input")
  def enc(s: String): String = java.util.Base64.getEncoder.encodeToString(s.getBytes(java.nio.charset.StandardCharsets.UTF_8))
  def sources = cpg.method.parameter.filter(_.index > 0)
  val first = __FIRST__
  val last = __LAST__
  val calls = cpg.call.filter(c =>
    c.lineNumber.exists(n => n >= first && n <= last) ||
    Set("command", "start", "exec", "add", "getTheValue").contains(c.name) ||
    c.code.contains("ProcessBuilder") || c.methodFullName.contains("ProcessBuilder")
  ).l
  println("COMMAND_DIAGNOSTIC_V1_BEGIN")
  sources.l.foreach(p => println("PARAM\t" + p.id + "\t" + p.lineNumber.getOrElse(-1) + "\t" + p.index + "\t" + enc(p.name) + "\t" + enc(p.code)))
  calls.foreach { c =>
    println("CALL\t" + c.id + "\t" + c.lineNumber.getOrElse(-1) + "\t" + enc(c.name) + "\t" + enc(c.methodFullName) + "\t" + enc(c.code))
    c.argument.l.foreach { a =>
      println("ARG\t" + c.id + "\t" + a.argumentIndex + "\t" + a.lineNumber.getOrElse(-1) + "\t" + enc(a.code))
    }
    if (c.lineNumber.exists(n => n >= first && n <= last) || c.name == "start") {
      c.argument.l.foreach { a =>
        try {
          val paths = cpg.call.filter(_.id == c.id).argument.filter(_.argumentIndex == a.argumentIndex).reachableByFlows(sources).l
          println("FLOW\t" + c.id + "\t" + a.argumentIndex + "\t" + paths.size + "\t" + enc(paths.iterator.p.mkString("\n")))
        } catch {
          case error: Exception => println("FLOW_ERROR\t" + c.id + "\t" + a.argumentIndex + "\t" + enc(error.toString))
        }
      }
    }
  }
  println("COMMAND_DIAGNOSTIC_V1_END")
}
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(data):
    return sha(json.dumps(data, sort_keys=True, ensure_ascii=False).encode())


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def checked_command(args, cwd=None, timeout=30):
    proc = subprocess.run(args, cwd=cwd, capture_output=True, timeout=timeout)
    if proc.returncode:
        raise ValueError(proc.stderr.decode("utf-8", "replace")[-1800:] or "Lệnh kiểm tra thất bại.")
    return proc.stdout


def span(issue):
    location = issue.get("textRange") or {}
    start = location.get("startLine", issue.get("line"))
    end = location.get("endLine", start)
    if type(start) is not int or type(end) is not int or not 1 <= start <= end:
        raise ValueError("Cảnh báo thiếu vùng dòng hợp lệ.")
    return start, end


def prepare(root, collection, benchmark):
    manifest = read(collection / "manifest.json")
    bundle = read(collection / "issues.json")
    if manifest.get("state") not in ("COLLECTED", "COMPLETED") or not manifest.get("analysis_id"):
        raise ValueError("Cần lượt SonarQube đã thu thập xong.")
    commit = manifest.get("benchmark_commit", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Lượt này thiếu benchmark_commit; cần lượt thu thập OWASP.")
    current = checked_command(["git", "rev-parse", "HEAD"], cwd=benchmark).decode().strip()
    if current != commit:
        raise ValueError("Repository OWASP khác commit của lần quét; chưa tạo chẩn đoán.")
    issues = bundle if isinstance(bundle, list) else bundle["issues"]
    items, helpers = [], {}
    project = manifest["project"]
    for issue in issues:
        if issue.get("rule") != RULE:
            continue
        component = issue["component"]
        if not component.startswith(project + ":"):
            raise ValueError("Component không thuộc project đã quét.")
        rel = component[len(project) + 1:]
        path = (root / rel).resolve()
        if not path.is_relative_to(root) or path.suffix != ".java":
            raise ValueError("Đường dẫn nguồn không hợp lệ.")
        raw = path.read_bytes()
        if manifest.get("source_hashes", {}).get(rel) != sha(raw):
            raise ValueError("Nguồn khác lần quét: " + rel)
        original = "src/main/java/org/owasp/benchmark/testcode/" + path.name
        if checked_command(["git", "show", commit + ":" + original], cwd=benchmark) != raw:
            raise ValueError("Nguồn khác bản gốc tại commit OWASP: " + path.name)
        if span(issue)[1] > len(raw.decode("utf-8").splitlines()):
            raise ValueError("Dòng cảnh báo vượt mã nguồn.")
        # Read-only, one-hop context inventory, not a Java name resolver.
        for name in sorted(set(re.findall(r"\borg\.owasp\.benchmark\.helpers\.([A-Za-z_$][A-Za-z0-9_$]*)", raw.decode("utf-8")))):
            helper = "src/main/java/org/owasp/benchmark/helpers/" + name + ".java"
            if helper not in helpers:
                proc = subprocess.run(["git", "show", commit + ":" + helper], cwd=benchmark, capture_output=True, timeout=30)
                if proc.returncode == 0:
                    helpers[helper] = proc.stdout
        items.append((issue, raw))
    if not items or len({i["key"] for i, _ in items}) != len(items):
        raise ValueError("Không có cảnh báo Command hoặc key bị trùng.")
    if len(items) > 6:
        raise ValueError("Chẩn đoán này giới hạn tối đa 6 cảnh báo; cần chọn lượt nhỏ.")
    return manifest, items, helpers


def parse_output(stdout):
    if stdout.count(BEGIN) != 1 or stdout.count(END) != 1:
        raise ValueError("Thiếu hoặc trùng mốc kết quả; gửi joern.log để kiểm tra.")
    segment = stdout.split(BEGIN, 1)[1].split(END, 1)[0]
    calls, parameters, flows, errors = {}, [], [], []
    decode = lambda value: base64.b64decode(value, validate=True).decode("utf-8")
    for line in segment.splitlines():
        cells = line.split("\t")
        kind = cells[0]
        if kind == "PARAM" and len(cells) == 6:
            parameters.append(dict(id=int(cells[1]), line=int(cells[2]), index=int(cells[3]), name=decode(cells[4]), code=decode(cells[5])))
        elif kind == "CALL" and len(cells) == 6:
            ident = int(cells[1])
            if ident in calls:
                raise ValueError("Trùng call node trong kết quả.")
            calls[ident] = dict(id=ident, line=int(cells[2]), name=decode(cells[3]), method_full_name=decode(cells[4]), code=decode(cells[5]), arguments=[])
        elif kind == "ARG" and len(cells) == 5:
            calls[int(cells[1])]["arguments"].append(dict(index=int(cells[2]), line=int(cells[3]), code=decode(cells[4])))
        elif kind == "FLOW" and len(cells) == 5:
            count = int(cells[3]); paths = decode(cells[4])
            if count < 0 or (count > 0 and not paths.strip()):
                raise ValueError("Số luồng và nội dung luồng không khớp.")
            flows.append(dict(call_id=int(cells[1]), argument_index=int(cells[2]), flow_count=count, paths=paths))
        elif kind == "FLOW_ERROR" and len(cells) == 4:
            errors.append(dict(call_id=int(cells[1]), argument_index=int(cells[2]), error=decode(cells[3])))
        elif kind in {"PARAM", "CALL", "ARG", "FLOW", "FLOW_ERROR"}:
            raise ValueError("Bản ghi Joern không đúng cấu trúc.")
    for item in flows + errors:
        if item["call_id"] not in calls:
            raise ValueError("Luồng không có call node tương ứng.")
    return dict(calls=list(calls.values()), parameters=parameters, flows=flows, flow_errors=errors,
                source_policy="all_non_receiver_parameters_are_candidates_not_proven_external",
                scope="single_file; helper context saved separately, not imported into this CPG",
                limitation="Flows do not prove shell execution, external control or exploitability; zero flows do not prove safety.")


def diagnose(folder, issue, raw, image):
    start, end = span(issue)
    (folder / "input").mkdir(parents=True, exist_ok=True)
    name = issue["component"].rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    (folder / "input" / name).write_bytes(raw)
    (folder / "source.java.txt").write_bytes(raw)
    (folder / "diagnostic.sc").write_text(SCRIPT.replace("__FIRST__", str(start)).replace("__LAST__", str(end)), encoding="utf-8")
    container = "command-diag-" + uuid.uuid4().hex[:12]
    command = ["docker", "run", "--rm", "--name", container, "--pull=never", "--network=none",
               "-v", str(folder) + ":/work", "-w", "/work", image, "joern", "--script", "/work/diagnostic.sc"]
    row = dict(issue_id=issue["key"], component=issue["component"], line=start,
               source_sha256=sha(raw), status="ERROR", error=None)
    try:
        proc = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=int(os.getenv("JOERN_TIMEOUT", "300")))
        (folder / "joern.log").write_text(proc.stdout + "\n[STDERR]\n" + proc.stderr, encoding="utf-8")
        if proc.returncode:
            raise ValueError("Joern lỗi; xem joern.log trong ZIP.")
        evidence = parse_output(proc.stdout)
        save(folder / "cpg_diagnostic.json", evidence)
        row.update(status="PARTIAL" if evidence["flow_errors"] else "COLLECTED",
                   call_count=len(evidence["calls"]), flow_query_count=len(evidence["flows"]),
                   flow_error_count=len(evidence["flow_errors"]))
    except subprocess.TimeoutExpired as exc:
        def as_text(value): return value.decode("utf-8", "replace") if isinstance(value, bytes) else (value or "")
        (folder / "joern.log").write_text(as_text(exc.stdout) + "\n[STDERR]\n" + as_text(exc.stderr), encoding="utf-8")
        row["error"] = "JOERN_TIMEOUT"
    except (ValueError, OSError, KeyError, UnicodeError) as exc:
        row["error"] = str(exc)
    finally:
        try:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            pass
    return row


def package(output):
    destination = output / "command_processbuilder_review.zip"
    names = {"context.json", "summary.json", "issues.json", "helper_inventory.json"}
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(names):
            if (output / name).is_file(): archive.write(output / name, name)
        for folder in sorted(output.glob("issue-*")):
            for name in ("source.java.txt", "diagnostic.sc", "joern.log", "cpg_diagnostic.json", "result.json"):
                if (folder / name).is_file(): archive.write(folder / name, folder.name + "/" + name)
        for path in sorted((output / "helper_context").glob("*.java")):
            archive.write(path, "helper_context/" + path.name)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-run", type=Path, required=True)
    parser.add_argument("--benchmark-root", type=Path, default=Path.home() / "AI_sec_benchmarks/BenchmarkJava")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root, collection = Path.cwd().resolve(), args.from_run.resolve()
    old, items, helpers = prepare(root, collection, args.benchmark_root.expanduser().resolve())
    print(f"COMMAND_DIAGNOSTIC: {len(items)} cảnh báo; nguồn khớp lần quét và commit OWASP.", flush=True)
    if args.check:
        print("CHECK_OK: chỉ đọc file/git; chưa chạy Docker/Joern, chưa tạo kết quả.")
        return 0
    image = json.loads(checked_command(["docker", "image", "inspect", os.getenv("JOERN_IMAGE", "ghcr.io/joernio/joern:nightly")]))[0]["Id"]
    context = dict(version=VERSION, script_sha256=sha(Path(__file__).read_bytes()),
                   collection=str(collection), manifest_sha256=sha((collection / "manifest.json").read_bytes()),
                   issues_sha256=sha((collection / "issues.json").read_bytes()), benchmark_commit=old["benchmark_commit"],
                   joern_image_id=image, source_hashes={i["component"]: sha(raw) for i, raw in items},
                   helper_hashes={name: sha(raw) for name, raw in helpers.items()},
                   command_module_sha256=sha((root / "command_triage_v2.py").read_bytes()) if (root / "command_triage_v2.py").is_file() else None)
    output = root / "experiments/command_processbuilder_diagnostic" / (collection.name + "-" + fingerprint(context)[:12])
    output.mkdir(parents=True, exist_ok=True)
    with (output / "run.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (output / "context.json").exists() and read(output / "context.json") != context:
            raise ValueError("Context khác kết quả đã lưu; không ghi đè.")
        save(output / "context.json", context)
        save(output / "issues.json", {"issues": [i for i, _ in items]})
        inventory = []
        (output / "helper_context").mkdir(exist_ok=True)
        for original, raw in helpers.items():
            dest = output / "helper_context" / Path(original).name
            dest.write_bytes(raw)
            inventory.append(dict(repository_path=original, source_sha256=sha(raw), saved_as=str(dest.relative_to(output)),
                                  provenance="git object at scanned benchmark_commit; one-hop textual reference only"))
        save(output / "helper_inventory.json", inventory)
        summary = dict(version=VERSION, state="IN_PROGRESS", results=[], ai_calls=0, sonar_scans=0,
                       started_at=datetime.now(timezone.utc).isoformat(), purpose="API and data-flow diagnostic only; no vulnerability verdict")
        save(output / "summary.json", summary)
        interrupted = False
        try:
            for index, (issue, raw) in enumerate(items, 1):
                folder = output / f"issue-{index:04d}"
                folder.mkdir(exist_ok=True)
                print(f"[{index}/{len(items)}] Đọc CPG: {issue['component'].rsplit('/', 1)[-1]}...", flush=True)
                if (folder / "result.json").exists():
                    row = read(folder / "result.json")
                    if row["source_sha256"] != sha(raw) or row["issue_id"] != issue["key"]:
                        raise ValueError("Checkpoint khác mã nguồn/cảnh báo.")
                    print("  Dùng chẩn đoán đã lưu.", flush=True)
                else:
                    row = diagnose(folder, issue, raw, image)
                    save(folder / "result.json", row)
                summary["results"].append(row)
                save(output / "summary.json", summary)
                print(" ", row["status"], "| số call:", row.get("call_count"), "| lỗi:", row.get("error"), flush=True)
        except KeyboardInterrupt:
            interrupted = True
            print("Đã dừng; các phần đã hoàn tất được giữ lại.")
        finally:
            summary.update(state="INTERRUPTED" if interrupted else ("COLLECTED" if len(summary["results"]) == len(items) and all(r["status"] == "COLLECTED" for r in summary["results"]) else "PARTIAL"),
                           finished_at=datetime.now(timezone.utc).isoformat(),
                           status_counts=dict(Counter(r["status"] for r in summary["results"])))
            save(output / "summary.json", summary)
            print("GÓI CHẨN ĐOÁN CẦN GỬI:", package(output), flush=True)
            print("Không gọi AI, không quét SonarQube, không đổi code nguồn hoặc nhãn phân tích.")
    return 0 if summary["state"] == "COLLECTED" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print("LỖI:", exc, file=sys.stderr)
        sys.exit(1)
