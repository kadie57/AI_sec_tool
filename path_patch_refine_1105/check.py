"""Offline verification of reviewed_v2 only; all executed data are temporary fixtures."""
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
SOURCE_HASH = "af9068d23364f76728cea8c0c30c37ea16bb58445fe96aeb3ab9c02b52a9fefb"
PROBE_HASH = "ad025b1576fb6816828a62e85d52af095959606d0efaa0c2b23c4f85ab8931ee"
CASE_NAMES = {"normal_file", "nested_file", "internal_parent_segment", "internal_symlink",
              "empty_file", "binary_first_byte", "parent_traversal", "sibling_prefix_bypass",
              "external_file_symlink", "external_directory_symlink", "missing_file",
              "wrong_argument_count", "directory_depth_64", "directory_depth_65"}
PROBE_NAMES = {"success", "open_child_failure", "open_file_failure", "read_failure",
               "read_failure_close_failure"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def execute(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=45)
    return {"returncode": result.returncode, "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip()}


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def inputs():
    source = (HERE / "sources/reviewed_v2.java.txt").read_bytes()
    probe = (HERE / "ResourceProbe.java.txt").read_bytes()
    if sha(source) != SOURCE_HASH or sha(probe) != PROBE_HASH:
        raise ValueError("Mã nguồn/bộ kiểm tra khác bản đã chuẩn bị; chưa chạy code.")
    java, javac = shutil.which("java"), shutil.which("javac")
    if not java:
        raise ValueError("Cần Java JDK để biên dịch và kiểm tra.")
    compiler = [javac] if javac else [java, "com.sun.tools.javac.Main"]
    java_version, compiler_version = execute([java, "-version"]), execute(compiler + ["-version"])
    if java_version["returncode"] or compiler_version["returncode"]:
        raise ValueError("Không chạy được Java/JDK compiler.")
    signature = {"source_sha256": SOURCE_HASH, "probe_sha256": PROBE_HASH,
                 "check_sha256": sha(Path(__file__).read_bytes()), "java": java_version,
                 "compiler": compiler_version, "platform": platform.platform()}
    return source.decode("utf-8"), probe.decode("utf-8"), java, compiler, signature


def valid(report, signature):
    cases = report.get("checks", [])
    changes = report.get("controlled_interleavings", [])
    probes = report.get("resource_checks", [])
    return (report.get("state") == "PASSED" and report.get("signature") == signature
            and len(cases) == len(CASE_NAMES) and {c["name"] for c in cases} == CASE_NAMES
            and all(c.get("passed") is True for c in cases)
            and len(changes) == 2 and {c["scenario"] for c in changes} ==
            {"file_replacement", "directory_replacement"}
            and all(c.get("blocked_without_output") is True for c in changes)
            and len(probes) == len(PROBE_NAMES) and {c["name"] for c in probes} == PROBE_NAMES
            and all(c.get("passed") is True for c in probes)
            and report.get("exact_compilation", {}).get("returncode") == 0)


def verify(dest):
    source, probe, java, compiler, signature = inputs()
    report = {"state": "IN_PROGRESS", "created_at": datetime.now(timezone.utc).isoformat(),
              "signature": signature, "checks": [], "controlled_interleavings": [],
              "resource_checks": [], "limitations": [
                  "Only reviewed_v2 is executed; original/Qwen/previous reviewed results are not rerun.",
                  "Functional copies change only the fixed base-directory literal to a temporary fixture.",
                  "Two instrumented interleavings are controlled changes, not a natural race success rate.",
                  "Resource probes are test doubles checking close attempts and exception propagation, not OS leak measurements.",
                  "Trusted configured root/ancestors and SecureDirectoryStream are required; at most 64 directory levels.",
                  "Hard-link provenance, arbitrary filesystem races and application access control are not proven by these checks."]}
    try:
        with tempfile.TemporaryDirectory(prefix="path-v2-check-") as temporary:
            root = Path(temporary)
            base = root / "uploads"
            (base / "sub").mkdir(parents=True)
            for path, content in [(base / "ok.txt", b"A sample"), (base / "sub/nested.txt", b"N sample"),
                                  (base / "empty.txt", b""), (base / "binary.bin", bytes([255, 0, 1]))]:
                path.write_bytes(content)
            outside = root / "outside.txt"
            outside.write_bytes(b"U synthetic fixture")
            sibling = root / "uploads_backup"
            sibling.mkdir()
            (sibling / "secret.txt").write_bytes(b"X synthetic sibling")
            (base / "inside-link").symlink_to(base / "ok.txt")
            (base / "outside-link").symlink_to(outside)
            (base / "dir-link").symlink_to(sibling, target_is_directory=True)
            deep = base
            depth_names = {}
            for i in range(1, 66):
                deep = deep / "d"
                deep.mkdir()
                if i in (64, 65):
                    (deep / "file.txt").write_bytes(b"A depth fixture")
                    depth_names[i] = str((deep / "file.txt").relative_to(base))

            def compile_source(name, text):
                folder = root / name
                folder.mkdir()
                src = folder / "PathCase01.java"
                src.write_text(text, encoding="utf-8")
                result = execute(compiler + ["-encoding", "UTF-8", "-d", str(folder), str(src)])
                if result["returncode"]:
                    raise RuntimeError("Biên dịch thất bại: " + result["stderr"])
                return folder, result

            if source.count('"/var/www/uploads/"') != 1:
                raise ValueError("Không xác định được hằng thư mục gốc của bộ thử.")
            exact, report["exact_compilation"] = compile_source("exact", source)
            fixture = source.replace('"/var/www/uploads/"', json.dumps(str(base) + "/"))
            classes, report["fixture_compilation"] = compile_source("fixture", fixture)
            cases = [
                ("normal_file", ["ok.txt"], "65", None),
                ("nested_file", ["sub/nested.txt"], "78", None),
                ("internal_parent_segment", ["sub/../ok.txt"], "65", None),
                ("internal_symlink", ["inside-link"], "65", None),
                ("empty_file", ["empty.txt"], "-1", None),
                ("binary_first_byte", ["binary.bin"], "255", None),
                ("parent_traversal", ["../outside.txt"], None, "SecurityException"),
                ("sibling_prefix_bypass", ["../uploads_backup/secret.txt"], None, "SecurityException"),
                ("external_file_symlink", ["outside-link"], None, "SecurityException"),
                ("external_directory_symlink", ["dir-link/secret.txt"], None, "SecurityException"),
                ("missing_file", ["not-present.txt"], None, "NoSuchFileException"),
                ("wrong_argument_count", [], None, "IllegalArgumentException"),
                ("directory_depth_64", [depth_names[64]], "65", None),
                ("directory_depth_65", [depth_names[65]], None, "Too many nested directories"),
            ]
            for name, args, expected, error in cases:
                result = execute([java, "-cp", str(classes), "pilot_path22.PathCase01", *args])
                passed = (result["returncode"] == 0 and result["stdout"] == expected) if not error else (
                    result["returncode"] != 0 and not result["stdout"] and error in result["stderr"])
                report["checks"].append({"name": name, "passed": passed, "output": result})
            print(f"KIỂM THỬ CHỨC NĂNG: {sum(c['passed'] for c in report['checks'])}/14", flush=True)

            marker = "            System.out.println(readRelative(directory, relative));"
            if fixture.count(marker) != 1:
                raise ValueError("Không xác định được điểm chèn thử thay tệp sau kiểm tra.")
            for scenario in ("file_replacement", "directory_replacement"):
                if scenario == "file_replacement":
                    argument = "change.txt"
                    (base / argument).write_bytes(b"A safe")
                    hook = ('Files.delete(targetPath);\nFiles.createSymbolicLink(targetPath, Paths.get('
                            + json.dumps(str(outside)) + '));\n')
                else:
                    (base / "change-dir").mkdir()
                    (base / "change-dir/file.txt").write_bytes(b"A safe")
                    outside_dir = root / "outside-dir"
                    outside_dir.mkdir()
                    (outside_dir / "file.txt").write_bytes(b"U synthetic fixture")
                    argument = "change-dir/file.txt"
                    hook = ('Files.move(targetPath.getParent(), Paths.get('
                            + json.dumps(str(base / "parked")) + '));\n'
                            'Files.createSymbolicLink(targetPath.getParent(), Paths.get('
                            + json.dumps(str(outside_dir)) + '));\n')
                folder, _ = compile_source(scenario, fixture.replace(marker, hook + marker))
                result = execute([java, "-cp", str(folder), "pilot_path22.PathCase01", argument])
                blocked = result["returncode"] != 0 and not result["stdout"] and (
                    "FileSystemException" in result["stderr"] or "IOException" in result["stderr"])
                report["controlled_interleavings"].append({"scenario": scenario, "instrumented": True,
                    "blocked_without_output": blocked, "output": result})
                print("THAY THẾ SAU KIỂM TRA:", scenario, "| đã chặn:", blocked, flush=True)

            probe_file = exact / "ResourceProbe.java"
            probe_file.write_text(probe, encoding="utf-8")
            compiled = execute(compiler + ["-encoding", "UTF-8", "-d", str(exact), str(probe_file)])
            if compiled["returncode"]:
                raise RuntimeError("Bộ thử tài nguyên không biên dịch được: " + compiled["stderr"])
            result = execute([java, "-cp", str(exact), "ResourceProbe"])
            report["resource_probe_output"] = result
            passed_names = {line[5:] for line in result["stdout"].splitlines() if line.startswith("PASS ")}
            report["resource_checks"] = [{"name": name, "passed": result["returncode"] == 0 and name in passed_names}
                                         for name in sorted(PROBE_NAMES)]
            print(f"ĐÓNG TÀI NGUYÊN / NGOẠI LỆ: {sum(c['passed'] for c in report['resource_checks'])}/5", flush=True)
            report["state"] = "PASSED"
            if not valid(report, signature):
                report["state"] = "FAILED"
    except Exception as exc:
        report.update(state="FAILED", error=str(exc))
        raise
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        save(dest, report)
    if report["state"] != "PASSED":
        raise ValueError("Có kiểm thử chưa đạt. Dừng trước khi quét SonarQube; xem " + str(dest))
    return report


if __name__ == "__main__":
    try:
        output = HERE / "work/verification_v2.json"
        verify(output)
        print("ĐÃ LƯU:", output)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        raise SystemExit(str(exc)) from None
