"""Verify and scan only reviewed_v2; compare with the saved previous scan.

python3 run.py              # offline tests then one isolated SonarQube scan
python3 run.py --check      # offline tests only, no SonarQube or token
"""
import argparse
from datetime import datetime, timezone
import fcntl
import getpass
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid

import check
import sonar_support as sonar

HERE = Path(__file__).resolve().parent
VERSION = "pathcase01-reviewed-v2-resource-refinement-1"
PREVIOUS_HASH = "d66605a0bcbf2309c6d3ab0fef3b8f5ad3dd150e5b1c54f3828a6b71fff8e9d9"
TRACKED_RULES = (sonar.RULE, "java:S2095", "java:S3776", "java:S2293")


def local_inputs():
    raw = (HERE / "comparison_previous.json").read_bytes()
    if sonar.sha(raw) != PREVIOUS_HASH:
        raise ValueError("File so sánh trước khác bản đã nhận; không ghép dữ liệu.")
    previous = sonar.read(HERE / "comparison_previous.json")
    if (previous.get("state") != "COMPLETED" or previous.get("target_rule") != sonar.RULE
            or previous.get("source_path") != sonar.SOURCE_PATH):
        raise ValueError("Kết quả trước chưa hoàn tất hoặc không đúng phạm vi.")
    for variant, expected in sonar.HASHES.items():
        row = previous["variants"][variant]["result"]
        if row.get("source_sha256") != expected or row.get("source_confirmed_on_server") is not True:
            raise ValueError("Kết quả trước không khớp nguồn: " + variant)
    old = (HERE / "sources/reviewed_v1.java.txt").read_bytes()
    if sonar.sha(old) != sonar.HASHES["reviewed"]:
        raise ValueError("Bản hiệu chỉnh trước đã thay đổi.")
    source, _, _, compiler, signature = check.inputs()
    return previous, source.encode("utf-8"), compiler, signature


def scanner_path():
    scanner = os.getenv("SONAR_SCANNER_PATH") or shutil.which("sonar-scanner")
    if not scanner:
        candidate = Path.home() / "Downloads/sonar-scanner-8.0.1.6346-linux-x64/bin/sonar-scanner"
        if candidate.is_file():
            scanner = str(candidate)
    if not scanner or not Path(scanner).is_file() or not os.access(scanner, os.X_OK):
        raise ValueError("Không thấy SonarScanner. Đặt SONAR_SCANNER_PATH trỏ tới bin/sonar-scanner đang dùng.")
    return str(Path(scanner).resolve())


def profile_signature(snapshot):
    return {k: v for k, v in snapshot.items() if k != "active_rules"}


def build_comparison(previous, state, verification):
    variants = {name: {"reused": True, "project_key": row["project_key"], "result": row["result"]}
                for name, row in previous["variants"].items()}
    variants["reviewed_v2"] = {"reused": False, "project_key": state["project_key"], "result": state["result"]}
    rows = [{"rule": rule, **{name: row["result"]["rule_counts"].get(rule, 0)
                              for name, row in variants.items()}} for rule in TRACKED_RULES]
    return {"experiment": VERSION, "state": "COMPLETED", "target_rule": sonar.RULE,
            "source_path": sonar.SOURCE_PATH, "profile": previous["profile"],
            "previous_comparison_sha256": PREVIOUS_HASH,
            "previous_scan_finished_at": previous["finished_at"],
            "started_at": state["started_at"], "finished_at": datetime.now(timezone.utc).isoformat(),
            "new_scans": 1, "new_llm_calls": 0, "runtime_verification_v2": verification,
            "new_run_signature": state["signature"], "tracked_rule_counts": rows, "variants": variants,
            "limitations": [
                "Previous three variants are saved scans, not rescanned; server/profile/active-rule fingerprint must match.",
                "Plugin versions are not independently fingerprinted by the previous comparison.",
                "Only Issues API is collected; separate Security Hotspots are outside this comparison.",
                "Warning absence does not prove security; warning presence requires source/evidence review.",
                "reviewed_v2 is an assisted revision, not raw Qwen output, and has not been applied to Clean_Code.",
                "Requires trusted configured root/ancestors, SecureDirectoryStream and at most 64 nested directories.",
                "Synthetic runtime checks do not cover all races, hard links or application authorization."]}


def run(args):
    previous, source, compiler, verification_signature = local_inputs()
    work = HERE / "work"
    work.mkdir(exist_ok=True)
    with (work / "run.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Lượt này đang chạy ở Terminal khác.") from None
        verification_file = work / "verification_v2.json"
        verification = sonar.read(verification_file) if verification_file.exists() else {}
        if check.valid(verification, verification_signature):
            print("KIỂM THỬ: đã có kết quả đạt, đúng nguồn và môi trường; dùng lại.", flush=True)
        else:
            print("[1/2] Kiểm thử riêng bản hiệu chỉnh v2...", flush=True)
            verification = check.verify(verification_file)
        if args.check:
            print("CHECK_OK. Chưa gọi SonarQube hoặc AI. FILE:", verification_file)
            return 0
        scanner = scanner_path()
        signature = {"version": VERSION, "source_sha256": check.SOURCE_HASH,
                     "previous_sha256": PREVIOUS_HASH, "verification_sha256": sonar.fingerprint(verification),
                     "scripts": {name: sonar.sha((HERE / name).read_bytes())
                                 for name in ("run.py", "check.py", "sonar_support.py")},
                     "sonar_url": args.sonar_url.rstrip("/"), "scanner": scanner}
        state_file, summary_file = work / "state.json", work / "comparison_v2.json"
        state = sonar.read(state_file) if state_file.exists() else None
        if state and state.get("signature") != signature:
            raise ValueError("Cấu hình/nguồn khác checkpoint. Giữ kết quả để đối chiếu, không quét đè.")
        if state and state.get("finished_at"):
            if not summary_file.exists() or sonar.sha(summary_file.read_bytes()) != state.get("summary_sha256"):
                raise ValueError("Bản tổng hợp đã bị sửa hoặc thiếu; cần đối chiếu checkpoint.")
            print("Đã hoàn tất. Không quét lại. FILE CẦN GỬI:", summary_file)
            return 0
        token = os.getenv("SONAR_TOKEN") or getpass.getpass("Nhập SonarQube User token (không hiện ký tự): ")
        if not token.strip():
            raise ValueError("Chưa có token.")
        api = sonar.API(args.sonar_url, token)
        spec = api.discover()
        reference_project = previous["reference_project"]
        current = api.snapshot(reference_project)
        if profile_signature(current) != previous["profile"]:
            sonar.save(work / "profile_mismatch.json", {"previous": previous["profile"],
                                                       "current": profile_signature(current)})
            raise ValueError("Server/profile/bộ rule khác lượt trước. Chưa tạo project/quét; gửi work/profile_mismatch.json.")
        if state and state.get("baseline") != current:
            raise ValueError("Bộ rule khác checkpoint; chưa tiếp tục quét.")
        if not state:
            tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:12]
            state = {"signature": signature, "baseline": current, "experiment_id": tag,
                     "project_key": "pathpatch_v2_" + tag, "created": False,
                     "started_at": datetime.now(timezone.utc).isoformat()}
            sonar.save(state_file, state)
        sonar.save(work / "api_contract.json", spec)
        project = state["project_key"]
        if project != "pathpatch_v2_" + state["experiment_id"] or project == reference_project:
            raise ValueError("Project đích không phải project kiểm chứng riêng.")
        folder = work / "reviewed_v2"
        dest = folder / sonar.SOURCE_PATH
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and dest.read_bytes() != source:
            raise ValueError("Bản sao dùng quét đã thay đổi; chưa quét.")
        dest.write_bytes(source)
        (folder / "sonar-project.properties").write_text("# Isolated reviewed_v2 scan\n", encoding="utf-8")
        env = os.environ.copy()
        env["SONAR_TOKEN"] = token
        env.pop("SONAR_SCANNER_JSON_PARAMS", None)
        env.pop("SONARQUBE_SCANNER_PARAMS", None)
        if not state.get("scan_started"):
            classes = Path(tempfile.mkdtemp(prefix="classes-", dir=folder))
            sonar.command(compiler + ["-g", "-encoding", "UTF-8", "-d", str(classes), str(dest)],
                          folder, folder / "javac.log")
            state["classes"] = str(classes)
            sonar.save(state_file, state)
            sonar.command([scanner, "--version"], folder, folder / "scanner-version.log", token, env=env)
        if not state["created"]:
            created = api.call("/api/projects/create", {"project": project, "name": "Path reviewed v2 " + state["experiment_id"],
                                                       "visibility": "private"}, post=True)
            if created.get("project", {}).get("key") != project:
                raise ValueError("Không xác nhận được project vừa tạo; chưa quét.")
            state["created"] = True
            sonar.save(state_file, state)
        api.call("/api/qualityprofiles/add_project", {"project": project, "language": "java",
                 "qualityProfile": current["profile_name"]}, post=True)
        if api.profile(project)["key"] != current["profile_key"] or api.snapshot(reference_project) != current:
            raise ValueError("Profile/bộ rule không khớp trước khi quét.")
        task_file = folder / "report-task.txt"
        if not state.get("scan_started"):
            if task_file.exists():
                raise ValueError("Có task ngoài checkpoint; không tự quét trùng.")
            state["scan_started"] = True
            sonar.save(state_file, state)
            print("[2/2] Quét một bản mới →", project, flush=True)
            sonar.command([scanner, "-Dsonar.host.url=" + api.url, "-Dsonar.projectKey=" + project,
                "-Dsonar.projectVersion=" + state["experiment_id"], "-Dsonar.sources=Clean_Code",
                "-Dsonar.inclusions=**/*.java", "-Dsonar.exclusions=", "-Dsonar.sourceEncoding=UTF-8",
                "-Dsonar.scm.disabled=true", "-Dsonar.java.binaries=" + state["classes"],
                "-Dsonar.scanner.metadataFilePath=" + str(task_file)],
                folder, folder / "scanner.log", token, timeout=900, env=env)
        if not task_file.exists():
            raise RuntimeError("Scanner chưa lưu task. Không tự quét trùng; gửi work/state.json và work/reviewed_v2/scanner.log.")
        properties = dict(line.split("=", 1) for line in task_file.read_text().splitlines() if "=" in line)
        if properties.get("projectKey") != project or not properties.get("ceTaskId"):
            raise ValueError("report-task không khớp project hoặc thiếu task ID.")
        if state.get("task_id") and state["task_id"] != properties["ceTaskId"]:
            raise ValueError("Task ID khác checkpoint.")
        state["task_id"] = properties["ceTaskId"]
        sonar.save(state_file, state)
        analysis_id = sonar.wait_task(api, state["task_id"], project, folder)
        result = sonar.collect(api, project, analysis_id, folder, source)
        if api.snapshot(reference_project) != current or api.profile(project)["key"] != current["profile_key"]:
            raise ValueError("Profile/bộ rule thay đổi trong lượt quét; chưa ghép kết quả.")
        state["result"] = result
        sonar.save(state_file, state)
        summary = build_comparison(previous, state, verification)
        sonar.save(summary_file, summary)
        state.update(finished_at=summary["finished_at"], summary_sha256=sonar.sha(summary_file.read_bytes()))
        sonar.save(state_file, state)
        for row in summary["tracked_rule_counts"]:
            print(row["rule"], "| hiệu chỉnh v1:", row["reviewed"], "→ v2:", row["reviewed_v2"])
        print("HOÀN TẤT. FILE CẦN GỬI:", summary_file)
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="Chỉ kiểm thử offline bản v2; không gọi dịch vụ.")
    parser.add_argument("--sonar-url", default=os.getenv("SONAR_URL", "http://127.0.0.1:9000"))
    args = parser.parse_args()
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\nĐã dừng. Giữ checkpoint; chạy lại cùng lệnh để tiếp tục.", file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print("LỖI:", sonar.clean(str(exc), os.getenv("SONAR_TOKEN", "")), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
