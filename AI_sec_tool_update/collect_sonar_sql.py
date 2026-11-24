"""Collect SonarQube findings for local Java code."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import sys
import time
import uuid

import requests

from sql_pipeline.cwe_mapper import MAPPING_VERSION, get_cwe_info
from sql_pipeline.run_io import redact, run_command, save_json

COLLECTION_VERSION = "sql-evidence-collection-v1"


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


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    root = Path.cwd().resolve()
    run_dir = root / "runs" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6])
    run_dir.mkdir(parents=True)
    manifest = {"pipeline_version": COLLECTION_VERSION, "mapping_version": MAPPING_VERSION,
                "collect_only": True,
                "state": "STARTED", "started_at": datetime.now(timezone.utc).isoformat(),
                "limitations": ["Single-file CPG; JDBC sinks at issue line only.",
                    "No Security Hotspots API in this version.",
                    "No concurrent scans of the same SonarQube project."]}
    save_json(run_dir / "manifest.json", manifest)
    try:
        token = os.getenv("SONAR_TOKEN")
        if not token:
            raise RuntimeError("Thiếu SONAR_TOKEN. Đặt biến môi trường trước khi chạy.")
        url = os.getenv("SONAR_URL", "http://127.0.0.1:9000")
        project = os.getenv("SONAR_PROJECT_KEY", "project_1")
        scanner = os.getenv("SONAR_SCANNER_PATH", "sonar-scanner")
        source_dir = root / "Clean_Code"
        java_files = sorted(source_dir.rglob("*.java"))
        if not java_files:
            raise RuntimeError("Không tìm thấy Clean_Code/*.java trong thư mục hiện tại.")
        manifest.update({"project": project, "sonar_url": url,
                         "source_hashes": {str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest() for f in java_files}})
        binary_dir = run_dir / "classes"
        binary_dir.mkdir()
        print("[1/3] Biên dịch Java...")
        # Fresh output directory prevents stale .class files from masking failure.
        run_command(["javac", "-g", "-d", str(binary_dir)] + [str(f) for f in java_files],
                    run_dir / "javac.log", 120, root)
        print("[2/3] Quét SonarQube...")
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
        print("[3/3] Chờ background task và lấy đủ các trang cảnh báo...")
        task = sonar.wait_for_analysis(task_id, int(os.getenv("SONAR_WAIT_TIMEOUT", "300")))
        save_json(run_dir / "analysis_task.json", task)
        manifest["analysis_id"] = task.get("analysisId")
        if not manifest["analysis_id"]:
            raise RuntimeError("SonarQube không trả analysisId.")
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
        manifest.update(state="COLLECTED", issue_count=len(issues),
                        supported_issue_count=sum(row["count"] for row in inventory if row["supported"]),
                        result_count=0)
        print(f"Kết quả: {run_dir}")
        return 0
    except (OSError, RuntimeError, ValueError, requests.RequestException) as exc:
        manifest.update(state="FAILED", error=redact(str(exc)))
        print(f"[LỖI] {redact(str(exc))}\nXem log trong {run_dir}", file=sys.stderr)
        return 1
    finally:
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        save_json(run_dir / "manifest.json", manifest)


if __name__ == "__main__":
    sys.exit(main())
