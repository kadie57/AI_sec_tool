"""Prepare a fixed, case-held-out OWASP evaluation inside the existing project.

Place this file directly in ~/AI_sec_tool, then run:
    python3 prepare_owasp_holdout.py --prepare

No SonarQube, Joern, Ollama, installation, or backend edits. Reference labels
are saved separately and must never be supplied to the analyzers.
"""
import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

VERSION = "owasp-holdout-plan-v1"
COMMIT = "a452b3aafd232245d0753e54eb243d6651f8ef96"
SEED = "khanh-owasp-heldout-20261115-v1"
PER_LABEL = 10
CATEGORIES = {"sqli": "89", "pathtraver": "22", "cmdi": "78"}
DEVELOPMENT = {"BenchmarkTest00001", "BenchmarkTest00006", "BenchmarkTest00008",
               "BenchmarkTest00051", "BenchmarkTest00052", "BenchmarkTest00063"}
PREFIX = Path("src/main/java/org/owasp/benchmark/testcode")
WORK = Path("experiments/owasp_holdout_v1")
REQUIRED = ("master_pipeline_multi_v1.py", "master_pipeline.py", "path_triage_v2.py",
            "command_triage_v2.py", "command_processbuilder_v1.py")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def git(repo, *args):
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=60)
    if result.returncode:
        raise ValueError("Không đọc được checkout OWASP: " + result.stderr.decode(errors="replace")[:300])
    return result.stdout


def references(repo):
    if git(repo, "rev-parse", "HEAD").decode().strip() != COMMIT:
        raise ValueError("Commit OWASP khác bản đã dùng; không tự đổi checkout.")
    if git(repo, "status", "--porcelain", "--untracked-files=no").strip():
        raise ValueError("Checkout OWASP có thay đổi ở tệp được Git theo dõi; chưa chọn mẫu.")
    raw = git(repo, "show", COMMIT + ":expectedresults-1.2.csv")
    result = {}
    for row in csv.reader(line for line in raw.decode().splitlines() if line and not line.startswith("#")):
        if len(row) != 4 or not re.fullmatch(r"BenchmarkTest\d{5}", row[0]) or row[0] in result:
            raise ValueError("Bảng nhãn OWASP không đúng cấu trúc hoặc trùng tên.")
        if row[2] not in ("true", "false"):
            raise ValueError("Giá trị nhãn OWASP không hợp lệ.")
        if row[1] in CATEGORIES and row[3] != CATEGORIES[row[1]]:
            raise ValueError("CWE không khớp nhóm OWASP.")
        result[row[0]] = {"category": row[1], "real_vulnerability": row[2] == "true", "cwe": row[3]}
    return result, sha(raw)


def history(root):
    """Exclude cases already collected/reviewed in this project's saved runs."""
    excluded, files = set(DEVELOPMENT), {}
    base = root / "runs"
    if base.exists():
        paths = sorted(set(base.rglob("issues.json")) | set(base.rglob("ai_results.json")))
        for path in paths:
            # Do not execute/import project code or inspect tokens/environment files.
            raw = path.read_bytes()
            data = json.loads(raw)
            rows = data if isinstance(data, list) else data.get("issues", data.get("results", []))
            if not isinstance(rows, list):
                raise ValueError("Không đọc được lịch sử cảnh báo: " + str(path))
            found = set()
            for row in rows:
                if isinstance(row, dict):
                    found.update(re.findall(r"\bBenchmarkTest\d{5}\b", str(row.get("component", ""))))
            if found:
                excluded.update(found)
                files[path.relative_to(root).as_posix()] = {"sha256": sha(raw), "cases": sorted(found)}
    return excluded, files


def choose(refs, excluded):
    selected, counts = [], {}
    for category in sorted(CATEGORIES):
        for truth in (False, True):
            pool = [name for name, row in refs.items()
                    if row["category"] == category and row["real_vulnerability"] == truth
                    and name not in excluded]
            counts[category + ("/true" if truth else "/false")] = len(pool)
            if len(pool) < PER_LABEL:
                raise ValueError(f"Không đủ {PER_LABEL} mẫu mới cho {category}, nhãn {truth}.")
            def rank(name):
                return sha(f"{SEED}|{category}|{str(truth).lower()}|{name}".encode()), name
            selected.extend(sorted(pool, key=rank)[:PER_LABEL])
    return sorted(selected), counts


def code_snapshot(root):
    missing = [name for name in REQUIRED if not (root / name).is_file()]
    if missing:
        raise ValueError("Đặt script trong ~/AI_sec_tool. Thiếu: " + ", ".join(missing))
    # Inventory only: no import, execution, environment values, secrets or source contents.
    paths = [p for p in root.iterdir() if p.is_file() and p.suffix in (".py", ".java", ".sc")]
    return {p.name: sha(p.read_bytes()) for p in sorted(paths)}


def verify(root, work):
    integrity = read_json(work / "integrity.json")
    for rel, expected in integrity["files"].items():
        path = (work / rel).resolve()
        if not path.is_relative_to(work.resolve()) or not path.is_file() or sha(path.read_bytes()) != expected:
            raise ValueError("Tệp kế hoạch/nguồn đã thay đổi hoặc bị thiếu: " + rel)
    snapshot = read_json(work / "backend_snapshot.json")
    changed = [name for name, digest in snapshot["root_code_sha256"].items()
               if not (root / name).is_file() or sha((root / name).read_bytes()) != digest]
    if changed:
        raise ValueError("Mã khác thời điểm lập kế hoạch: " + ", ".join(changed) +
                         ". Giữ nguyên kết quả; cần ghi nhận phiên bản trước khi đánh giá.")
    return read_json(work / "plan.json")


def prepare(root, repo, extra):
    work = root / WORK
    if work.exists():
        plan = verify(root, work)
        if not set(extra).issubset(set(read_json(work / "excluded_cases.json")["cases"])):
            raise ValueError("Đã có kế hoạch cố định; không tự chọn lại khi thêm mẫu loại trừ.")
        print("KẾ HOẠCH ĐÃ CÓ: giữ nguyên danh sách, không chọn lại.")
        return work, plan
    refs, reference_sha = references(repo)
    excluded, history_files = history(root)
    for sample in extra:
        if sample not in refs:
            raise ValueError("Tên mẫu cần loại trừ không có trong commit: " + sample)
        excluded.add(sample)
    selected, pool_counts = choose(refs, excluded)
    snapshot = code_snapshot(root)
    work.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".owasp-plan-", dir=work.parent))
    try:
        items, labels = [], {}
        for sample in selected:
            source_path = PREFIX / (sample + ".java")
            raw = git(repo, "show", COMMIT + ":" + source_path.as_posix())
            rel = Path("inputs") / COMMIT / source_path
            dest = staging / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            row = refs[sample]
            items.append({"sample": sample, "category": row["category"], "cwe": row["cwe"],
                          "repository_path": source_path.as_posix(),
                          "project_path": (WORK / rel).as_posix(), "source_sha256": sha(raw)})
            labels[sample] = row
        plan = {
            "version": VERSION, "state": "PLANNED_NOT_SCANNED",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "benchmark_repository": "https://github.com/OWASP-Benchmark/BenchmarkJava",
            "benchmark_commit": COMMIT, "reference_csv_sha256": reference_sha,
            "selection": {"method": "Smallest SHA256(seed|category|lowercase_truth|sample) per stratum",
                          "seed": SEED, "per_label_per_category": PER_LABEL, "eligible_counts": pool_counts},
            "sample_count": len(items), "samples": items,
            "reference_labels": "reference_labels.json — scoring only, never analyzer input",
            "measurement_policy": [
                "Keep all selected cases even if SonarQube reports no target warning.",
                "Report SAST detection coverage, supported-warning coverage and triage decision coverage separately.",
                "Report TP/FP mistakes against reference labels, UNKNOWN, SKIPPED and processing errors separately.",
                "Report AI predictions and combined-rule decisions separately; human edits are not AI output.",
                "Do not tune prompts on these outcomes and then report the same cases as held-out.",
                "Record generated requests, actual model digest, options, rule profile/plugins and timings at runtime.",
                "Check prompts do not receive reference labels or answer-revealing comments before generation."
            ],
            "limitations": [
                "Case-level split only: related templates/helper code may recur across development and evaluation.",
                "Public synthetic benchmark; absence from model training data cannot be established.",
                "60 balanced cases are not the full benchmark or the prevalence of real enterprise code.",
                "History exclusions cover runs/**/issues.json and ai_results.json plus six known development cases.",
                "Use --exclude before first preparation for cases evaluated elsewhere.",
                "Code hashes are a starting snapshot, not a validated complete runtime freeze."
            ]
        }
        write_json(staging / "plan.json", plan)
        write_json(staging / "reference_labels.json", {"provenance": {"commit": COMMIT,
                   "csv_sha256": reference_sha}, "labels": labels, "usage": "SCORING_ONLY_DO_NOT_SEND_TO_LLM"})
        write_json(staging / "excluded_cases.json", {"cases": sorted(excluded),
                   "known_development": sorted(DEVELOPMENT), "history_files": history_files})
        write_json(staging / "backend_snapshot.json", {"root_code_sha256": snapshot,
                   "python": sys.version.split()[0], "planner_sha256": sha(Path(__file__).read_bytes()),
                   "scope": "Existing root Python/Java/Scala files; runtime config/baselines verified at collection."})
        files = {p.relative_to(staging).as_posix(): sha(p.read_bytes())
                 for p in sorted(staging.rglob("*")) if p.is_file()}
        write_json(staging / "integrity.json", {"algorithm": "sha256", "files": files})
        # A concurrent process cannot replace a populated destination directory.
        staging.rename(work)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return work, plan


def review_zip(work):
    dest = work / "owasp_holdout_plan_review.zip"
    # The score key and Java code stay on the laptop, away from AI review input.
    names = ("plan.json", "backend_snapshot.json", "excluded_cases.json", "integrity.json")
    if dest.exists():
        with zipfile.ZipFile(dest) as z:
            if set(z.namelist()) != set(names) or any(z.read(n) != (work / n).read_bytes() for n in names):
                raise ValueError("ZIP kế hoạch khác dữ liệu đã lưu; không ghi đè.")
        return dest
    with zipfile.ZipFile(dest, "x", zipfile.ZIP_DEFLATED) as z:
        for name in names:
            z.write(work / name, name)
    return dest


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--verify", action="store_true")
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--repo", type=Path, default=Path.home() / "AI_sec_benchmarks/BenchmarkJava")
    parser.add_argument("--exclude", action="append", default=[], metavar="BenchmarkTestNNNNN")
    args = parser.parse_args()
    root = args.project_root.expanduser().resolve()
    try:
        if args.prepare:
            work, plan = prepare(root, args.repo.expanduser().resolve(), args.exclude)
            verify(root, work)
            dest = review_zip(work)
        else:
            work = root / WORK
            plan = verify(root, work)
            dest = None
        print("PLAN_OK:", plan["sample_count"], "mẫu, 3 nhóm, mỗi nhóm 10 có lỗi + 10 không có lỗi theo OWASP.")
        print("NHÓM:", dict(Counter(r["category"] for r in plan["samples"])))
        print("Chưa quét SonarQube, chưa gọi Joern/AI, chưa sửa mã backend.")
        print("Đã loại sáu mẫu phát triển và các mẫu tìm thấy trong lịch sử runs.")
        print("Nhãn tham chiếu lưu riêng; không đưa reference_labels.json vào yêu cầu AI.")
        if dest:
            print("ZIP CẦN GỬI:", dest)
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        print("LỖI:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
