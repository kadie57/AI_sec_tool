"""Run from ~/AI_sec_tool/eval_sql89_new_v1. --check, --collect, --analyze.
No answer-label file is loaded by this runner or passed to the model.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
PROJECT = "sql89_followup_v1"
MODULES = ["master_pipeline.py", "master_pipeline_v6.py", "master_pipeline_source_v1.py",
    "master_pipeline_combined_v1.py", "source_audit_v2.py", "replay_source_merge.py",
    "check_sql_prompt_controls.py", "triage_v5.py", "triage_v6.py", "validate_v6.py",
    "iris_prompter.py", "cwe_mapper.py"]

def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--collect", action="store_true")
    action.add_argument("--analyze", action="store_true")
    parser.add_argument("--tool-root", type=Path, default=HERE.parent)
    args = parser.parse_args()
    root = args.tool_root.resolve()
    sources = sorted((HERE / "Clean_Code").glob("*.java"))
    if len(sources) != 6:
        raise ValueError("Bộ đánh giá phải có đúng 6 file Java")
    paths = [root / name for name in MODULES]
    if any(not p.is_file() for p in paths):
        raise ValueError("Đặt thư mục này bên trong AI_sec_tool; thiếu: " +
                         ", ".join(p.name for p in paths if not p.is_file()))
    current = {"project": PROJECT, "sources": {p.name: fingerprint(p) for p in sources},
        "scripts": {p.name: fingerprint(p) for p in paths},
        "runner": fingerprint(Path(__file__)),
        "limitations": "Authored follow-up samples, not an independent benchmark."}
    freeze = HERE / "frozen_config.json"
    if freeze.exists() and json.loads(freeze.read_text()) != current:
        raise ValueError("Mã hoặc cấu hình đã đổi so với bản chốt. Giữ kết quả, không tự sửa mốc.")
    if args.check:
        with tempfile.TemporaryDirectory(prefix="sql89_compile_") as d:
            subprocess.run(["javac", "-g", "-d", d] + [str(p) for p in sources], check=True, timeout=120)
        subprocess.run([sys.executable, str(root / "master_pipeline_combined_v1.py"), "--check"],
                       cwd=root, check=True, timeout=120)
        if not freeze.exists():
            with freeze.open("x", encoding="utf-8") as f:
                json.dump(current, f, ensure_ascii=False, indent=2)
        print("EVAL_CHECK_OK: 6 mẫu biên dịch được; đã chốt hash. Không chạy Java hoặc gọi AI.")
        return 0
    if not freeze.exists():
        raise ValueError("Chạy --check trước để biên dịch và chốt cấu hình")
    if not os.getenv("SONAR_TOKEN"):
        raise ValueError("SONAR_TOKEN chưa đặt trong terminal này")
    os.environ["SONAR_PROJECT_KEY"] = PROJECT
    if args.collect:
        print("Chỉ quét 6 mẫu mới; project SonarQube:", PROJECT, flush=True)
        return subprocess.run([sys.executable, str(root / "master_pipeline.py"), "--collect-only"],
            cwd=HERE, check=False).returncode
    # Analysis is deliberately a separate action after inspection of inventory.
    collected = []
    for path in (HERE / "runs").glob("*/manifest.json"):
        manifest = json.loads(path.read_text())
        expected = {"Clean_Code/" + k: v for k, v in current["sources"].items()}
        if (manifest.get("state") == "COLLECTED" and manifest.get("project") == PROJECT
                and manifest.get("source_hashes") == expected
                and manifest.get("supported_issue_count", 0) > 0):
            collected.append(path)
    if not collected:
        raise ValueError("Cần lượt --collect thành công, có cảnh báo hỗ trợ trên đúng 6 mẫu")
    sys.path.insert(0, str(root))
    os.chdir(root)
    import master_pipeline_combined_v1 as combined
    original_main = combined.pipeline.main
    def isolated_main():
        os.chdir(HERE)
        return original_main()
    combined.pipeline.main = isolated_main
    sys.argv = [str(root / "master_pipeline_combined_v1.py")]
    print("Phân tích bộ mới: quét mới rồi tối đa 3 lần gọi AI/cảnh báo đủ điều kiện.", flush=True)
    return combined.main()

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        sys.exit("LỖI: " + str(exc))
