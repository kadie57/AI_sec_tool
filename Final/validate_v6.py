"""Four new controlled code cases with the frozen v6 two-stage prompts.

Run beside triage_v5.py and triage_v6.py in ~/AI_sec_tool:
    OLLAMA_TIMEOUT=900 python3 validate_v6.py

Uses triage_v6_results.json as the frozen configuration, NOT as answers.
Makes four fresh prose calls and four fresh JSON calls, at most eight calls.
Each stage is saved before proceeding; restart skips saved stages. Java is
compiled for syntax/type checks but NEVER executed or sent to a database.
These are manually designated SQL sites, not SonarQube-detected warnings.
This checks the triage component only, not SonarQube/Joern or the full pipeline.
No expected labels are embedded in model requests or used to change outputs.
"""
import argparse
import copy
import fcntl
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

try:
    import triage_v6 as v6
except ModuleNotFoundError as exc:
    if exc.name == "triage_v6":
        raise SystemExit("Đặt validate_v6.py cùng thư mục với triage_v5.py và triage_v6.py.") from None
    raise

core = v6.core
VERSION = "sql89-v6-new-cases-1"
BASELINE = v6.OUTPUT / "triage_v6_results.json"
OUTPUT = Path("experiments/v6_validation_1") / core.ANALYSIS_ID
CASE_IDS = ("Case11", "Case12", "Case13", "Case14")


def sources():
    opening = '''package validation_sql89;

import java.sql.*;

public class CLASSNAME {
    public static void main(String[] args) throws SQLException {
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected one argument");
        }
        String team = args[0];
'''
    connection = '''        try (Connection connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb",
                System.getenv("DB_USER"), System.getenv("DB_PASSWORD"));
'''
    tail = '''    }
}
'''
    result = {}
    for name in ("Case11", "Case12"):
        block = '''        boolean accepted = team.matches("[A-Za-z0-9_]{1,24}");
        if (!accepted) {
            System.err.println("Invalid team");
'''
        if name == "Case11":
            block += "            return;\n"
        block += '''        }
        String sql = "SELECT id FROM members WHERE team = '" + team + "'";
'''
        result[name] = opening.replace("CLASSNAME", name) + block + connection + '''             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(sql)) {
            System.out.println(result.next());
        }
''' + tail
    result["Case13"] = opening.replace("CLASSNAME", "Case13") + '''        String sql = "SELECT id FROM members WHERE team = ? AND enabled = ?";
''' + connection + '''             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, team);
            statement.setBoolean(2, true);
            try (ResultSet result = statement.executeQuery()) {
                System.out.println(result.next());
            }
        }
''' + tail
    result["Case14"] = opening.replace("CLASSNAME", "Case14") + '''        String sql = "SELECT id FROM members WHERE team = '" + team + "' AND enabled = ?";
''' + connection + '''             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setBoolean(1, true);
            try (ResultSet result = statement.executeQuery()) {
                System.out.println(result.next());
            }
        }
''' + tail
    return result


def prepare_plan(path):
    baseline = core.read_json(path)
    if (baseline.get("experiment") != v6.PROMPT_VERSION or baseline.get("state") != "COMPLETED"
            or baseline.get("model") != core.MODEL
            or sorted(r.get("sample", "") for r in baseline["results"]) != sorted(core.SAMPLES)
            or core.sha(Path(core.__file__).read_bytes()) != v6.CORE_SHA256
            or core.sha(Path(v6.__file__).read_bytes()) != baseline["provenance"]["script_sha256"]):
        raise ValueError("Cần kết quả v6 hoàn tất và đúng hai script v5/v6 đã dùng; không tự đổi cấu hình.")
    first = baseline["results"][0]["stage1_reused"]["request_payload"]
    start, end = "[MÃ NGUỒN — DỮ LIỆU]\n", "\n[HẾT MÃ NGUỒN]\n\n"
    questions = first["prompt"].split(end, 1)[1]
    for row in baseline["results"]:
        prose, triage = row["stage1_reused"], row["triage"]
        request = prose["request_payload"]
        if (set(request) != {"model", "system", "prompt", "stream", "options"}
                or request["model"] != core.MODEL or request["system"] != first["system"]
                or request["options"] != core.OPTIONS or request["stream"] is not False
                or request["prompt"].count(start) != 1 or request["prompt"].count(end) != 1
                or request["prompt"].split(end, 1)[1] != questions):
            raise ValueError("Các bản phân tích cũ không dùng cùng một cấu hình.")
        numbered = request["prompt"].split(start, 1)[1].split(end, 1)[0]
        expected = v6.make_request(core.make_request(numbered, row["issue_line"]), prose["raw_output"])
        if (triage["request_payload"] != expected
                or triage.get("prompt_version") != v6.PROMPT_VERSION
                or any(r.get("error_kind") or r["generation"].get("done") is not True
                       or r["generation"].get("done_reason") == "length" for r in (prose, triage))):
            raise ValueError("Request hoặc phản hồi v6 cũ không hợp lệ.")
    plan = []
    for name, source in sources().items():
        lines = source.splitlines()
        issue_line = next(i for i, s in enumerate(lines, 1) if "statement.executeQuery(" in s)
        numbered = "\n".join(f"{i}: {s}" for i, s in enumerate(lines, 1))
        request = copy.deepcopy(first)
        request["prompt"] = (f"Đánh giá khả năng SQL injection tại dòng {issue_line}.\n\n"
                             + start + numbered + end + questions)
        plan.append({"sample": name, "source": source, "source_sha256": core.sha(source.encode()),
                     "issue_line": issue_line, "numbered_source": numbered, "line_count": len(lines),
                     "stage1_request": request})
    return baseline, plan


def compile_sources(plan):
    javac = shutil.which("javac")
    if not javac:
        raise ValueError("Không tìm thấy javac. Cần môi trường JDK đã dùng cho dự án; chưa gọi AI.")
    with tempfile.TemporaryDirectory(prefix="v6_java_check_") as temporary:
        folder = Path(temporary)
        files = []
        for item in plan:
            path = folder / (item["sample"] + ".java")
            path.write_text(item["source"], encoding="utf-8")
            files.append(str(path))
        result = subprocess.run([javac, "-encoding", "UTF-8", "-d", str(folder / "classes"), *files],
                                capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise ValueError("Mẫu Java không biên dịch được; chưa gọi AI.\n" + result.stderr)


def ask_prose(request):
    started = time.perf_counter()
    body, raw, error = None, "", None
    try:
        response = core.requests.post(os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
                                      + "/api/generate", json=request,
                                      timeout=(5, int(os.getenv("OLLAMA_TIMEOUT", "900"))))
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict):
            raise ValueError("Invalid envelope")
        raw = body.get("response", "")
        if body.get("error") or body.get("done") is not True:
            error = "OLLAMA_ERROR"
        elif body.get("done_reason") == "length":
            error = "TRUNCATED_OUTPUT"
        elif not isinstance(raw, str) or not raw.strip():
            error = "EMPTY_RESPONSE"
        elif body.get("prompt_eval_count", 0) + request["options"]["num_predict"] >= request["options"]["num_ctx"]:
            error = "CONTEXT_LIMIT"
    except core.requests.Timeout:
        error = "OLLAMA_TIMEOUT"
    except core.requests.RequestException:
        error = "OLLAMA_HTTP_ERROR"
    except (ValueError, TypeError):
        error = "INVALID_OLLAMA_ENVELOPE"
    return {"raw_output": raw, "ollama_response": body, "request_payload": request,
            "error_kind": error, "elapsed_seconds": round(time.perf_counter() - started, 3)}


def saved_stage(path, request, context):
    if not path.exists():
        return None
    saved = core.read_json(path)
    if saved.get("request_payload") != request or saved.get("context_sha256") != core.fingerprint(context):
        raise ValueError("Checkpoint khác dữ liệu/cấu hình hiện tại; không ghi đè.")
    return saved


def stage2_request(item, prose):
    return v6.make_request(core.make_request(item["numbered_source"], item["issue_line"]), prose["raw_output"])


def summary(output, context, plan):
    rows = []
    for item in plan:
        folder = output / item["sample"]
        prose = saved_stage(folder / "stage1.json", item["stage1_request"], context)
        triage = None
        if prose and not prose["error_kind"]:
            triage = saved_stage(folder / "stage2.json", stage2_request(item, prose), context)
        elif (folder / "stage2.json").exists():
            raise ValueError("Có kết quả bước 2 nhưng bước 1 thiếu hoặc lỗi.")
        rows.append({k: item[k] for k in ("sample", "source", "source_sha256", "issue_line")} |
                    {"stage1": prose, "triage": triage})
    prose_results = [r["stage1"] for r in rows if r["stage1"] is not None]
    results = [r["triage"] for r in rows if r["triage"] is not None]
    errors = dict(Counter(r["error_kind"] for r in prose_results + results if r["error_kind"]))
    return {"experiment": VERSION, "state": "COMPLETED" if len(results) == len(plan) else "IN_PROGRESS",
            "configuration": context, "review_required": True,
            "counts": {"samples": len(plan), "stage1_calls": len(prose_results), "stage2_calls": len(results),
                       "verdicts": dict(Counter(r["verdict"] for r in results)), "errors": errors},
            "elapsed_seconds": round(sum(r["elapsed_seconds"] for r in prose_results + results), 3),
            "scope": "Four new development checks with manually designated SQL sites; no SAST scan or Joern.",
            "limitations": ["Both stages use fresh model responses; no prior answers are supplied.",
                            "Labels and explanations require human review; no general accuracy claim.",
                            "Existing v6 prose errors may recur; the prompts are intentionally frozen."],
            "results": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline", type=Path, default=BASELINE)
    parser.add_argument("--dry-run", action="store_true", help="Validate configuration and compile Java without AI calls.")
    args = parser.parse_args()
    lock = None
    try:
        path = args.baseline.resolve()
        baseline, plan = prepare_plan(path)
        compile_sources(plan)
        print("4 mẫu Java biên dịch được. Giữ nguyên prompt v6; chạy mới 2 bước/mẫu (tối đa 8 lượt).", flush=True)
        if args.dry_run:
            print("Chưa gọi AI, chưa tạo kết quả.")
            return 0
        output = OUTPUT.resolve()
        if output == path.parent or output.is_relative_to(path.parent):
            raise ValueError("Đầu ra phải tách biệt với baseline.")
        output.mkdir(parents=True, exist_ok=True)
        lock = (output / "run.lock").open("a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Lượt kiểm tra này đang chạy ở Terminal khác.") from None
        context = {"experiment": VERSION, "baseline_sha256": core.sha(path.read_bytes()),
                   "script_sha256": core.sha(Path(__file__).read_bytes()),
                   "model": core.MODEL, "model_digest": baseline["model_digest"],
                   "v6_sha256": core.sha(Path(v6.__file__).read_bytes()), "v5_sha256": v6.CORE_SHA256,
                   "requests": {p["sample"]: core.fingerprint(p["stage1_request"]) for p in plan}}
        context_file = output / "experiment.json"
        if context_file.exists():
            if core.read_json(context_file) != context:
                raise ValueError("Dữ liệu/script đã khác lượt đã lưu; không ghi đè.")
        elif any((output / name / stage).exists() for name in CASE_IDS for stage in ("stage1.json", "stage2.json")):
            raise ValueError("Có checkpoint nhưng thiếu experiment.json.")
        current = summary(output, context, plan)
        if current["counts"]["errors"]:
            print(f"Có lỗi đã lưu. Gửi file để kiểm tra: {output / 'v6_validation_results.json'}")
            return 1
        if current["state"] != "COMPLETED" and core.model_digest() != context["model_digest"]:
            raise ValueError("Model khác lượt v6 trước; chưa gọi AI.")
        if not context_file.exists():
            core.write_json(context_file, context)
        summary_path = output / "v6_validation_results.json"
        core.write_json(summary_path, current)
        for i, item in enumerate(plan, 1):
            folder = output / item["sample"]
            folder.mkdir(exist_ok=True)
            (folder / (item["sample"] + ".java")).write_text(item["source"], encoding="utf-8")
            prose = saved_stage(folder / "stage1.json", item["stage1_request"], context)
            if prose is None:
                print(f"[{i}/4] {item['sample']} — bước 1/2: đọc và giải thích code...", flush=True)
                prose = ask_prose(item["stage1_request"])
                prose["context_sha256"] = core.fingerprint(context)
                core.write_json(folder / "stage1.json", prose)
                core.write_json(summary_path, summary(output, context, plan))
            if prose["error_kind"]:
                break
            request = stage2_request(item, prose)
            triage = saved_stage(folder / "stage2.json", request, context)
            if triage is None:
                print(f"[{i}/4] {item['sample']} — bước 2/2: đối chiếu và xuất JSON...", flush=True)
                triage = core.ask(request, item["line_count"])
                triage.update(prompt_version=v6.PROMPT_VERSION, decision_policy_version=core.PROMPT_VERSION,
                              context_sha256=core.fingerprint(context))
                core.write_json(folder / "stage2.json", triage)
                core.write_json(summary_path, summary(output, context, plan))
            print(f"  {item['sample']}: {triage['verdict']} | lỗi: {triage['error_kind']}", flush=True)
            if triage["error_kind"]:
                break
        final = summary(output, context, plan)
        print(f"Đã lưu {final['counts']['stage2_calls']}/4 kết quả. Cần đọc cả nhãn và lời giải thích.")
        print(f"FILE CẦN GỬI: {summary_path}")
        return 0 if final["state"] == "COMPLETED" and not final["counts"]["errors"] else 1
    except KeyboardInterrupt:
        print("\nĐã dừng. Chạy lại cùng lệnh sẽ bỏ qua các bước đã lưu.")
        return 130
    except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError,
            subprocess.SubprocessError, core.requests.RequestException) as exc:
        print(f"[LỖI] {exc}", file=sys.stderr)
        return 1
    finally:
        if lock is not None:
            lock.close()


if __name__ == "__main__":
    sys.exit(main())
