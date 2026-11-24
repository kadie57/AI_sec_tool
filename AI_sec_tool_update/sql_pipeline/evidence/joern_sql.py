"""Single-file JDBC evidence extracted from the existing Joern stage."""

import json
import os
from pathlib import Path
import re
import subprocess
import uuid

from ..run_io import run_command, save_json


def path_locations(flow):
    """Extract ordered coordinates from the Joern tables used by live and saved runs."""
    paths = []
    nodes = None
    for row in flow["paths"].splitlines():
        if row.startswith("┌"):
            if nodes is not None:
                raise ValueError("Unclosed Joern path table")
            nodes = []
        elif row.startswith("└"):
            if nodes is None or len(nodes) < 2 or nodes[0]["node_type"] != "MethodParameterIn":
                raise ValueError("Invalid Joern path endpoints")
            paths.append(nodes)
            nodes = None
        elif row.startswith("│"):
            if nodes is None or not row.endswith("│"):
                raise ValueError("Invalid Joern path row")
            # The tracked expression can itself contain separators and span several rows.
            left, line, method, filename = row[1:-1].rsplit("│", 3)
            node_type, _ = left.split("│", 1)
            node_type, line = node_type.strip(), line.strip()
            if node_type and node_type != "nodeType":
                if line and (not line.isascii() or not line.isdecimal()):
                    raise ValueError("Invalid Joern line number")
                nodes.append({"node_type": node_type, "line": int(line) if line else None,
                              "method": method.strip(), "file": filename.strip()})
        elif row.strip() and not row.startswith("├"):
            raise ValueError("Unrecognized Joern path table")
    if nodes is not None or len(paths) != flow["flow_count"]:
        raise ValueError("Joern path table count differs from flow_count")
    return paths


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
    output = run_joern_script(root, artifact, image)
    result = parse_joern_output(output)
    save_json(artifact / "cpg_evidence.json", result)
    return result


def run_joern_script(root, artifact, image):
    """Run the staged slice against read-only sources in the pinned local image."""
    container_name = "thesis-joern-" + uuid.uuid4().hex[:12]
    try:
        return run_command([
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
