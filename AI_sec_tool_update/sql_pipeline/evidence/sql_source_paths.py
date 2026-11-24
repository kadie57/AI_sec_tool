"""Joern paths from verified Servlet reads to the SQL argument of one alert."""

from hashlib import sha256
import json
from pathlib import Path

from .joern_sql import run_joern_script
from .sql_evidence_selection import CONTEXT_RADIUS, MAX_PATHS, select_steps
from ..run_io import save_json

VERSION = "sql-anchored-paths-v1"
PATH_LIMIT = 12


def endpoints(specifications):
    """Use a typed read, including reads proved inside a wrapper, and one JDBC target."""
    sources = {}
    for source in specifications["sources"]:
        if source["role"] == "servlet_request_read":
            read = source
        elif source["role"] == "helper_returns_servlet_read":
            read = source["return_evidence"]
        else:
            continue
        name = read["signature"].partition("(")[0]
        sources[read["file_id"], read["line"], name] = {
            **read, "name": name,
        }
    sinks = specifications["sinks"]
    sink = sinks[0] if specifications["sink_resolution"] == "one_verified_signature" and len(sinks) == 1 else None
    if sink and (sink["file_id"], sink["role"], sink["argument_index"]) != ("F0", "sql_text", 1):
        sink = None
    return list(sources.values()), sink


def query(files, sources, sink):
    def tuple_for(file_id, line, name):
        return f"({json.dumps(files[file_id]['path'])}, {line}, {json.dumps(name)})"

    origins = ", ".join(tuple_for(s["file_id"], s["line"], s["name"]) for s in sources)
    target = tuple_for(sink["file_id"], sink["line"], sink["signature"].partition("(")[0])
    return f'''import io.shiftleft.codepropertygraph.generated.nodes.{{AstNode, Call, CfgNode}}

@main def exec() = {{
  importCode("/project")
  def emit(fields: Any*): Unit = println(("SQL_PATH" +: fields).mkString("\\t"))
  def fileName(n: AstNode): String =
    n.file.name.headOption.getOrElse("").stripPrefix("/project/")
  def matching(ref: (String, Int, String)) = {{
    val (file, line, name) = ref
    cpg.call.filter(c => c.name == name && c.lineNumber.contains(line) && fileName(c) == file).l
  }}
  val sinkCalls = matching({target})
  val sinkArgs = sinkCalls.iterator.argument(1).l
  emit("SINK", sinkCalls.size, sinkArgs.size)
  List({origins}).zipWithIndex.foreach {{ (ref, i) =>
    val reads = matching(ref)
    emit("SOURCE", i, reads.size)
    if (reads.size == 1 && sinkCalls.size == 1 && sinkArgs.size == 1) {{
      val paths = sinkArgs.iterator.reachableByFlows(reads.iterator).take({PATH_LIMIT + 1}).l
      emit("COUNT", i, paths.size)
      paths.take({PATH_LIMIT}).zipWithIndex.foreach {{ (path, p) =>
        path.elements.foreach {{ n =>
          val (method, start, end) = n match {{
            case cfg: CfgNode =>
              val m = cfg.method
              (m.name, m.lineNumber.getOrElse(0), m.lineNumberEnd.getOrElse(0))
            case _ => ("", 0, 0)
          }}
          emit("NODE", i, p, n.getClass.getSimpleName, fileName(n), n.lineNumber.getOrElse(0), method, start, end)
          n match {{
            case c: Call if c.dispatchType == "DYNAMIC_DISPATCH" =>
              val targets = c.start.callee.filter(m => !m.isExternal && m.lineNumber.isDefined).l
                .map(m => (fileName(m), m.lineNumber.get, m.fullName)).distinct.sortBy(identity)
              if (targets.size > 1) targets.foreach {{ (file, line, name) =>
                emit("TARGET", i, p, fileName(c), c.lineNumber.getOrElse(0), c.name, file, line, name)
              }}
            case _ =>
          }}
        }}
      }}
    }}
  }}
}}
'''


def select_paths(stdout, files, sources, sink):
    by_path = {f["path"]: file_id for file_id, f in files.items() if f["kind"] == "JAVA"}
    code = {key: files[key]["masked_source"].splitlines() for key in by_path.values()}

    def coordinate(path, line):
        file_id, line = by_path.get(path), int(line)
        lines = code.get(file_id, ())
        if 1 <= line <= len(lines) and lines[line - 1].strip():
            return {"file_id": file_id, "line": line}
        return None

    nodes, targets, counts, matched = {}, {}, {}, {}
    sink_match = None
    for row in stdout.splitlines():
        if not row.startswith("SQL_PATH\t"):
            continue
        _, kind, *fields = row.split("\t")
        if kind == "SINK":
            sink_match = tuple(map(int, fields))
        elif kind == "SOURCE":
            i, count = map(int, fields)
            matched[i] = count
        elif kind == "COUNT":
            i, count = map(int, fields)
            counts[i] = count
        elif kind == "NODE":
            i, p, node_type, path, line, method, start, end = fields
            ref = coordinate(path, line)
            if ref:
                ref.update(method=method, method_start=int(start), method_end=int(end), node_type=node_type)
            nodes.setdefault((int(i), int(p)), []).append(ref)
        elif kind == "TARGET":
            i, p, path, line, call, target_path, target_line, method = fields
            site, target = coordinate(path, line), coordinate(target_path, target_line)
            if site and target:
                dispatch = targets.setdefault((int(i), int(p)), {})
                edge = dispatch.setdefault((site["file_id"], site["line"], call),
                                           {**site, "name": call, "possible_targets": []})
                options = edge["possible_targets"]
                option = {**target, "method": method}
                if option not in options:
                    options.append(option)

    if sink_match is None or set(matched) != set(range(len(sources))):
        raise ValueError("Joern thiếu bản ghi đối chiếu tọa độ source/sink.")
    expected_counts = {i for i, count in matched.items() if count == 1} if sink_match == (1, 1) else set()
    if counts.keys() != expected_counts or any(not 0 <= n <= PATH_LIMIT + 1 for n in counts.values()):
        raise ValueError("Joern trả số đường không nhất quán với các đầu mút đã đối chiếu.")
    expected_paths = {(i, p) for i, count in counts.items() for p in range(min(count, PATH_LIMIT))}
    if nodes.keys() != expected_paths:
        raise ValueError("Joern thiếu tọa độ của đường ứng viên.")

    paths, seen = [], set()
    for key, path in sorted(nodes.items()):
        source = sources[key[0]]
        first = path[0]
        if not first or first["node_type"] != "Call" or any(first[k] != source[k] for k in ("file_id", "line")):
            raise ValueError("Đường Joern lệch vị trí đọc HTTP đã xác minh.")
        # The final node is the queried argument. Its CPG position can be synthetic,
        # so display its source position from the verified Java signature instead.
        argument = {**sink["argument"], "name": sink["signature"].partition("(")[0]}
        last = path[-1]
        if len(path) > 1 and last and last["file_id"] == argument["file_id"]:
            argument.update({key: last[key] for key in ("method", "method_start", "method_end")})
        steps = []
        previous = first
        for node in path[1:-1]:
            if node and (node["file_id"], node["line"]) != (previous["file_id"], previous["line"]):
                steps.append(node)
                previous = node
        signature = (key[0], tuple((n["file_id"], n["line"]) for n in steps))
        if signature in seen:
            continue
        seen.add(signature)
        focused = select_steps(steps)
        paths.append({
            "source": {**first, "api_owner": source["owner"], "api_signature": source["signature"]},
            "steps": focused,
            "sink": argument,
            "omitted_steps": len(steps) - len(focused),
            "unlocated_nodes": path.count(None),
            "dispatch": list(targets.get(key, {}).values()),
        })
    if paths:
        status = "candidate_paths"
    elif sink_match != (1, 1):
        status = "sink_not_unique_in_cpg"
    else:
        status = "no_candidate_path" if counts else "no_matched_http_read"
    return {
        "status": status,
        "matched_sources": sum(count == 1 for count in matched.values()),
        "source_count": len(sources),
        "candidate_paths_found": sum(min(count, PATH_LIMIT) for count in counts.values()),
        "search_limit_hit": any(count > PATH_LIMIT for count in counts.values()),
        "paths": paths[:MAX_PATHS],
        "paths_not_shown": len(paths) - min(len(paths), MAX_PATHS),
    }


def infer_source_paths(bundle, specifications, artifact, image):
    sources, sink = endpoints(specifications)
    if not sink or not sources:
        result = {"version": VERSION, "paths": [],
                  "status": "jdbc_signature_not_unique" if not sink else "no_verified_http_read"}
        save_json(artifact / "source_paths.json", result)
        return result
    files = bundle["files"]
    project = artifact / "java"
    inputs = {}
    for file_id, file in files.items():
        if file["kind"] != "JAVA":
            continue
        relative = Path(file["path"])
        if relative.is_absolute() or ".." in relative.parts or relative.suffix != ".java":
            raise ValueError("Đường dẫn Java trong gói bằng chứng không hợp lệ.")
        staged = project / relative
        staged.parent.mkdir(parents=True, exist_ok=True)
        raw = file["masked_source"].encode("utf-8")
        with staged.open("xb") as handle:
            handle.write(raw)
        inputs[file_id] = {"path": relative.as_posix(), "source_sha256": file["sha256"],
                           "staged_sha256": sha256(raw).hexdigest()}
    (artifact / "slice.sc").write_text(query(files, sources, sink), encoding="utf-8")
    output = run_joern_script(project, artifact, image)
    result = select_paths(output, files, sources, sink)
    result.update(version=VERSION, scope="verified_java_bundle", inputs=inputs,
                  interpretation="Candidate dataflow. Runtime branch and dispatch feasibility require separate evidence.")
    save_json(artifact / "source_paths.json", result)
    return result
