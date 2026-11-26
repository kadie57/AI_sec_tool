"""Select source locations for defensive review of one saved SQL alert."""

import re

from common.source_text import TOKENS

from .joern_sql import path_locations

MAX_PATHS = 3
MAX_INTERMEDIATE_STEPS = 10
CONTEXT_RADIUS = 5
NEARBY_CONTROL = re.compile(r"\b(?:(?:if|switch|while|for)\s*\(|case\s|default\s*:|else\b)")
NEARBY_BIND = re.compile(r"\.set(?:String|Int|Long|Short|Byte|Object|Null|Boolean|Date|"
                         r"Timestamp|BigDecimal|Bytes|Double|Float|Time)\s*\(")


def sink_status(flow):
    calls, arguments = flow.get("sink_call_count"), flow.get("sink_argument_count")
    if calls is None or arguments is None:
        return "diagnostics_unavailable"
    if calls == 0:
        return "call_not_located_in_alert_range"
    if arguments == 0:
        return "call_located_without_sql_argument"
    return "one_sql_argument_in_alert_range" if arguments == 1 else "multiple_sql_arguments_in_alert_range"


def select_steps(nodes):
    """Sample long paths in order, prioritizing calls and returns within each segment."""
    if len(nodes) <= MAX_INTERMEDIATE_STEPS:
        return nodes
    selected = []
    for index in range(MAX_INTERMEDIATE_STEPS):
        start = index * len(nodes) // MAX_INTERMEDIATE_STEPS
        end = (index + 1) * len(nodes) // MAX_INTERMEDIATE_STEPS
        segment = nodes[start:end]
        selected.append(next((node for node in segment if node["node_type"] in {"Call", "Return"}), segment[0]))
    return selected


def select_evidence(item, bundle, flow):
    source = bundle["files"]["F0"]["masked_source"]
    lines = source.splitlines()
    relative = item.relative.as_posix()
    file_names = {"", relative, item.relative.name, "/project/" + relative, bundle["files"]["F0"]["path"]}

    def in_snapshot(node):
        line = node["line"]
        return node["file"] in file_names and line is not None and 1 <= line <= len(lines) and lines[line - 1].strip()

    def window(line, radius=CONTEXT_RADIUS):
        return [max(1, line - radius), min(len(lines), line + radius)]

    result = {
        "version": "sql-path-context-v1",
        "file_id": "F0",
        "scope": "single_file",
        "source_basis": "candidate_method_parameters; external origin unverified",
        "sink_status": sink_status(flow),
        "alert_context": [window(item.start)[0], window(item.end)[1]],
        "path_status": "no_candidate_flow",
        "paths": [],
    }
    paths = []
    if flow.get("scope") != "single_file":
        result["scope"] = "unknown"
        result["path_status"] = "single_file_provenance_unavailable"
    else:
        try:
            paths = path_locations(flow)
        except ValueError:
            result["path_status"] = "path_coordinates_unavailable"

    context_centers = {item.start, item.end}
    locations = {}
    signatures = set()
    unmapped = 0
    selected = result["paths"]
    for path in paths:
        if not in_snapshot(path[0]) or not in_snapshot(path[-1]):
            unmapped += 1
            continue
        # Preserve returns to an earlier line after a call. Collapse only adjacent repeats.
        steps = []
        missing = 0
        for node in path[1:-1]:
            if not in_snapshot(node):
                missing += 1
            elif not steps or steps[-1]["line"] != node["line"]:
                steps.append(node)
            elif node["node_type"] in {"Call", "Return"}:
                steps[-1] = node
        focused_steps = select_steps(steps)
        focus = [path[0], *focused_steps, path[-1]]
        ordered = tuple(node["line"] for node in focus)
        if ordered in signatures:
            continue
        signatures.add(ordered)
        if len(selected) == MAX_PATHS:
            continue
        selected.append({"source_line": ordered[0], "intermediate_lines": list(ordered[1:-1]),
                         "sql_argument_line": ordered[-1], "unlocated_nodes": missing,
                         "omitted_intermediate_locations": len(steps) - len(focused_steps)})
        context_centers.update(ordered)
        for node in focus:
            line = node["line"]
            entry = locations.setdefault(line, {"line": line, "method": node["method"], "node_types": []})
            if node["node_type"] not in entry["node_types"]:
                entry["node_types"].append(node["node_type"])

    if paths:
        result["path_status"] = "selected" if selected else "path_coordinates_unavailable"
        result["paths_not_shown"] = len(paths) - len(selected)
        result["paths_with_unmapped_endpoints"] = unmapped
    if selected:
        result["locations"] = [locations[line] for line in sorted(locations)]
        result["endpoint_context"] = sorted({tuple(window(path[key])) for path in selected
                                               for key in ("source_line", "sql_argument_line")})

    # These are nearby syntax references, not proof a particular branch executed.
    syntax_lines = [TOKENS.sub("", line) for line in lines]
    nearby = {}
    for center in sorted(context_centers):
        start, end = window(center, radius=3)
        for line in range(start, end + 1):
            if NEARBY_CONTROL.search(syntax_lines[line - 1]):
                nearby[line] = "control"
            elif NEARBY_BIND.search(syntax_lines[line - 1]):
                nearby[line] = "possible_parameter_binding"
    if nearby:
        ranked = sorted(nearby, key=lambda line: (min(abs(line - center) for center in context_centers), line))
        result["nearby_syntax"] = [{"line": line, "kind": nearby[line], "context": window(line, radius=2)}
                                   for line in sorted(ranked[:8])]
    return result
