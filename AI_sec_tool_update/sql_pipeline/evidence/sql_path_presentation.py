"""Render selected Joern paths with code at their original source coordinates."""

ENDPOINT_RADIUS = 5
SUPPORT_RADIUS = 2
VALUE_EVIDENCE_ROLES = {
    "switch_selector": "switch selector",
    "switch_case_selected": "selected case",
    "switch_fallthrough": "fall-through case",
    "if_true": "selected if branch",
    "if_false": "selected else branch",
    "conditional_value_selected": "selected conditional expression",
    "local_assignment": "value assignment",
    "helper_return": "helper return",
    "helper_call": "helper call",
    "servlet_request_read": "request data read",
    "string_concatenation": "SQL string construction",
}
BRANCH_ROLES = {
    "switch_selector", "switch_case_selected", "switch_fallthrough",
    "if_true", "if_false", "conditional_value_selected",
}
VALUE_CHAIN_ROLES = {"local_assignment", "helper_return", "helper_call", "servlet_request_read", "string_concatenation"}
VALUE_PROOF_ROLES = (BRANCH_ROLES - {"switch_selector"}) | {"local_assignment", "helper_return", "servlet_request_read"}
INTEGER_EVIDENCE_ROLES = {"integer_arithmetic", "integer_comparison"}
CONSTANT_CONTEXT_ROLES = {"constant_expression", "constant_string_index"} | INTEGER_EVIDENCE_ROLES
STRUCTURED_VALUE_ROLES = BRANCH_ROLES | VALUE_CHAIN_ROLES | CONSTANT_CONTEXT_ROLES | {"local_definition"}


def positions(value, file_id):
    if isinstance(value, dict):
        if value.get("file_id") == file_id and type(value.get("line")) is int:
            yield value["line"]
        for nested in value.values():
            yield from positions(nested, file_id)
    elif isinstance(value, list):
        for nested in value:
            yield from positions(nested, file_id)


def verified_argument(selected, values, alert):
    if (not values or values.get("status") != "evaluated"
            or values.get("scope") != "modeled_java_execution_up_to_the_reported_call"):
        return None
    specs = selected.get("endpoint_specifications", {})
    arguments = values.get("arguments", [])
    sinks = specs.get("sinks", [])
    if specs.get("sink_resolution") != "one_verified_signature" or len(sinks) != 1 or len(arguments) != 1:
        return None
    argument, sink = arguments[0], sinks[0]
    call_line = sink.get("line")
    sql_argument = sink.get("argument")
    if (argument.get("reason") != "bounded_java_evaluation"
            or argument.get("status") not in {"constant_sql_text", "external_input_contributes"}
            or sink.get("role") != "sql_text" or sink.get("argument_index") != 1 or sink.get("file_id") != "F0"
            or type(call_line) is not int or not alert["start_line"] <= call_line <= alert["end_line"]
            or not isinstance(sql_argument, dict) or sql_argument.get("file_id") != "F0"
            or argument.get("call") != {key: sink.get(key) for key in ("file_id", "line", "column")}
            or argument.get("sql_argument") != sql_argument):
        return None
    return argument


def verified_display(argument, visible, files, *, structured=False):
    def source_line(ref):
        file_id, line = ref.get("file_id"), ref.get("line")
        code = files.get(file_id, [])
        if (type(line) is not int or not 1 <= line <= len(code) or not code[line - 1].strip()
                or (file_id == "F0" and line not in visible)):
            return None
        return {"file_id": file_id, "line": line, "code": code[line - 1].strip()}

    def coordinate(ref):
        return f"{ref['file_id']}:{ref['line']}"

    sql_argument = source_line(argument["sql_argument"])
    warning = source_line(argument["call"])
    if not sql_argument or not warning:
        return None
    target, call = coordinate(sql_argument), coordinate(warning)
    refs = {}
    rendered_facts = []
    for fact in argument.get("evidence", []):
        if row := source_line(fact):
            refs[fact["role"]] = coordinate(row)
            rendered_facts.append({**row, "role": fact["role"]})
    location = target if call == target else f"{target} (JDBC call {call})"
    if argument["status"] == "constant_sql_text" and "constant_expression" in refs:
        statement = (f"Static Java evaluation verified that the SQL text argument at {location} is constant. "
                     "Request data does not contribute to that argument on the evaluated execution.")
    elif argument["status"] == "external_input_contributes" and "servlet_request_read" in refs:
        statement = (f"Static Java evaluation verified that request data read at {refs['servlet_request_read']} "
                     f"contributes to the SQL text argument at {location} on the evaluated execution.")
    else:
        return None

    if structured:
        branch = [fact for fact in rendered_facts if fact["role"] in BRANCH_ROLES]
        chain = [fact for fact in rendered_facts if fact["role"] in VALUE_CHAIN_ROLES]
        constants = [fact for fact in rendered_facts if fact["role"] in CONSTANT_CONTEXT_ROLES]
        explained = {coordinate(fact) for fact in branch + chain}
        constant_context = list({coordinate(fact): fact for fact in constants
                                 if coordinate(fact) not in explained}.values())
        # Keep value provenance in the evaluator's order, separate from branch decisions.
        support = [fact for fact in branch + chain if fact["role"] in VALUE_PROOF_ROLES] or constants
        warning_ref = {key: warning[key] for key in ("file_id", "line")}
        support_refs = list({coordinate(fact): {key: fact[key] for key in ("file_id", "line")}
                             for fact in support if coordinate(fact) != call}.values())
        return {
            "warning_anchor": warning,
            "verified_finding": statement,
            "selected_branch": branch,
            "value_to_jdbc": [*chain, {**sql_argument, "role": "sql_text_argument"}],
            "constant_context": constant_context,
            "decisive_citation_roles": {
                "warning_line": warning_ref,
                "verified_support_lines": support_refs,
            },
        }

    details = [f"{refs[role]} {description}" for role, description in VALUE_EVIDENCE_ROLES.items() if role in refs]
    if not details and "constant_expression" in refs:
        details.append(f"{refs['constant_expression']} constant expression")
    return statement + (f" Relevant lines include {', '.join(details)}." if details else "")


def render_path_snippets(evidence, *, verified_sink_note=False, structured_sink_evidence=False):
    """Return the display payload and the main-file lines visible for citation."""
    main_file = next((file for file in evidence["files"] if file["file_id"] == "F0"), None)
    if main_file is None:
        raise ValueError("Path snippets require the main source file F0")
    lines = main_file["lines"]
    files = {file["file_id"]: file["lines"] for file in evidence["files"]}
    alert = evidence["alert"]
    selected = evidence.get("selected_evidence") or {}
    anchored = selected.get("anchored_paths") or {}
    anchored_paths = anchored.get("paths", [])
    value_argument = None
    if verified_sink_note or structured_sink_evidence:
        selected = selected.copy()
        value_argument = verified_argument(selected, selected.pop("jdbc_value_evidence", None), alert)
    visible = set()

    def excerpt(start, end, *, repeat=(), file_id="F0"):
        source = files[file_id]
        output = []
        for line in range(max(1, start), min(len(source), end) + 1):
            code = source[line - 1].strip()
            if code and (file_id != "F0" or line not in visible or line in repeat):
                output.append(f"{file_id}:{line} {code}")
                if file_id == "F0":
                    visible.add(line)
        return output

    def endpoint(line):
        return {"anchor": f"F0:{line}", "code": excerpt(line - ENDPOINT_RADIUS, line + ENDPOINT_RADIUS, repeat=(line,))}

    def anchored_endpoint(ref):
        file_id, line = ref["file_id"], ref["line"]
        start, end = line - ENDPOINT_RADIUS, line + ENDPOINT_RADIUS
        declaration = []
        method_start, method_end = ref.get("method_start", 0), ref.get("method_end", 0)
        if 1 <= method_start <= line <= method_end <= len(files[file_id]):
            start, end = max(start, method_start), min(end, method_end)
            if method_start < start:
                declaration = excerpt(method_start, method_start, file_id=file_id, repeat=(method_start,))
        return {
            "anchor": f"{file_id}:{line}",
            "method": ref.get("method"),
            "code": declaration + excerpt(start, end, file_id=file_id, repeat=range(start, end + 1)),
        }

    paths = []
    for path in anchored_paths:
        source = anchored_endpoint(path["source"])
        source["verified_api"] = path["source"]["api_owner"] + "." + path["source"]["api_signature"]
        steps = []
        for ref in path["steps"]:
            code = excerpt(ref["line"], ref["line"], repeat=(ref["line"],), file_id=ref["file_id"])
            if code:
                steps.append({"code": code[0], "method": ref["method"], "node_kind": ref["node_type"]})
        paths.append({"Source": source, "Steps": steps, "Sink": anchored_endpoint(path["sink"]),
                      "possible_dispatch": path["dispatch"], "unlocated_nodes": path["unlocated_nodes"],
                      "omitted_intermediate_locations": path["omitted_steps"]})

    for path in ([] if anchored_paths else selected.get("paths", [])):
        source = endpoint(path["source_line"])
        steps = []
        for line in path["intermediate_lines"]:
            # A return to an earlier line is retained in the path order.
            steps.extend(excerpt(line, line, repeat=(line,)))
        sink = endpoint(path["sql_argument_line"])
        paths.append({"Source": source, "Steps": steps, "Sink": sink,
                      "unlocated_nodes": path.get("unlocated_nodes", 0),
                      "omitted_intermediate_locations": path.get("omitted_intermediate_locations", 0)})

    start, end = alert["start_line"], alert["end_line"]
    alert_excerpt = excerpt(start - ENDPOINT_RADIUS, end + ENDPOINT_RADIUS, repeat=range(start, end + 1))
    related = []
    for entry in selected.get("nearby_syntax", []):
        related.extend(excerpt(*entry["context"]))
    anchors = set(positions(selected.get("endpoint_specifications"), "F0"))
    anchors.update(positions(selected.get("jdbc_value_evidence"), "F0"))
    if anchored_paths and value_argument:
        anchors.update(positions(value_argument, "F0"))
    for line in sorted(anchors):
        related.extend(excerpt(line - SUPPORT_RADIUS, line + SUPPORT_RADIUS))
    if structured_sink_evidence and value_argument:
        # The verified value may depend on lines outside the excerpts, even without a Joern path.
        for fact in value_argument["evidence"]:
            if fact["file_id"] == "F0" and fact["role"] in STRUCTURED_VALUE_ROLES:
                related.extend(excerpt(fact["line"], fact["line"]))

    summary = {key: value for key, value in selected.items()
               if key not in {"paths", "locations", "alert_context", "endpoint_context", "anchored_paths"}}
    if anchored_paths:
        summary.pop("paths_with_unmapped_endpoints", None)
        summary.pop("paths_not_shown", None)
        summary.update(scope=anchored["scope"], path_status=anchored["status"],
                       source_basis="statically_verified_servlet_read",
                       anchored_dataflow={key: anchored[key] for key in (
                           "candidate_paths_found", "matched_sources", "source_count", "paths_not_shown",
                           "search_limit_hit", "interpretation",
                       )})
    presented = {"paths": paths, "alert_excerpt": alert_excerpt, "supporting_excerpts": related}
    if value_argument:
        if observation := verified_display(value_argument, visible, files, structured=structured_sink_evidence):
            argument = value_argument["sql_argument"]
            target = f"{argument['file_id']}:{argument['line']}"
            sink = next((path["Sink"] for path in paths if path["Sink"]["anchor"] == target), None)
            if sink is None:
                presented["verified_alert_sink"] = observation
            else:
                sink["verified_value"] = observation
            if anchored_paths:
                summary["anchored_dataflow"]["modeled_sql_value"] = value_argument["status"]
    display = {
        "alert": alert,
        "source_line_notation": ("F<id>:<original line number> <code>" if anchored_paths
                                 else "F0:<original line number> <code>"),
        "selected_evidence": {**presented, **summary},
        "files": [{key: value for key, value in main_file.items() if key != "lines"},
                  *(file for file in evidence["files"] if file["file_id"] != "F0")],
        "joern_summary": evidence["joern_summary"],
        "missing_context": evidence["missing_context"],
    }
    return display, [code if line in visible else "" for line, code in enumerate(lines, 1)]
