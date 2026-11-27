"""Trace candidate CPG paths between typed HTTP reads and exact file operands."""

from collections import Counter, defaultdict
from itertools import chain
import base64
import json
import os
from pathlib import Path

from common.joern_project import snapshot_import
from common.run_io import run_command

from ..prepare_path_evidence import LOCAL_FLOW, PROBE, decode_sites


PATH_LIMIT = 8
DISPLAY_PATHS = 2
DISPLAY_STEPS = 6
OPERAND_MEANINGS = {
    "fixed_value": "Verified Java value: the exact file operand comes from fixed expressions on the modeled branches.",
    "configuration_value": "Verified Java value: the exact file operand depends only on fixed expressions and JVM "
                           "configuration on the modeled branches.",
    "external_input_in_expression": "A verified HTTP read contributes to the operand expression on the modeled branches.",
    "possible_external_input_in_expression": "A verified HTTP read can contribute to the operand on a modeled branch. "
                                            "Other branches can supply a different value.",
    "unknown": "The complete operand value remains unresolved. The individual steps below are verified Java observations.",
}
HEADER_FLOW_ROLES = {"http_header_enumeration", "header_element_from_receiver", "url_decode_from_argument_1"}
HELPER_DECISIONS = {
    "helper_if_true": "if condition is true",
    "helper_if_false": "if condition is false",
    "helper_conditional_true": "conditional expression selects the true value",
    "helper_conditional_false": "conditional expression selects the false value",
    "helper_switch_case_selected": "switch selects this case",
}


def project_sites(files, root, graph, jars, *, value_facts=False):
    classes, empty = graph / "classes", graph / "empty"
    classes.mkdir()
    empty.mkdir()
    inputs = graph / "java-files.tsv"
    inputs.write_text("".join(f"{name}\t{root / name}\n" for name in files), encoding="utf-8")
    run_command(["javac", "--release", "17", "-proc:none", "-d", str(classes), str(PROBE), str(LOCAL_FLOW)],
                graph / "javac.log", 60, cwd=graph)
    output = run_command([
        "java", "-Dpath.evidence.projectSites=true", f"-Dpath.evidence.valueFacts={str(value_facts).lower()}",
        "-cp", str(classes), "PathEvidenceProbe", str(inputs),
        os.pathsep.join(map(str, jars)) or str(empty), str(empty),
    ], graph / "java.log", 120, cwd=graph)
    header, *records = output.splitlines()
    sections = {}
    name = None
    for record in records:
        if record.startswith("FILE\t"):
            name = record.split("\t", 1)[1]
            if name not in files or name in sections:
                raise ValueError(f"Unexpected Java project probe file: {name}")
            sections[name] = [header]
        elif name is None:
            raise ValueError("Java project probe omitted a file marker.")
        else:
            sections[name].append(record)
    if sections.keys() != files.keys():
        raise ValueError("Java project probe did not cover the staged sources.")
    indexed = defaultdict(list)
    lengths = {name: len(file["masked_source"].splitlines()) for name, file in files.items()}
    for name, section in sections.items():
        core = [line for line in section if not line.startswith(("CTOR\t", "FACT\t"))]
        errors, found, uses = decode_sites("\n".join(core), lengths[name])
        if value_facts:
            add_probe_facts(section, found, uses, lengths)
        for site in found.values():
            indexed[name, site["line"], site["method"]].append(site)
    return errors, indexed


def add_probe_facts(section, sites, uses, lengths):
    origins = defaultdict(list)
    for site, operand, origin, *_ in uses:
        origins[site, operand].append(origin)
    facts = defaultdict(list)
    for record in section:
        fields = record.split("\t")
        if fields[0] == "CTOR":
            _, site_id, encoded = fields
            site = sites[int(site_id)]
            if site["method"] != "<init>" or "constructor_code" in site or not base64.b64decode(encoded, validate=True):
                raise ValueError("Constructor record differs from the typed Java site.")
            site["constructor_code"] = encoded
        elif fields[0] == "FACT":
            _, site, operand, file, first, last, role = fields
            key = int(site), int(operand)
            first, last = int(first), int(last)
            if key not in origins or not 1 <= first <= last <= lengths.get(file, 0):
                raise ValueError("Java value fact differs from its operand or source coordinates.")
            facts[key].append((file, first, last, role))
    for (site, operand), observations in origins.items():
        if len(observations) != 1:
            continue
        origin, = observations
        facts_at_operand = list(dict.fromkeys(facts[site, operand]))
        roles = {fact[-1] for fact in facts_at_operand}
        if (origin != "unknown" or {"verified_helper_call", "helper_return"} <= roles
                or "helper_return_unresolved" in roles or "excluded_branch" in roles):
            sites[site].setdefault("value_by_operand", {})[operand] = (origin, facts_at_operand)


def locate_operands(row, indexed, *, value_facts=False):
    path = row["source"]["path"]
    java = row["java_evidence"]
    operands = []
    for use in java.get("same_method_path_use", {}).get("uses", []):
        operation = use["operation"]
        candidates = [site for site in java["sites_in_anchor_methods"]
                      if all(site[key] == value for key, value in operation.items())]
        key = (path, operation["line"], operation["method"])
        project = indexed.get(key, [])
        ambiguous_location = len(project) > 1
        if value_facts and len(candidates) == 1:
            archived, = candidates
            project = [item for item in project if all(item.get(field) == value for field, value in archived.items())]
            if len(project) != 1:
                continue
            site, = project
        else:
            if len(candidates) != 1 or project != candidates:
                continue
            site, = candidates
        operand = use["path_input"]
        if operand == "receiver":
            index, line = 0, operation["line"]
        else:
            index = int(operand.removeprefix("argument_"))
            if not 1 <= index <= len(site["argument_lines"]):
                raise ValueError("Path operand differs from the verified Java argument list.")
            line = site["argument_lines"][index - 1]
        endpoint = (*key, index)
        proof = site.get("value_by_operand", {}).get(index)
        if value_facts and ambiguous_location:
            if not proof or "constructor_code" not in site:
                continue
            endpoint = (*endpoint, site["constructor_code"])
        target = {**operation, "parameters": site["parameters"], "path_input": operand, "line": line, "api_line": key[1]}
        operands.append((endpoint, target, proof) if value_facts else (endpoint, target))
    return operands


def write_query(graph, jars, sources, operands):
    def records(kind, items):
        return "".join("\t".join(map(str, (kind, i, *item))) + "\n" for i, item in enumerate(items))

    (graph / "endpoints.tsv").write_text(records("source", sources) + records("sink", operands), encoding="utf-8")
    template = Path(__file__).with_name("path_slice.sc").read_text(encoding="utf-8")
    (graph / "slice.sc").write_text(template.replace("{SNAPSHOT_IMPORT}", snapshot_import(jars))
                                   .replace("{PATH_LIMIT}", str(PATH_LIMIT)), encoding="utf-8")


def parse_query(output, sources, operands):
    matches, sinks, counts = {}, {}, {}
    paths = defaultdict(list)
    for line in output.splitlines():
        if not line.startswith("PATH_FLOW\t"):
            continue
        _, kind, *fields = line.split("\t")
        if kind == "NODE":
            target, rank, source, file, line, method, node = fields
            paths[int(target), int(rank)].append((int(source), file, int(line), method, node))
            continue
        index, *numbers = map(int, fields)
        table = {"SOURCE": matches, "SINK": sinks, "COUNT": counts}[kind]
        if len(numbers) != (2 if kind == "SINK" else 1) or index in table or any(n < 0 for n in numbers):
            raise ValueError("Malformed or duplicate Joern endpoint result.")
        table[index] = tuple(numbers)
    if set(matches) != set(range(len(sources))) or set(sinks) != set(range(len(operands))):
        raise ValueError("Joern did not report all requested endpoints.")
    verified_sources = {i for i, count in matches.items() if count == (1,)}
    expected = {i for i, counts in sinks.items() if counts == (1, 1)} if verified_sources else set()
    if counts.keys() != expected or any(n[0] > PATH_LIMIT + 1 for n in counts.values()):
        raise ValueError("Joern returned inconsistent candidate counts.")
    if paths.keys() != {(i, j) for i, n in counts.items() for j in range(min(n[0], PATH_LIMIT))}:
        raise ValueError("Joern candidate paths lack node locations.")
    results = {}
    for i, operand in enumerate(operands):
        total, = counts.get(i, (0,))
        candidates = []
        for j in range(min(total, PATH_LIMIT)):
            nodes = paths[i, j]
            source_id, file, line, _, kind = nodes[0]
            if (source_id not in verified_sources or (file, line) != sources[source_id][:2] or kind != "Call"
                    or any(node[0] != source_id for node in nodes)):
                raise ValueError("Joern path does not start at the verified HTTP read.")
            candidates.append((sources[source_id], nodes))
        status = "no_candidate_path"
        if sinks[i] != (1, 1):
            status = "operand_not_unique_in_cpg"
        elif not verified_sources:
            status = "no_matched_http_read"
        elif candidates:
            status = "candidate_paths"
        results[operand] = {"status": status, "search_limit_hit": total > PATH_LIMIT, "candidates": candidates}
    return results, len(verified_sources)


def compact_steps(nodes, code):
    steps, missing = [], 0
    for _, path, line, method, kind in nodes:
        if path not in code or not 1 <= line <= len(code[path]) or not code[path][line - 1].strip():
            missing += 1
            continue
        if not steps or (path, line) != (steps[-1]["path"], steps[-1]["line"]):
            steps.append({"path": path, "line": line, "method": method, "node_type": kind})
    extra = max(0, len(steps) - DISPLAY_STEPS)
    if extra:
        # Preserve steps at both ends and prioritize source-file/method boundaries.
        focused = {0, len(steps) - 1}
        order = sorted(range(1, len(steps) - 1), key=lambda i: (
            steps[i]["path"] == steps[i - 1]["path"], steps[i]["method"] == steps[i - 1]["method"], i,
        ))
        focused.update(order[:DISPLAY_STEPS - 2])
        steps = [steps[i] for i in sorted(focused)]
    return steps, extra, missing


def operand_value_view(origin, facts, code, reference):
    steps, guards, header_flow, helper_branches = [], [], [], []
    for file, line, _, role in facts:
        if role in {"excluded_branch", "excluded_helper_branch"}:
            continue
        source_line = code[file][line - 1].strip()
        if not source_line:
            continue
        ref = reference(file, line)
        step = {**ref, "role": role}
        steps.append(step)
        if role == "header_availability_guard_true":
            guards.append({**ref, "code": source_line})
        elif role in HEADER_FLOW_ROLES:
            header_flow.append(step)
        elif role in HELPER_DECISIONS:
            helper_branches.append({**ref, "decision": HELPER_DECISIONS[role], "code": source_line})
    roles = {step["role"] for step in steps}
    value = {"origin": origin, "meaning": OPERAND_MEANINGS[origin], "steps": steps}
    if "helper_return" in roles and any(role.startswith("actual_argument_") for role in roles):
        value["verified_helper_dependency"] = (
            "The modeled helper return carries a value from the listed actual argument at the call site."
        )
    flow_roles = Counter(step["role"] for step in header_flow)
    if len(guards) == 1 and flow_roles["http_header_enumeration"] == flow_roles["header_element_from_receiver"] == 1:
        value["meaning"] = "Java verified an HTTP-to-operand route for the request branch described below."
        value["request_input_branch"] = {
            "condition": "The checked header enumeration has an element on this branch.",
            "guards_true": guards,
            "input_steps": header_flow,
        }
        if helper_branches:
            value["resolved_helper_branches"] = {
                "scope": "Java resolved these decisions within the helper for this call.",
                "decisions": helper_branches,
                "return_sites": [step for step in steps if step["role"] == "helper_return"],
            }
        grouped = HEADER_FLOW_ROLES | set(HELPER_DECISIONS) | {"header_availability_guard_true"}
        value["steps"] = [step for step in steps if step["role"] not in grouped]
    return value


def bundle(row, operands, traces, indexed, code, hashes, *, audit=None):
    main_file = row["source"]["path"]
    file_ids = {main_file: "F0"}
    visible = defaultdict(set)

    def reference(path, line, **fields):
        if path not in file_ids:
            file_ids[path] = f"F{len(file_ids)}"
        visible[path].add(line)
        return {"file_id": file_ids[path], "line": line, **fields}

    reports = []
    remaining_paths = DISPLAY_PATHS
    # Reserve room for a second operand when the warning has multiple operations.
    for key, target, *proofs in operands:
        trace = traces[key]
        origin_at_operand, facts = proofs[0] if proofs and proofs[0] else (None, [])
        if origin_at_operand is not None:
            target = {**target, "java_operand_value": operand_value_view(origin_at_operand, facts, code, reference)}
        paths, seen = [], set()
        kept = []
        for origin, nodes in trace["candidates"]:
            excluded = sorted({line for _, file, line, _, _ in nodes
                               if file == main_file and any(f == file and start <= line <= end and role == "excluded_branch"
                                                             for f, start, end, role in facts)})
            configuration_read = any(
                fact[3] in {"jvm_working_directory", "static_final_initializer"}
                and any(file == fact[0] and line == fact[1] for _, file, line, _, _ in nodes)
                for fact in facts
            )
            reason = ("verified_excluded_branch" if excluded else
                      "verified_fixed_operand" if origin_at_operand == "fixed_value" else
                      "verified_configuration_operand" if origin_at_operand == "configuration_value"
                      and not configuration_read and all(line > 0 for _, _, line, _, _ in nodes) else None)
            if reason:
                audit.append({"issue_id": row["alert"]["issue_id"], "target": key[:4], "reason": reason,
                              "source": origin, "excluded_lines": excluded, "nodes": nodes})
            else:
                kept.append((origin, nodes))
        for origin, nodes in kept:
            if remaining_paths == 0:
                break
            steps, omitted, missing = compact_steps(nodes[1:-1], code)
            signature = (origin, tuple((s["path"], s["line"]) for s in steps))
            if signature in seen:
                continue
            seen.add(signature)
            site, = indexed[origin]
            paths.append({
                "source": reference(origin[0], origin[1], owner=site["owner"], method=site["method"],
                                    parameters=site["parameters"]),
                "steps": [reference(**step) for step in steps],
                "omitted_steps": omitted, "unlocated_nodes": missing,
            })
            remaining_paths -= 1
            if len(paths) >= (1 if len(operands) > 1 else DISPLAY_PATHS):
                break
        status = "all_candidates_conflict_with_java_evidence" if not kept and trace["candidates"] else trace["status"]
        reports.append({"target": {**target, "file_id": "F0"}, "status": status,
                        "search_limit_hit": trace["search_limit_hit"], "paths": paths})
    snippets = []
    for name in file_ids:
        if file_ids[name] == "F0":
            continue
        neighbors = set(chain.from_iterable(range(max(1, n - 1), min(len(code[name]), n + 1) + 1)
                                            for n in visible[name]))
        snippets.append({"file_id": file_ids[name], "path": name, "sha256": hashes[name],
                         "excerpt": {str(n): code[name][n - 1] for n in sorted(neighbors) if code[name][n - 1].strip()}})
    return {"operations": reports,
            "unverified_operand_count": len(row["java_evidence"].get("same_method_path_use", {}).get("uses", []))
            - len(operands), "files": snippets}
