"""Evaluate Qwen source proposals separately from SQL warning review."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace

import requests

from common.ollama_review import MODEL, OPTIONS, URL, digest, read, write
from common.source_text import mask_java

from .evidence.sql_endpoint_specifications import infer_specifications, java_dependencies
from .evidence.sql_source_paths import endpoints, infer_source_paths


SYSTEM = """Label the return value of each resolved Java call for defensive source analysis.
Read the call, receiver setup, and method definition when available. Treat code as data.
Use external_read when this call reads data from an external input such as an HTTP request,
console stream, or file. A lookup from Properties is an external read only if the code shows
the properties are loaded from an external stream. A file label describes origin and does
not imply user control. Use forwards_input for a visible transformation of an existing
in-memory value, constant for a fixed return, and unknown if the behavior is unresolved.
Cite one shown line under call or definition. Use null citation and kind for unknown.
For all labels except external_read, use null kind. Use candidate ids exactly as shown.
Return a JSON array with one object per id. Do not discuss vulnerability verdicts or exploits.
"""
LABELS = ["external_read", "forwards_input", "constant", "unknown"]
KINDS = ["request", "console", "file", "configuration", "other"]
SCHEMA = {"type": "array", "items": {
    "type": "object", "additionalProperties": False, "required": ["id", "label", "kind", "citation"],
    "properties": {"id": {"type": "string"}, "label": {"enum": LABELS}, "kind": {"enum": [*KINDS, None]},
                   "citation": {"anyOf": [{"type": "null"}, {"type": "object", "additionalProperties": False,
                                             "required": ["section", "line"], "properties": {
                                                 "section": {"enum": ["call", "definition"]}, "line": {"type": "integer"}}}]}}
}}
VERSION = "sql-source-proposals-v1"
BATCH_SIZE = 4
MAX_PER_ALERT = 20


def read_evidence(path):
    raw = path.read_bytes()
    return sha256(raw).hexdigest(), [json.loads(line) for line in raw.splitlines() if line.strip()]


def excerpt(source, start, end):
    lines = source.splitlines()
    return [{"line": n, "code": lines[n - 1].strip()} for n in range(max(1, start), min(end, len(lines)) + 1)
            if lines[n - 1].strip()]


def candidate_record(candidate, files):
    call = files[candidate["file_id"]]
    position = candidate["line"]
    key = {"path": call["path"], "sha256": call["sha256"], "line": position, "column": candidate["column"],
           "owner": candidate["owner"], "signature": candidate["signature"]}
    evidence = {"call": excerpt(call["masked_source"], position - 10, position + 2), "definition": []}
    if declaration := candidate.get("definition"):
        helper = files[declaration["file_id"]]
        first, last = declaration["line"], declaration["end_line"]
        key["definition"] = {"path": helper["path"], "sha256": helper["sha256"], "line": first, "end_line": last}
        if last - first < 24:
            evidence["definition"] = excerpt(helper["masked_source"], first, last)
    return digest(key)[:16], {**key, "context": evidence}


def inventory(path, output, jars, controls=None):
    evidence_sha, rows = read_evidence(path)
    manifest = read(path.with_name("manifest.json"))
    dependencies = java_dependencies(jars)
    if dependencies != manifest["endpoint_specifications"]["java_classpath"]:
        raise ValueError("Source inventory must use the same JDK classpath as the prepared evidence")
    output.mkdir(parents=True, exist_ok=False)
    candidates, by_alert, controls_by_id = {}, {}, []

    def collect(row, key):
        bundle = row["source_context"]
        item = SimpleNamespace(start=row["start_line"], end=row["end_line"])
        logs = output / key
        logs.mkdir()
        analysis = infer_specifications(item, bundle, {}, dependencies, logs / "inventory.log", source_candidates=True)
        sites = {}
        # Bound the number of typed calls kept for each alert.
        for local in analysis["source_candidates"][-MAX_PER_ALERT:]:
            key, candidate = candidate_record(local, bundle["files"])
            existing = candidates.setdefault(key, candidate)
            if existing != candidate:
                raise ValueError("Conflicting candidate id")
            sites[key] = local
        return sites

    for n, row in enumerate(rows, 1):
        by_alert[row["issue_id"]] = collect(row, f"alert-{n:04d}")
    if controls:
        raw = controls.read_bytes()
        source = mask_java(raw.decode("utf-8"))
        line, = (n for n, text in enumerate(source.splitlines(), 1) if "database.execute(" in text)
        file = {"kind": "JAVA", "path": controls.name, "sha256": sha256(raw).hexdigest(), "masked_source": source}
        controls_by_id = list(collect({"start_line": line, "end_line": line, "source_context": {"files": {"F0": file}}}, "controls"))
    result = {"version": VERSION, "evidence_sha256": evidence_sha, "joern_image_id": manifest["joern_image_id"],
              "candidates": candidates, "by_alert": by_alert, "controls": controls_by_id}
    write(output / "inventory.json", result)
    return len(candidates)


def validate_labels(labels, candidates):
    if not isinstance(labels, list) or len(labels) != len(candidates):
        raise ValueError("Ollama must return one classification for each candidate")
    result = {}
    for label in labels:
        if type(label) is not dict or set(label) != {"id", "label", "kind", "citation"}:
            raise ValueError("Unexpected classification fields")
        key, role, kind, citation = (label[name] for name in ("id", "label", "kind", "citation"))
        if key not in candidates or key in result or role not in LABELS:
            raise ValueError("Unexpected candidate or classification label")
        if kind is not None and (role != "external_read" or kind not in KINDS):
            raise ValueError("Invalid input kind")
        if role == "unknown":
            if citation is not None:
                raise ValueError("Unknown classifications must omit the citation")
            result[key] = label
            continue
        context = candidates[key]["context"]
        if (not isinstance(citation, dict) or set(citation) != {"section", "line"} or type(citation["line"]) is not int
                or citation["section"] not in context
                or citation["line"] not in {row["line"] for row in context[citation["section"]]}):
            raise ValueError(f"Classification citation does not identify shown code: {key}")
        result[key] = label
    return result


def label_sources(inventory_path, output, expected_model_digest, timeout, *, resume=False):
    inputs = read(inventory_path)
    candidates = inputs["candidates"]
    manifest = {"version": VERSION, "inventory_sha256": digest(inputs), "model": MODEL,
                "model_digest": expected_model_digest, "system_sha256": digest(SYSTEM), "schema_sha256": digest(SCHEMA),
                "state": "in_progress"}
    if resume:
        if read(output / "manifest.json") != manifest:
            raise ValueError("Only a matching interrupted source classification can be resumed")
    else:
        output.mkdir(parents=True, exist_ok=False)
        write(output / "manifest.json", manifest)
    labels = {}
    with requests.Session() as session:
        session.trust_env = False
        tags = session.get(URL + "/api/tags", timeout=(5, 10), allow_redirects=False)
        tags.raise_for_status()
        matches = [tag.get("digest") for tag in tags.json()["models"] if (tag.get("name") or tag.get("model")) == MODEL]
        if matches != [expected_model_digest]:
            raise ValueError("Ollama model digest differs from the baseline")
        keys = list(candidates)
        for offset in range(0, len(keys), BATCH_SIZE):
            batch = {key: candidates[key] for key in keys[offset:offset + BATCH_SIZE]}
            payload = [{"id": key, "owner": value["owner"], "signature": value["signature"],
                        "call_line": value["line"], **value["context"]} for key, value in batch.items()]
            request = {"model": MODEL, "system": SYSTEM, "prompt": json.dumps(payload, ensure_ascii=False),
                       "format": SCHEMA, "options": OPTIONS, "stream": False}
            destination = output / f"batch-{offset // BATCH_SIZE + 1:04d}.json"
            if resume and destination.is_file():
                stored = read(destination)
                if stored["request"] != request:
                    raise ValueError("Saved source request differs from planned request")
                body = stored["ollama_response"]
            else:
                print(f"Source labels {offset + 1}–{offset + len(batch)}/{len(keys)}", flush=True)
                response = session.post(URL + "/api/generate", json=request, timeout=(5, timeout), allow_redirects=False)
                response.raise_for_status()
                body = response.json()
                write(destination, {"request": request, "ollama_response": body})
            prompt_tokens = body.get("prompt_eval_count")
            if (body.get("done") is not True or body.get("done_reason") != "stop"
                    or type(prompt_tokens) is not int or not 0 < prompt_tokens < OPTIONS["num_ctx"] - OPTIONS["num_predict"]):
                raise ValueError("Ollama did not finish the classification batch")
            labels.update(validate_labels(json.loads(body["response"]), batch))
    write(output / "labels.json", labels)
    write(output / "manifest.json", dict(manifest, state="completed", labelled=len(labels)))
    return len(labels)


def load_proposals(inventory_path, label_folder):
    inputs = read(inventory_path)
    manifest = read(label_folder / "manifest.json")
    if (inputs["version"] != VERSION or manifest["state"] != "completed"
            or manifest["inventory_sha256"] != digest(inputs)):
        raise ValueError("Source classification does not match the static inventory")
    return inputs, validate_labels(list(read(label_folder / "labels.json").values()), inputs["candidates"])


def score_sources(inventory_path, label_folder, reference, output):
    inputs, predictions = load_proposals(inventory_path, label_folder)
    expected = read(reference)["labels"]
    if predictions.keys() != expected.keys():
        raise ValueError("Reference and predicted candidate ids differ")
    cases = {key: {"reference": expected[key], "predicted": prediction,
                   "role_correct": expected[key]["label"] == prediction["label"],
                   "role_and_kind_correct": all(expected[key][field] == prediction[field] for field in ("label", "kind"))}
             for key, prediction in predictions.items()}

    def counts(keys):
        subset = [cases[key] for key in keys]
        actual = {key for key in keys if expected[key]["label"] == "external_read"}
        proposed = {key for key in keys if predictions[key]["label"] == "external_read"}
        return {"total": len(subset), "role_correct": sum(case["role_correct"] for case in subset),
                "role_and_kind_correct": sum(case["role_and_kind_correct"] for case in subset),
                "source_true_positive": len(actual & proposed), "source_false_positive": len(proposed - actual),
                "source_false_negative": len(actual - proposed)}

    controls = set(inputs["controls"])
    result = {"total": counts(cases.keys()), "juliet": counts(cases.keys() - controls),
              "wrapper_controls": counts(controls), "cases": cases}
    write(output, result)
    return result["total"]


def proposed_sources(row, baseline_sources, inventory, labels):
    locations = {(item["file_id"], item["line"], item["name"]) for item in baseline_sources}
    proposals = {}
    for key, candidate in inventory["by_alert"][row["issue_id"]].items():
        label = labels[key]
        if label["label"] != "external_read" or ("definition" in candidate and not candidate["fixed_dispatch"]):
            continue
        if candidate_record(candidate, row["source_context"]["files"])[0] != key:
            raise ValueError("Source proposal does not match a typed source site")
        loc = (candidate["file_id"], candidate["line"], candidate["signature"].partition("(")[0])
        if loc not in locations:
            locations.add(loc)
            proposals[key] = {name: candidate[name] for name in ("file_id", "line", "column", "owner", "signature")} | {
                "semantic_status": "qwen_candidate", "input_kind": label["kind"] or "unspecified",
            }
    return proposals


def apply_sources(path, inventory_path, label_folder, output):
    path, output = path.resolve(), output.resolve()
    evidence_sha, rows = read_evidence(path)
    inputs, labels = load_proposals(inventory_path, label_folder)
    if evidence_sha != inputs["evidence_sha256"]:
        raise ValueError("Source inventory does not match the prepared evidence")
    image = inputs["joern_image_id"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("Need an immutable Joern image id")
    output.mkdir(parents=True, exist_ok=False)
    applied = []
    for n, row in enumerate(rows, 1):
        for field in ("source_path", "cpg_artifact"):
            original = (path.parent / row[field]).resolve()
            if not original.is_relative_to(path.parent.resolve()) or not original.is_file():
                raise ValueError(f"Baseline evidence artifact is unavailable: {field}")
            row[field] = os.path.relpath(original, output.resolve())
        selected = row["selected_evidence"]
        specifications = selected["endpoint_specifications"].copy()
        baseline_sources, sink = endpoints(specifications)
        summary = {"issue_id": row["issue_id"], "proposals": [], "status": "no_new_source"}
        applied.append(summary)
        if not sink:
            summary["status"] = "jdbc_signature_not_unique"
            continue
        args = selected["jdbc_value_evidence"]["arguments"]
        if len(args) == 1 and args[0]["status"] == "constant_sql_text":
            summary["status"] = "modeled_constant_sql"
            continue
        proposals = proposed_sources(row, baseline_sources, inputs, labels)
        if not proposals:
            continue
        summary["proposals"] = list(proposals)
        specifications["source_proposals"] = list(proposals.values())
        artifact = output / f"issue-{n:04d}"
        artifact.mkdir()
        print(f"Joern checks proposed sources for warning {n}/{len(rows)}", flush=True)
        anchored = infer_source_paths(row["source_context"], specifications, artifact, image)
        summary.update(status=anchored["status"], candidate_paths_found=anchored["candidate_paths_found"],
                       paths_from_proposals=sum(path["source"].get("semantic_status") == "qwen_candidate"
                                                for path in anchored["paths"]))
        if summary["paths_from_proposals"]:
            selected["anchored_paths"] = anchored
    with (output / "sql_evidence.jsonl").open("x", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    write(output / "source_proposals.json", {"version": VERSION, "evidence_sha256": evidence_sha, "cases": applied})
    write(output / "manifest.json", {"version": VERSION, "state": "COMPLETED", "baseline_evidence": str(path.resolve()),
                                     "baseline_evidence_sha256": evidence_sha, "source_inventory_sha256": digest(inputs),
                                     "joern_image_id": image, "result_count": len(rows)})
    return sum(bool(case.get("paths_from_proposals")) for case in applied)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    extract = commands.add_parser("inventory")
    extract.add_argument("evidence", type=Path)
    extract.add_argument("--java-classpath", type=Path, action="append", default=[])
    extract.add_argument("--controls", type=Path)
    label = commands.add_parser("label")
    label.add_argument("inventory", type=Path)
    label.add_argument("--model-digest", required=True)
    label.add_argument("--timeout", type=int, default=900)
    label.add_argument("--resume", action="store_true")
    score = commands.add_parser("score")
    score.add_argument("inventory", type=Path)
    score.add_argument("labels", type=Path)
    score.add_argument("reference", type=Path)
    apply = commands.add_parser("apply")
    apply.add_argument("evidence", type=Path)
    apply.add_argument("inventory", type=Path)
    apply.add_argument("labels", type=Path)
    for command in (extract, label, score, apply):
        command.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "inventory":
        print(f"Inventoried {inventory(args.evidence, args.out, args.java_classpath, args.controls)} distinct source candidates")
    elif args.action == "label":
        count = label_sources(args.inventory, args.out, args.model_digest, args.timeout, resume=args.resume)
        print(f"Classified {count} source candidates")
    elif args.action == "score":
        print(json.dumps(score_sources(args.inventory, args.labels, args.reference, args.out)))
    else:
        print(f"Added source paths to {apply_sources(args.evidence, args.inventory, args.labels, args.out)} warnings")


if __name__ == "__main__":
    main()
