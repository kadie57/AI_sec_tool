"""Structured warning reviews and request provenance for local Ollama."""

import hashlib
import json
import time

import requests


MODEL = "qwen2.5-coder:14b-instruct-q4_K_M"
URL = "http://127.0.0.1:11434"
OPTIONS = {"temperature": 0, "seed": 42, "num_ctx": 8192, "num_predict": 1024}

VERDICTS = ["LIKELY_TP", "LIKELY_FP", "UNKNOWN"]
SCHEMA = {"type": "object", "additionalProperties": False,
          "required": ["verdict", "explanation", "citations"],
          "properties": {
              "verdict": {"type": "string", "enum": VERDICTS},
              "explanation": {"type": "string"},
              "citations": {"type": "array", "items": {
                  "type": "object", "additionalProperties": False,
                  "required": ["file_id", "line"],
                  "properties": {"file_id": {"type": "string"}, "line": {"type": "integer"}}}}}}


def serial(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def digest(value):
    return hashlib.sha256(serial(value).encode()).hexdigest()


def write(path, value):
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate(data, row, *, bind_warning_citation=False):
    if not isinstance(data, dict) or set(data) != set(SCHEMA["required"]):
        raise ValueError("Invalid JSON fields")
    if not isinstance(data["explanation"], str) or not data["explanation"].strip():
        raise ValueError("Empty explanation")
    if data["verdict"] not in VERDICTS or not isinstance(data["citations"], list):
        raise ValueError("Invalid verdict or citations")
    files = {f["file_id"]: f["lines"] for f in (row["source"], *row["helpers"])}
    refs = set()
    for ref in data["citations"]:
        if (not isinstance(ref, dict) or set(ref) != {"file_id", "line"}
                or not isinstance(ref["file_id"], str)):
            raise ValueError("Invalid citation")
        line = ref["line"]
        lines = files.get(ref["file_id"], [])
        if type(line) != int or not 1 <= line <= len(lines) or not lines[line-1].strip():
            raise ValueError("Citation outside provided code or blank")
        refs.add((ref["file_id"], line))
    if data["verdict"] == "UNKNOWN":
        return data
    a = row["alert"]
    has_warning = any(fid == "F0" and a["start_line"] <= n <= a["end_line"] for fid, n in refs)
    if bind_warning_citation and not has_warning and refs:
        line = a["start_line"]
        lines = files.get("F0", [])
        if 1 <= line <= min(a["end_line"], len(lines)) and lines[line - 1].strip():
            warning = {"file_id": "F0", "line": line}
            return {**data, "citations": [warning, *data["citations"]]}
    if len(refs) < 2 or not has_warning:
        raise ValueError("Decisive verdict needs warning line and supporting evidence")
    return data


def decode_response(result):
    body = result["ollama_response"]
    if body.get("error") or body.get("done") is not True or body.get("done_reason") != "stop":
        raise ValueError("Ollama did not finish normally")
    count = body.get("prompt_eval_count")
    if type(count) is not int or not 0 < count < OPTIONS["num_ctx"] - OPTIONS["num_predict"]:
        raise ValueError("Context budget not verified")
    response = json.loads(body["response"])
    return response


def run_requests(items, output, timeout, config, system, schema, assess, *, dry_run=False):
    index = []
    for key, (row, req) in items.items():
        if (req["system"] != system or req["format"] != schema
                or tuple(req["format"]["properties"]) != tuple(schema["properties"])):
            raise ValueError("Request prompt or schema does not match the run's declared prompt profile.")
        index.append({"issue_id": key, "alert": row["alert"], "source": row["source"]["sha256"],
                      "request_sha256": digest(req)})
    config["cases"] = index
    if not dry_run:
        session = requests.Session()
        session.trust_env = False
        tags = session.get(URL + "/api/tags", timeout=(5, 10), allow_redirects=False)
        tags.raise_for_status()
        matches = [m.get("digest") for m in tags.json()["models"]
                   if (m.get("name") or m.get("model")) == MODEL]
        if len(matches) != 1 or not matches[0]:
            raise ValueError("Không xác định được digest model đã chọn trong Ollama.")
        config["model_digest"] = matches[0]
    config["mode"] = "dry-run" if dry_run else "ollama"
    output.mkdir(parents=True, exist_ok=False)
    write(output / "manifest.json", config)
    for n, (key, (row, req)) in enumerate(items.items(), 1):
        dest = output / f"case-{n:04d}.json"
        result = {"issue_id": key, "request": req}
        if not dry_run:
            start = time.monotonic()
            print(f"[{n}/{len(items)}] {key}", flush=True)
            try:
                response = session.post(URL + "/api/generate", json=req,
                                        timeout=(5, timeout), allow_redirects=False)
                response.raise_for_status()
                result["ollama_response"] = response.json()
                assess(result, row)
            except (requests.RequestException, ValueError, KeyError, TypeError, AttributeError) as exc:
                result["error"] = str(exc)
            result["elapsed_seconds"] = round(time.monotonic() - start, 3)
        write(dest, result)
    print(output)


def read_results(folder):
    manifest = read(folder / "manifest.json")
    if manifest["mode"] != "ollama":
        raise ValueError("Dry-run has no model results")
    records = {}
    for n, item in enumerate(manifest["cases"], 1):
        path = folder / f"case-{n:04d}.json"
        row = read(path) if path.exists() else None
        if row and (row["issue_id"] != item["issue_id"] or digest(row["request"]) != item["request_sha256"]):
            raise ValueError("Stored request does not match manifest")
        records[item["issue_id"]] = (item, row)
    return manifest, records
