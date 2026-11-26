"""Find candidate caller files in the same hashed Java snapshot as an alert."""

from hashlib import sha256
from pathlib import Path
import re

from common.source_text import mask_java

from .sql_context_bundle_v1 import MAX_BYTES, MAX_FILES, code_without_literals


VERSION = "snapshot-caller-evidence-v1"
IDENTIFIER = re.compile(r"[\w$]+")


def add_snapshot_callers(inputs, bundles, source_root, hashes):
    """Inventory type references for the JDK probe, without treating them as calls."""
    candidates = {item.relative.stem: [] for item in inputs}
    for name, digest in sorted(hashes.items()):
        relative = Path(name)
        if relative.suffix != ".java":
            continue
        path = (source_root / relative).resolve()
        if relative.is_absolute() or not path.is_relative_to(source_root):
            raise ValueError(f"Đường dẫn Java nằm ngoài snapshot: {name}")
        raw = path.read_bytes()
        if sha256(raw).hexdigest() != digest:
            raise ValueError(f"Mã nguồn khác hash của lượt quét: {name}")
        source = raw.decode("utf-8")
        references = set(IDENTIFIER.findall(code_without_literals(source))) & candidates.keys()
        for target in references:
            if relative.stem != target:
                candidates[target].append({
                    "path": name, "kind": "JAVA", "sha256": digest, "masked_source": mask_java(source),
                })

    for item in inputs:
        bundle = bundles[item.issue["key"]]
        files = bundle["files"]
        existing = {file["path"] for file in files.values()}
        entries = [entry for entry in candidates[item.relative.stem] if entry["path"] not in existing]
        if not entries:
            continue
        if (len(files) + len(entries) > MAX_FILES
                or sum(len(file["masked_source"].encode("utf-8")) for file in [*files.values(), *entries]) > MAX_BYTES):
            bundle["missing_context"].append("Các tệp có thể chứa lời gọi vượt giới hạn gói bằng chứng.")
            continue
        caller_ids = []
        for entry in entries:
            file_id = f"F{len(files)}"
            files[file_id] = {**entry, "file_id": file_id}
            caller_ids.append(file_id)
        bundle["snapshot_callers"] = caller_ids
