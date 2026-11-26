"""JSON persistence and tool logging extracted from the existing pipeline."""

import json
import os
from pathlib import Path
import re
import subprocess


def save_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def redact(text):
    text = text or ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    token = os.getenv("SONAR_TOKEN")
    if token:
        text = text.replace(token, "REDACTED")
    return re.sub(r"\bsq[apu]_[A-Za-z0-9]+", "REDACTED", text)


def run_command(cmd, log_path, timeout, cwd=None):
    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                                errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        Path(log_path).write_text(redact(exc.stdout) + "\n" + redact(exc.stderr), encoding="utf-8")
        raise RuntimeError(f"Hết thời gian chạy công cụ; xem {log_path}") from None
    Path(log_path).write_text(redact(result.stdout) + "\n[STDERR]\n" + redact(result.stderr), encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"Công cụ trả mã {result.returncode}; xem {log_path}")
    return result.stdout
