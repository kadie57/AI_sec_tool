"""Shared staging and execution for a local, read-only Java CPG snapshot."""

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

from .run_io import run_command
from .source_text import mask_java


def java_dependencies(jars):
    if shutil.which("java") is None:
        raise ValueError("Cần JDK 17 trở lên để xác minh chữ ký source/sink.")
    entries = []
    for value in jars:
        jar = value.expanduser().resolve()
        if jar.suffix != ".jar" or not jar.is_file() or os.pathsep in str(jar):
            raise ValueError(f"Classpath cần đường dẫn đến tệp JAR cục bộ: {jar}")
        with jar.open("rb") as stream:
            digest = sha256()
            for block in iter(lambda: stream.read(65536), b""):
                digest.update(block)
        entries.append({"path": str(jar), "sha256": digest.hexdigest()})
    return entries


def stage_snapshot(root, hashes, target):
    root, target = root.resolve(), target.resolve()
    files = {}
    for name, expected in sorted(hashes.items()):
        relative = Path(name)
        if relative.suffix != ".java":
            continue
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != name or any(c in name for c in "\t\r\n"):
            raise ValueError(f"Invalid snapshot path: {name}")
        original = (root / relative).resolve()
        if not original.is_relative_to(root):
            raise ValueError(f"Source is outside the snapshot: {name}")
        raw = original.read_bytes()
        if sha256(raw).hexdigest() != expected:
            raise ValueError(f"Source hash differs from the scan: {name}")
        source = mask_java(raw.decode("utf-8"))
        staged = target / relative
        staged.parent.mkdir(parents=True, exist_ok=True)
        with staged.open("xb") as stream:
            stream.write(source.encode("utf-8"))
        files[name] = {"path": name, "kind": "JAVA", "sha256": expected, "masked_source": source}
    if not files:
        raise ValueError("The collection has no Java sources in its snapshot manifest")
    return files


def stage_classpath(recorded, replacements, output):
    paths = replacements or [Path(entry["path"]) for entry in recorded]
    actual = java_dependencies(paths)
    if [entry["sha256"] for entry in actual] != [entry["sha256"] for entry in recorded]:
        raise ValueError("Java classpath hashes or order differ from the baseline")
    target = output / "type-jars"
    target.mkdir()
    staged = []
    for n, entry in enumerate(actual, 1):
        raw = Path(entry["path"]).read_bytes()
        if sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError("Classpath JAR changed while staging")
        path = target / f"{n:04d}.jar"
        path.write_bytes(raw)
        staged.append(path)
    return staged


def snapshot_import(jars):
    command = ["joern-parse", "/project", "--language", "JAVASRC", "-o", "/work/snapshot.bin",
               "--frontend-args", "--delombok-mode", "no-delombok"]
    if jars:
        command.extend(["--inference-jar-paths", ",".join(f"/work/type-jars/{path.name}" for path in jars)])
    options = ", ".join(json.dumps(arg) for arg in command)
    load = f'''val build = scala.sys.process.Process(Seq({options})).!
  require(build == 0, "Java snapshot parse failed")
  importCpg("/work/snapshot.bin", "snapshot")'''
    return load


def run_joern_script(root, artifact, image, *, container_workdir="/work"):
    """Run the staged slice against read-only sources in the pinned local image."""
    container_name = "thesis-joern-" + uuid.uuid4().hex[:12]
    try:
        return run_command([
            "docker", "run", "--rm", "--name", container_name, "--pull=never", "--network=none",
            "-v", f"{root}:/project:ro", "-v", f"{artifact}:/work", "-w", container_workdir,
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
