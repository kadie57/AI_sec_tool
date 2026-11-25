"""Build and query one Joern CPG for a hash-verified Java snapshot."""

from hashlib import sha256
import json
import os
from pathlib import Path

from .joern_sql import run_joern_script
from .source_text import mask_java
from .sql_endpoint_specifications import PROBE, java_dependencies
from .sql_source_paths import path_script
from ..run_io import run_command


VERSION = "sql-project-paths-v1"
SCOPE = "verified_java_snapshot"


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


def read_servlet_sites(files, project, jars, output):
    """Apply the existing JDK Servlet signature policy to every Java file."""
    java = output / "java-files.tsv"
    ids = {f"S{i}": path for i, path in enumerate(files)}
    java.write_text("".join(f"{key}\t{project / path}\n" for key, path in ids.items()), encoding="utf-8")
    empty = output / "empty-classpath"
    empty.mkdir()
    classpath = os.pathsep.join(map(str, jars)) or str(empty)
    result = run_command(["java", "-Dsql.evidence.projectServletSources=true", str(PROBE),
                          "0", "0", classpath, str(empty), str(java)], output / "java-project.log", 120)
    sources, errors = {}, None
    for line in result.splitlines():
        record, *fields = line.split("\t")
        if record == "STATUS":
            errors = int(fields[0])
        elif record == "P":
            key, line, column, owner, signature = fields
            name = ids[key]
            line, column = int(line), int(column)
            code = files[name]["masked_source"].splitlines()
            if not 1 <= line <= len(code) or not code[line - 1].strip():
                raise ValueError("Servlet API has no coordinate in the verified snapshot")
            sources[name, line, column] = {"path": name, "line": line, "column": column, "owner": owner,
                                          "signature": signature, "name": signature.partition("(")[0]}
        else:
            raise ValueError("Unexpected Java project probe output")
    if errors is None:
        raise ValueError("Java project probe did not report compilation status")
    return list(sources.values()), errors


def case_files(bundle_files, snapshot, needed):
    files = bundle_files.copy()
    file_ids = {}
    for key, file in files.items():
        if file["kind"] == "JAVA":
            name = file["path"]
            entry = snapshot.get(name)
            if not entry or any(file[field] != entry[field] for field in ("sha256", "masked_source")) or name in file_ids:
                raise ValueError(f"Evidence file does not match the Java snapshot: {name}")
            file_ids[name] = key
    cursor = 0
    # Stable ids keep evidence comparable across replays.
    for name in sorted(needed - file_ids.keys()):
        while f"F{cursor}" in files:
            cursor += 1
        key = f"F{cursor}"
        files[key] = {**snapshot[name], "file_id": key}
        file_ids[name] = key
    return files, file_ids


def trace_files(stdout, snapshot):
    paths = set()
    for row in stdout.splitlines():
        fields = row.split("\t")
        if fields[1] == "NODE":
            paths.add(fields[5])
        elif fields[1] == "TARGET":
            paths.update((fields[4], fields[7]))
    return paths & snapshot.keys()


def write_batch(artifact, tasks, jars):
    def rows():
        for index, files, sources, sink in tasks:
            yield ("sink", index, files[sink["file_id"]]["path"], sink["line"], sink["signature"].partition("(")[0])
            for source in sources:
                yield ("source", index, files[source["file_id"]]["path"], source["line"], source["name"])

    with (artifact / "queries.tsv").open("x", encoding="utf-8") as stream:
        for row in rows():
            fields = tuple(map(str, row))
            if any(any(c in field for c in "\t\r\n") for field in fields):
                raise ValueError("Invalid endpoint coordinate in Joern batch")
            stream.write("\t".join(fields) + "\n")
    command = ["joern-parse", "/project", "--language", "JAVASRC", "-o", "/work/snapshot.bin",
               "--frontend-args", "--delombok-mode", "no-delombok"]
    if jars:
        command.extend(["--inference-jar-paths", ",".join(f"/work/type-jars/{path.name}" for path in jars)])
    options = ", ".join(json.dumps(arg) for arg in command)
    load = f'''val build = scala.sys.process.Process(Seq({options})).!
  require(build == 0, "Java snapshot parse failed")
  importCpg("/work/snapshot.bin", "snapshot")'''
    batch = '''  val input = scala.io.Source.fromFile("/work/queries.tsv", "UTF-8")
  val entries = try input.getLines().map(_.split("\\t", -1)).toList finally input.close()
  val byCase = entries.groupBy(_(1).toInt)
  def ref(row: Array[String]): (String, Int, String) = (row(2), row(3).toInt, row(4))
  byCase.toList.sortBy(_._1).foreach { case (id, entries) =>
    val sink = entries.find(_(0) == "sink").get
    println(s"SQL_CASE\\t$id")
    trace(entries.filter(_(0) == "source").map(ref), ref(sink))
  }'''
    (artifact / "slice.sc").write_text(path_script(load, batch, indexed=True), encoding="utf-8")


def split_batch(stdout, expected):
    results = {}
    current = None
    for line in stdout.splitlines():
        if line.startswith("SQL_CASE\t"):
            current = int(line.split("\t")[1])
            if current in results:
                raise ValueError(f"Duplicate Joern batch result: {current}")
            results[current] = []
        elif line.startswith("SQL_PATH\t"):
            if current is None:
                raise ValueError("Joern path has no alert in the batch")
            results[current].append(line)
    if results.keys() != expected:
        raise ValueError("Joern did not complete the expected alert batch")
    return {index: "\n".join(rows) for index, rows in results.items()}


def query_snapshot(project, artifact, jars, image, tasks):
    write_batch(artifact, tasks, jars)
    result = run_joern_script(project, artifact, image)
    return split_batch(result, {index for index, _, _, _ in tasks})
