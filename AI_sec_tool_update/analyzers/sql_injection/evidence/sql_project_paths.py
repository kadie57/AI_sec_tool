"""Build and query one Joern CPG for a hash-verified Java snapshot."""

import os

from common.joern_project import run_joern_script, snapshot_import, stage_classpath, stage_snapshot
from common.run_io import run_command

from .sql_endpoint_specifications import PROBE
from .sql_source_paths import java_method_name, path_script


VERSION = "sql-project-paths-v2"
SCOPE = "verified_java_snapshot"


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
                                          "signature": signature, "name": java_method_name(signature)}
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
            yield ("sink", index, files[sink["file_id"]]["path"], sink["line"], java_method_name(sink["signature"]))
            for source in sources:
                yield ("source", index, files[source["file_id"]]["path"], source["line"], source["name"])

    with (artifact / "queries.tsv").open("x", encoding="utf-8") as stream:
        for row in rows():
            fields = tuple(map(str, row))
            if any(any(c in field for c in "\t\r\n") for field in fields):
                raise ValueError("Invalid endpoint coordinate in Joern batch")
            stream.write("\t".join(fields) + "\n")
    load = snapshot_import(jars)
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
