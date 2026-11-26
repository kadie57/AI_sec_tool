"""Bounded Java value-helper context from the exact Git commit of a scan.

This is a source inventory, not a Java call-graph/type/reflection proof.
No Java is executed and no benchmark labels are opened.
"""
import hashlib
import json
import re
import subprocess

from common.source_text import TOKENS, mask_java

VERSION = "sql-value-helper-context-v1"
QUAL = r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*"
MAX_FILES = 12
MAX_BYTES = 30000
JDBC_TYPES = {"Connection", "Statement", "PreparedStatement", "CallableStatement", "ResultSet"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fingerprint(obj):
    return sha(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode())


def git(repo, *args):
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError("Không đọc được Git tại phiên bản đã quét: " + " ".join(args[:2]))
    return result.stdout


def code_without_literals(source):
    return TOKENS.sub(
                  lambda m: " " * len(m[0]), mask_java(source))


class Repository:
    def __init__(self, root, commit):
        if not re.fullmatch(r"[0-9a-f]{40}", commit or ""):
            raise ValueError("Thiếu commit đầy đủ của lượt quét.")
        self.root, self.commit = root, commit
        names = git(root, "ls-tree", "-r", "--name-only", commit, "--", "src/main/java", "src/main/resources").decode().splitlines()
        self.paths = set(names)
        self.classes = {p[len("src/main/java/"):-5].replace("/", "."): p
                        for p in names if p.startswith("src/main/java/") and p.endswith(".java")}
        self.cache = {}

    def read(self, path):
        if path not in self.paths:
            raise ValueError("Không có file tại commit đã quét: " + path)
        if path not in self.cache:
            raw = git(self.root, "show", self.commit + ":" + path)
            if len(raw) > 100000:
                raise ValueError("File vượt giới hạn ngữ cảnh: " + path)
            self.cache[path] = raw
        return self.cache[path]

    def resolve(self, name, source):
        if name in self.classes:
            return self.classes[name]
        imports = re.findall(r"\bimport\s+(" + QUAL + r")\s*;", mask_java(source))
        package = re.search(r"\bpackage\s+(" + QUAL + r")\s*;", mask_java(source))
        candidates = [q for q in imports if q.rsplit(".", 1)[-1] == name]
        if package:
            candidates.append(package[1] + "." + name)
        found = {self.classes[q] for q in candidates if q in self.classes}
        return next(iter(found)) if len(found) == 1 else None

    def value_dependencies(self, source):
        """Explicit value-object declarations/constructors and assigned static calls.

        JDBC connection/result infrastructure is outside this bounded inventory.
        Arbitrary instance dispatch and wildcard imports are NOT resolved.
        """
        code = code_without_literals(source)
        names = set(re.findall(r"\bnew\s+(" + QUAL + r")\s*\(", code))
        pattern = r"(?<![\w$.])(" + QUAL + r")\s+[A-Za-z_$][\w$]*\s*=\s*([^;]+);"
        for match in re.finditer(pattern, code, re.S):
            typ, rhs = match.groups()
            if typ.rsplit(".", 1)[-1] in JDBC_TYPES:
                continue
            names.add(typ)
            for called in re.findall(r"(" + QUAL + r")\s*\(", rhs):
                if "." in called:
                    names.add(called.rsplit(".", 1)[0])
        names.update(re.findall(r"\b(?:implements|extends)\s+(" + QUAL + r")", code))
        return {p for name in names if (p := self.resolve(name, source))}


def build(repo, main_path, main_raw):
    if repo.read(main_path) != main_raw:
        raise ValueError("Mã chính không khớp commit đã quét; không ghép helper khác phiên bản.")
    files, queue, gaps, links = {}, [main_path], [], []
    while queue:
        path = queue.pop(0)
        if path in files:
            continue
        if len(files) >= MAX_FILES:
            gaps.append("Vượt giới hạn số file helper: " + path)
            continue
        raw = repo.read(path)
        source = raw.decode("utf-8")
        kind = "JAVA" if path.endswith(".java") else "PROPERTIES"
        if kind == "JAVA":
            clean = mask_java(source)
        else:
            clean = "\n".join("" if s.lstrip().startswith(("#", "!")) else s for s in source.splitlines())
        if sum(len(f["masked_source"].encode()) for f in files.values()) + len(clean.encode()) > MAX_BYTES:
            gaps.append("Vượt giới hạn kích thước helper: " + path)
            continue
        files[path] = {"path": path, "sha256": sha(raw), "source": source,
                       "masked_source": clean, "kind": kind}
        if kind != "JAVA":
            continue
        dependencies = repo.value_dependencies(source) - {main_path, path}
        resources = re.findall(r'getResourceAsStream\s*\(\s*"([^"\\]+\.properties)"\s*\)', clean)
        resource_contents = []
        for resource in resources:
            if resource.startswith("/") or ".." in resource.split("/"):
                gaps.append("Chưa xử lý cách phân giải resource: " + resource)
                continue
            rel = "src/main/resources/" + resource
            if rel not in repo.paths:
                gaps.append("Thiếu resource được gọi: " + rel)
                continue
            dependencies.add(rel)
            resource_contents.append(repo.read(rel).decode("utf-8"))
        # Support one explicit reflection idiom: literal package + property value.
        # Include configured class AND constructor fallback classes; never execute them.
        if "Class.forName" in clean:
            matches = re.findall(r'"([A-Za-z_$][\w$.]*\.)"\s*\+\s*\w+\.getProperty\(\s*"([\w.-]+)"\s*\)', clean)
            resolved = False
            for prefix, key in matches:
                for content in resource_contents:
                    values = re.findall(r"(?m)^\s*" + re.escape(key) + r"\s*[=:]\s*([\w$]+)\s*$", content)
                    for value in values:
                        target = repo.classes.get(prefix + value)
                        if target:
                            dependencies.add(target)
                            resolved = True
            if not resolved:
                gaps.append("Chưa xác định đủ đích reflection/configuration trong " + path)
        for dep in sorted(dependencies):
            links.append({"from": path, "to": dep, "basis": "bounded_syntax_and_resource_inventory"})
            if dep not in files and dep not in queue:
                queue.append(dep)
    ordered = [main_path] + sorted(p for p in files if p != main_path)
    indexed = {"F" + str(i): {"file_id": "F" + str(i), **files[path]}
               for i, path in enumerate(ordered) if path in files}
    if "F0" not in indexed:
        raise ValueError("Mã chính vượt giới hạn, chưa tạo yêu cầu AI.")
    return {"version": VERSION, "commit": repo.commit, "files": indexed, "links": links,
            "missing_context": sorted(set(gaps)),
            "scope": "main file plus bounded explicit value-helper and resource inventory",
            "limitations": ["Not a complete Java type resolver or interprocedural dataflow analysis.",
                "Classpath resource is from the scanned repository; deployment overrides are not modeled.",
                "JDBC connection creation/results helpers are not expanded; the reported JDBC call is analyzed as supplied.",
                "Comments are masked; public class identifiers remain visible."]}


def references(bundle):
    """Only substantive code/property lines can be selected as evidence."""
    refs = {}
    for ident, f in bundle["files"].items():
        for line, value in enumerate(f["masked_source"].splitlines(), 1):
            s = value.strip()
            if not s or not re.search(r"[A-Za-z0-9_$]", s):
                continue
            if f["kind"] == "JAVA" and (s.startswith(("package ", "import ", "@"))
                    or s.startswith("throws ")):
                continue
            refs[f"{ident}:{line}"] = {"file_id": ident, "path": f["path"],
                "line": line, "code": f["source"].splitlines()[line-1], "sha256": f["sha256"]}
    return refs


def render(bundle):
    blocks = []
    for ident, f in bundle["files"].items():
        lines = "\n".join(f"{ident}:{i} {s.rstrip()}" for i, s in enumerate(f["masked_source"].splitlines(), 1) if s.strip())
        blocks.append(f"[FILE {ident} | {f['path']}]\n{lines}\n[/FILE {ident}]")
    return "\n\n".join(blocks)
