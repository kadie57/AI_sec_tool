"""Offline tests of the exact, manually inspected PathCase01 draft.

Uses only temporary synthetic fixtures. Does not touch /var/www or project Java.
"""
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
ORIGINAL_HASH = "cd52945fba3047ebbffb2e963993d05f26acad1be5843c5c3b203034978550a2"
PROPOSAL_HASH = "725820a7cf3ed4c0c949153cd59a3659efb5a2fba5e4e04e600dea08c55ec5f6"


def sha(data): return hashlib.sha256(data).hexdigest()


def run(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=30)
    return {"returncode": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}


REVIEWED_HASH = '5f35eb48c083cb2d1cabef5ec6937c447f7397b3df6936d6083b3e15d7bba9d5'


def main():
    original = (HERE / "original.java.txt").read_bytes()
    proposed = (HERE / "proposed.java.txt").read_bytes()
    reviewed = (HERE / "reviewed.java.txt").read_bytes()
    if sha(original) != ORIGINAL_HASH or sha(proposed) != PROPOSAL_HASH or sha(reviewed) != REVIEWED_HASH:
        raise SystemExit("Source differs from the reviewed version; refusing to execute changed code.")
    java = shutil.which("java")
    javac = shutil.which("javac")
    if not java:
        raise SystemExit("Java is required. No software was installed automatically.")
    compiler = [javac] if javac else [java, "com.sun.tools.javac.Main"]
    result = {"created_at": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
              "java": run([java, "-version"]), "compiler": run(compiler + ["-version"]),
              "source_sha256": sha(original), "proposed_sha256": sha(proposed), "reviewed_sha256": sha(reviewed),
              "scope": "Exact sources compiled; functional copies change only the fixed base-directory literal.",
              "checks": [], "limitations": []}
    if result["compiler"]["returncode"]:
        raise SystemExit("A JDK compiler is required (javac or jdk.compiler module).")
    with tempfile.TemporaryDirectory(prefix="path-draft-review-") as temporary:
        root = Path(temporary)
        base = root / "uploads"; base.mkdir()
        (base / "sub").mkdir()
        (base / "ok.txt").write_bytes(b"A sample")
        (base / "sub/nested.txt").write_bytes(b"N sample")
        (base / "empty.txt").write_bytes(b"")
        (base / "binary.bin").write_bytes(bytes([255, 0, 1]))
        outside = root / "outside.txt"; outside.write_bytes(b"U synthetic outside fixture")
        sibling = root / "uploads_backup"; sibling.mkdir()
        (sibling / "secret.txt").write_bytes(b"X synthetic sibling fixture")
        (base / "inside-link").symlink_to(base / "ok.txt")
        (base / "outside-link").symlink_to(outside)
        (base / "dir-link").symlink_to(sibling, target_is_directory=True)
        classes = {}
        result["compilation"] = {}
        for kind, raw in (("original", original), ("proposed", proposed), ("reviewed", reviewed)):
            text = raw.decode()
            if text.count('"/var/www/uploads/"') != 1:
                raise SystemExit("Unexpected source structure; no files were executed.")
            for mode in ("exact", "fixture"):
                folder = root / f"{kind}_{mode}"; folder.mkdir()
                src = folder / "PathCase01.java"
                content = text if mode == "exact" else text.replace('"/var/www/uploads/"', json.dumps(str(base) + "/"))
                src.write_text(content)
                compiled = run(compiler + ["-encoding", "UTF-8", "-d", str(folder), str(src)])
                result["compilation"][kind + "_" + mode] = compiled
                if compiled["returncode"]:
                    raise SystemExit("Compilation failed: " + compiled["stderr"])
                if mode == "fixture": classes[kind] = folder
        cases = [
            ("normal_file", ["ok.txt"], "65", "allow"),
            ("nested_file", ["sub/nested.txt"], "78", "allow"),
            ("internal_parent_segment", ["sub/../ok.txt"], "65", "allow"),
            ("internal_symlink", ["inside-link"], "65", "allow"),
            ("empty_file", ["empty.txt"], "-1", "allow"),
            ("binary_first_byte", ["binary.bin"], "255", "allow"),
            ("parent_traversal", ["../outside.txt"], "85", "block"),
            ("sibling_prefix_bypass", ["../uploads_backup/secret.txt"], "88", "block"),
            ("external_file_symlink", ["outside-link"], "85", "block"),
            ("external_directory_symlink", ["dir-link/secret.txt"], "88", "block"),
            ("missing_file", ["not-present.txt"], None, "missing"),
            ("wrong_argument_count", [], None, "argument"),
        ]
        for name, args, expected, behavior in cases:
            outputs = {kind: run([java, "-cp", str(folder), "pilot_path22.PathCase01", *args]) for kind, folder in classes.items()}
            before, after = outputs["original"], outputs["proposed"]
            if behavior == "allow":
                ok = all(o["returncode"] == 0 and o["stdout"] == expected for o in outputs.values())
            elif behavior == "block":
                ok = before["returncode"] == 0 and before["stdout"] == expected and all(o["returncode"] != 0 and "SecurityException" in o["stderr"] for k,o in outputs.items() if k != "original")
            elif behavior == "missing":
                ok = all(o["returncode"] != 0 for o in outputs.values()) and all("NoSuchFileException" in o["stderr"] for k,o in outputs.items() if k != "original")
            else:
                ok = all(o["returncode"] != 0 and "IllegalArgumentException" in o["stderr"] for o in outputs.values())
            result["checks"].append({"name": name, "expected": behavior, "passed": ok, **outputs})
        # Controlled filesystem changes after validation; no naturally timed attack.
        result["controlled_interleavings"] = []
        for kind, content in (("proposed", proposed), ("reviewed", reviewed)):
            for scenario in ("file_replacement", "directory_replacement"):
                tag = kind + "_" + scenario
                if scenario == "file_replacement":
                    argument = tag + ".txt"
                    (base / argument).write_bytes(b"A safe fixture")
                    hook = ('java.nio.file.Files.delete(targetPath);\n'
                            'java.nio.file.Files.createSymbolicLink(targetPath, Paths.get(' + json.dumps(str(outside)) + '));\n')
                else:
                    test_dir = base / tag; test_dir.mkdir()
                    (test_dir / "file.txt").write_bytes(b"A safe fixture")
                    outside_dir = root / (tag + "_outside"); outside_dir.mkdir()
                    (outside_dir / "file.txt").write_bytes(b"U synthetic outside fixture")
                    argument = tag + "/file.txt"
                    hook = ('java.nio.file.Files.move(targetPath.getParent(), Paths.get(' + json.dumps(str(base / (tag + "_parked"))) + '));\n'
                            'java.nio.file.Files.createSymbolicLink(targetPath.getParent(), Paths.get(' + json.dumps(str(outside_dir)) + '));\n')
                folder = root / ("controlled_" + tag); folder.mkdir()
                text = content.decode().replace('"/var/www/uploads/"', json.dumps(str(base) + "/"))
                marker = "        File file = targetPath.toFile();" if kind == "proposed" else "            try (SeekableByteChannel channel = openRelative(directory, relative);"
                if text.count(marker) != 1:
                    raise SystemExit("Unexpected marker for controlled-interleaving test.")
                (folder / "PathCase01.java").write_text(text.replace(marker, hook + marker))
                compiled = run(compiler + ["-encoding", "UTF-8", "-d", str(folder), str(folder / "PathCase01.java")])
                if compiled["returncode"]:
                    raise SystemExit(compiled["stderr"])
                output = run([java, "-cp", str(folder), "pilot_path22.PathCase01", argument])
                outside_read = output["returncode"] == 0 and output["stdout"] == "85"
                result["controlled_interleavings"].append({"variant": kind, "scenario": scenario, "instrumented": True,
                    "outside_read_reproduced": outside_read, "blocked_without_output": output["returncode"] != 0 and not output["stdout"], "output": output})
        result["limitations"] = [
            "No naturally timed attack or production filesystem was exercised.",
            "No SonarQube rescan was performed.",
            "The reviewed candidate requires a trusted configured root/ancestors and a SecureDirectoryStream provider. It fails closed if unsupported.",
            "These tests do not prove protection against every filesystem/permission/race scenario; hard-link provenance and business access control are outside this review.",
        ]
        result["static_checks_passed"] = sum(c["passed"] for c in result["checks"])
        result["static_checks_total"] = len(result["checks"])
        result["ai_review_verdict"] = "NEEDS_REVISION_FOR_STATED_UNTRUSTED_WRITABLE_DIRECTORY_ASSUMPTION"
        revised_blocks = all(item["blocked_without_output"] for item in result["controlled_interleavings"] if item["variant"] == "reviewed")
        result["reviewed_candidate_verdict"] = ("READY_FOR_PROJECT_VALIDATION_WITH_STATED_LIMITATIONS"
            if result["static_checks_passed"] == result["static_checks_total"] and revised_blocks else "VALIDATION_NOT_PASSED")
    dest = HERE / "verification_results.json"
    dest.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(f"STATIC_CHECKS: {result['static_checks_passed']}/{result['static_checks_total']}")
    for item in result["controlled_interleavings"]:
        print("CONTROLLED_CHANGE:", item["variant"], item["scenario"], "outside_read=", item["outside_read_reproduced"], "blocked=", item["blocked_without_output"])
    print("AI_REVIEW:", result["ai_review_verdict"])
    print("REVIEWED_CANDIDATE:", result["reviewed_candidate_verdict"])
    print("SAVED:", dest)
    controlled_ok = all(item["outside_read_reproduced"] if item["variant"] == "proposed" else item["blocked_without_output"] for item in result["controlled_interleavings"])
    return 0 if result["static_checks_passed"] == result["static_checks_total"] and controlled_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
