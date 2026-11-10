"""Run the explicit offline suites in a disposable source workspace.

Never compile into the caller's target/classes. Output directory must be new.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
MAIN = [
    "python-parser/test", "test_integrated_parser.py", "test_cyclonedx_converter.py",
    "test_security_sbom_pipeline.py", "test_remote_maven.py",
    "python-security-integration/test_integrated_security.py",
    "python-security-integration/test_risk_model.py", "test_repository_evaluation.py",
    "test_python_declarations.py", "test_mixed_integration.py", "test_security_step5.py",
]
SUITES = [
    ("main", MAIN, ["python-parser", "python-security-integration"], 317),
    ("security-review", ["src/main/java/com/bomerang/test_" + name + ".py" for name in
        ["week7", "normalize_week7", "osv_version_matcher", "maven_versions", "maven_qualifiers",
         "evaluation_metrics", "rebuild_selected_graph", "review_priorities", "risk_model"]],
     ["src/main/java/com/bomerang"], 95),
    ("legacy-parser", ["python-security-integration/python-parser/test"],
     ["python-security-integration/python-parser"], 26),
]


def write(path, data):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")


def hashes(directory):
    return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in directory.rglob("*") if p.is_file()} if directory.exists() else {}


def stage_sources(stage):
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", "*.class", ".pytest_cache", "*.log", ".gradle")
    for directory in ["python-parser", "python-security-integration", "src", "integration-fixtures",
                      "security-fixtures", "ci"]:
        shutil.copytree(ROOT / directory, stage / directory, ignore=ignore)
    for file in ROOT.glob("*.py"):
        shutil.copy2(file, stage / file.name)
    for directory in ["gold", "sources/flask"]:
        shutil.copytree(ROOT / "accuracy-tests" / directory, stage / "accuracy-tests" / directory)
    shutil.copy2(ROOT / "accuracy-tests/repository_cases.json", stage / "accuracy-tests/repository_cases.json")
    legacy_result = stage / "accuracy-tests/results/flask-integrated-final.json"
    legacy_result.parent.mkdir(parents=True)
    shutil.copy2(ROOT / "ci/fixtures/flask-step2-integrated.json", legacy_result)
    for name in ["mixed-resolved.json", "mixed.cdx.json"]:
        dest = stage / "test-reports/step4" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "ci/fixtures" / name, dest)


def run(command, stage, env, output, name):
    with (output / (name + ".log")).open("x", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=stage, env=env, stdout=stream,
                                stderr=subprocess.STDOUT, encoding="utf-8", timeout=600)
    print(name + ": exit " + str(result.returncode), flush=True)
    if result.returncode:
        print((output / (name + ".log")).read_text(encoding="utf-8"), flush=True)
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = hashes(ROOT / "target/classes")
    summary = {"started_at": datetime.now(timezone.utc).isoformat(),
               "python": sys.version, "platform": platform.platform(),
               "packages": {n: importlib.metadata.version(n) for n in
                            ["pytest", "packaging", "requests", "jsonschema", "referencing"]},
               "github_actions_execution": "not asserted by local runner",
               "suites": {}, "commands": [], "success": False}
    failed = False
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
    env.pop("PYTEST_ADDOPTS", None)
    try:
        with tempfile.TemporaryDirectory(prefix="bomerang-ci-") as temp:
            stage = Path(temp)
            stage_sources(stage)
            env["PYTHONPATH"] = os.pathsep.join(str(stage / p) for p in ["python-parser", "python-security-integration"])
            java = stage / "src/main/java/com/bomerang"
            (stage / "target/classes").mkdir(parents=True)
            commands = [
                ("java-version", ["java", "-version"]),
                ("javac-version", ["javac", "-version"]),
                ("compile-exporter", ["javac", "--release", "17", "-encoding", "UTF-8", "-sourcepath",
                    "src/main/java", "-d", "target/classes", "src/main/java/com/bomerang/JsonDependencyExporter.java"]),
                ("compile-bridge", ["javac", "--release", "17", "-encoding", "UTF-8", "-cp",
                    str(java / "lib/maven-artifact-3.9.9.jar"), "-d", str(java / "bridge"),
                    str(java / "bridge/MavenComparisonServer.java")]),
            ]
            for name, command in commands:
                summary["commands"].append(command)
                if run(command, stage, env, output, name):
                    raise RuntimeError(name + " failed")
            for name, targets, paths, expected in SUITES:
                env["PYTHONPATH"] = os.pathsep.join(str(stage / p) for p in paths)
                xml = output / (name + ".xml")
                command = [sys.executable, "-B", "-m", "pytest", "--import-mode=importlib",
                           "-p", "no:cacheprovider", "-q", *targets, "--junitxml=" + str(xml)]
                summary["commands"].append(command)
                rc = run(command, stage, env, output, name)
                cases = list(ET.parse(xml).iter("testcase"))
                counts = Counter("failed" if c.find("failure") is not None else
                                 "error" if c.find("error") is not None else
                                 "skipped" if c.find("skipped") is not None else "passed" for c in cases)
                counts = {k: counts[k] for k in ["passed", "failed", "error", "skipped"]}
                identities = [(c.get("classname"), c.get("name")) for c in cases]
                ok = rc == 0 and counts["passed"] == expected and len(cases) == expected and len(set(identities)) == expected
                summary["suites"][name] = {**counts, "expected": expected, "gate_passed": ok, "targets": targets}
                failed |= not ok
            env["PYTHONPATH"] = os.pathsep.join(str(stage / p) for p in ["python-parser", "python-security-integration", "."])
            command = [sys.executable, "-B", "evaluate_repository_parsing.py", "--source",
                       "accuracy-tests/sources/flask", "--declarations", "--output", str(output / "flask.json"),
                       "--save-integrated", str(output / "flask-integrated.json")]
            summary["commands"].append(command)
            failed |= run(command, stage, env, output, "flask") != 0
            command = [sys.executable, "-B", "ci/verify_artifacts.py", str(output)]
            summary["commands"].append(command)
            failed |= run(command, stage, env, output, "artifacts") != 0
    except Exception as exc:
        summary["error"] = str(exc)
        failed = True
    finally:
        after = hashes(ROOT / "target/classes")
        summary["target_classes_unchanged"] = before == after
        summary["target_file_count"] = len(before)
        failed |= before != after
        summary["total"] = {k: sum(s[k] for s in summary["suites"].values())
                            for k in ["passed", "failed", "error", "skipped"]}
        summary["success"] = not failed
        write(output / "summary.json", summary)
        print(json.dumps({"success": not failed, "total": summary["total"],
                          "target_classes_unchanged": before == after}), flush=True)
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
