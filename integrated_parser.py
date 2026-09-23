"""Run the existing Python and Java parsers and return a shared dependency graph."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "python-parser"))
from python_parser import PythonParser  # noqa: E402


def analyze(project_dir: Path, java_classes: Path, pypi_client=None) -> dict:
    project_dir = Path(project_dir).resolve()
    if not project_dir.is_dir():
        raise ValueError(f"Not a directory: {project_dir}")
    nodes = {}
    files = []
    for path in sorted(project_dir.rglob("*")):
        if not path.is_file() or any(p in {".git", "target", ".venv", "venv"} for p in path.parts):
            continue
        if path.name == "requirements.txt":
            files.append(str(path.relative_to(project_dir)))
            for node in PythonParser(pypi_client=pypi_client).parse(str(path)):
                item = asdict(node)
                nodes.setdefault(item["purl"], item)
        elif path.name in {"pom.xml", "build.gradle", "build.gradle.kts"}:
            files.append(str(path.relative_to(project_dir)))
            completed = subprocess.run(
                ["java", "-cp", str(java_classes), "com.bomerang.JsonDependencyExporter", str(path)],
                capture_output=True, text=True, check=True,
            )
            for item in json.loads(completed.stdout):
                nodes.setdefault(item["purl"], item)
    return {"files": files, "dependencies": list(nodes.values())}


def main():
    parser = argparse.ArgumentParser(description="Analyze Python and Java dependency files")
    parser.add_argument("project_dir", type=Path)
    parser.add_argument("--java-classes", type=Path, default=ROOT / "target" / "classes")
    args = parser.parse_args()
    print(json.dumps(analyze(args.project_dir, args.java_classes), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
