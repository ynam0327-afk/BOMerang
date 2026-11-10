"""Capture actual Python analysis and replay it against frozen PyPI responses.

Output must be a new directory. --snapshot disables all external PyPI access.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "python-parser"), str(ROOT / "python-security-integration")]
from python_parser import PythonParser
from pypi_client import PyPIClient
from integrated_parser import analyze
from cyclonedx_converter import convert_to_cyclonedx
from validate_cyclonedx import validate_document


class SnapshotPyPI(PyPIClient):
    def __init__(self, snapshot=None):
        self.frozen = snapshot is not None
        self.snapshot = snapshot or {"metadata": {}, "versions": {}}

    def get_release_metadata(self, name, version):
        key = name + "@" + version
        if key not in self.snapshot["metadata"]:
            if self.frozen:
                raise AssertionError("Missing frozen metadata: " + key)
            self.snapshot["metadata"][key] = super().get_release_metadata(name, version)
        return self.snapshot["metadata"][key]

    def get_available_versions(self, name):
        if name not in self.snapshot["versions"]:
            if self.frozen:
                raise AssertionError("Missing frozen version list: " + name)
            self.snapshot["versions"][name] = super().get_available_versions(name)
        return self.snapshot["versions"][name]


def write(output, name, data):
    with (output / name).open("x", encoding="utf-8") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("input", type=Path)
    args.add_argument("--output", required=True, type=Path)
    args.add_argument("--snapshot", type=Path)
    options = args.parse_args()
    options.output.mkdir(parents=True, exist_ok=False)
    source = options.input.resolve()
    client = SnapshotPyPI(json.loads(options.snapshot.read_text(encoding="utf-8")) if options.snapshot else None)
    parser = PythonParser(client)
    raw = [asdict(node) for node in parser.parse(str(source))]
    graph = analyze(source.parent, ROOT / "target/classes", client)
    bom = convert_to_cyclonedx(graph)
    write(options.output, "parser.json", raw)
    write(options.output, "graph.json", graph)
    write(options.output, "bom.cdx.json", bom)
    write(options.output, "schema.json", validate_document(bom))
    write(options.output, "pypi-snapshot.json", client.snapshot)
    details = {
        "input": str(source), "input_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "parser_module": str(sys.modules["python_parser"].__file__),
        "parser_nodes": len(raw), "integrated_nodes": len(graph["dependencies"]),
        "urllib3_parser": [row for row in raw if row["name"].lower() == "urllib3"],
        "urllib3_integrated": [row for row in graph["dependencies"] if row["name"] == "urllib3"],
        "requests_metadata": {key: data.get("info", {}).get("requires_dist") for key, data in client.snapshot["metadata"].items() if key.lower().startswith("requests@")},
        "frozen_replay": client.frozen,
    }
    write(options.output, "summary.json", details)
    print(json.dumps(details, ensure_ascii=True), flush=True)


if __name__ == "__main__":
    main()
