"""Compare direct Maven declarations in an external repo with integrated output.

Usage: python validate_external.py PATH_TO_CLONED_REPO --java-classes target/classes
Add --resolve-maven to fetch remote transitive POMs (requires Maven Central access).
This is declaration coverage, not effective dependency-tree accuracy.
"""
import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from integrated_parser import analyze


def direct_maven_coordinates(project):
    expected = set()
    for pom in project.rglob("pom.xml"):
        if any(part in {".git", "target", ".venv", "venv"} for part in pom.parts):
            continue
        root = ET.parse(pom).getroot()
        namespace = {"m": root.tag.split("}")[0][1:]} if root.tag.startswith("{") else {}
        prefix = "m:" if namespace else ""
        for item in root.findall(f"./{prefix}dependencies/{prefix}dependency", namespace):
            group = item.findtext(f"{prefix}groupId", namespaces=namespace)
            name = item.findtext(f"{prefix}artifactId", namespaces=namespace)
            if group and name:
                expected.add((group, name))
    return expected


def compare(project, classes, resolve_maven=False):
    expected = direct_maven_coordinates(project)
    output = analyze(project, classes, resolve_maven=resolve_maven)
    actual = {(item["group"], item["name"]) for item in output["dependencies"]
              if item["ecosystem"] == "maven" and item["depth"] == 1}
    matched = expected & actual
    return {
        "project": str(project.resolve()), "pom_direct_expected": len(expected),
        "pom_direct_found": len(actual), "matched": len(matched),
        "direct_recall": len(matched) / len(expected) if expected else None,
        "direct_precision": len(matched) / len(actual) if actual else None,
        "missing": sorted(f"{g}:{a}" for g, a in expected - actual),
        "extra": sorted(f"{g}:{a}" for g, a in actual - expected),
        "remote_nodes": sum(n["ecosystem"] == "maven" and n["depth"] > 1
                            for n in output["dependencies"]),
        "unresolved_or_placeholder_versions": sum(
            n["ecosystem"] == "maven" and
            (not n["resolved_version"] or n["resolved_version"] == "unknown (managed)" or
             "${" in n["resolved_version"])
            for n in output["dependencies"]),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=Path)
    parser.add_argument("--java-classes", type=Path, default=Path(__file__).parent / "target/classes")
    parser.add_argument("--resolve-maven", action="store_true")
    options = parser.parse_args()
    print(json.dumps(compare(options.project, options.java_classes, options.resolve_maven),
                     ensure_ascii=False, indent=2))
