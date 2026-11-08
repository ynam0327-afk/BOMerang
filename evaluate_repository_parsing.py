"""Evaluate direct dependency declarations independently of version resolution.

No network operations. Source mode analyzes a hash-verified snapshot using the
root integrated_parser.py in a fresh subprocess with an offline PyPI client.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import sys
import tempfile

from packaging.markers import Marker, default_environment
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parent
MISSING = "<not-recorded>"


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_new(path, document):
    """Never overwrite a previous result, including untracked files."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(document, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def required(row, keys, label):
    if not isinstance(row, dict):
        raise ValueError(f"{label} must be an object")
    missing = set(keys) - row.keys()
    if missing:
        raise ValueError(f"{label} missing fields: {sorted(missing)}")


def source_name(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("source_file must be a nonempty repository-relative path")
    value = value.replace("\\", "/")
    if value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise ValueError("source_file must be repository-relative; use --source-root for absolute paths")
    path = PurePosixPath(value)
    if ".." in path.parts:
        raise ValueError("source_file cannot escape the repository")
    return str(path)


def identity(row):
    if not isinstance(row["ecosystem"], str):
        raise ValueError("ecosystem must be a string")
    name, eco = row["name"], row["ecosystem"].lower()
    if not isinstance(name, str) or not name:
        raise ValueError("name must be a nonempty string")
    if eco == "pypi":
        name = canonicalize_name(name)
    elif eco == "maven":
        group = row.get("group")
        if not isinstance(group, str) or not group:
            raise ValueError("Maven rows require group")
        name = group + ":" + name
    else:
        raise ValueError(f"Unsupported ecosystem: {eco}")
    return eco, name, source_name(row["source_file"])


def normalized_attribute(row, key):
    if key not in row or row[key] == MISSING:
        return MISSING
    value = row[key]
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{key} must be a string or null")
    if key == "declared_version" and row["ecosystem"].lower() == "pypi":
        return str(SpecifierSet(value or ""))
    if key == "marker" and value:
        return str(Marker(value))
    if key == "marker":
        return value or None
    return value


ATTRIBUTES = ("declared_version", "scope", "marker")


def validate_gold(gold):
    required(gold, ("dependencies",), "gold")
    if not isinstance(gold["dependencies"], list):
        raise ValueError("gold.dependencies must be an array")
    for row in gold["dependencies"]:
        required(row, ("name", "ecosystem", "declared_version", "scope",
                       "source_file", "marker", "evidence"), "gold dependency")
        identity(row)
        for attr in ATTRIBUTES:
            normalized_attribute(row, attr)
        if not row["evidence"]:
            raise ValueError("gold evidence must be nonempty")


def extract_direct(graph, source_root=None):
    required(graph, ("dependencies",), "integrated result")
    if not isinstance(graph["dependencies"], list):
        raise ValueError("dependencies must be an array")
    rows, transitive = [], 0
    for item in graph["dependencies"]:
        required(item, ("name", "ecosystem", "depth"), "dependency")
        if not isinstance(item["depth"], int) or isinstance(item["depth"], bool) or item["depth"] < 1:
            raise ValueError("depth must be a positive integer")
        if item["depth"] > 1:
            transitive += 1
            continue
        required(item, ("declared_version", "resolved_version", "version_status"), "direct dependency")
        if item["version_status"] not in ("confirmed", "estimated", "unresolved"):
            raise ValueError("version_status must be confirmed, estimated or unresolved")
        if item["resolved_version"] is not None and not isinstance(item["resolved_version"], str):
            raise ValueError("resolved_version must be a string or null")
        if (item["version_status"] == "unresolved") != (item["resolved_version"] is None):
            raise ValueError("version_status and resolved_version are inconsistent")
        sources = item.get("source_files") or [item.get("source_file")]
        if not isinstance(sources, list) or not sources:
            raise ValueError("direct dependency requires source_file or source_files")
        for source in dict.fromkeys(sources):
            if source_root and isinstance(source, str) and (
                Path(source).is_absolute() or re.match(r"^[A-Za-z]:", source)
            ):
                try:
                    source = Path(source).resolve().relative_to(Path(source_root).resolve()).as_posix()
                except ValueError as exc:
                    raise ValueError("source file is outside --source-root") from exc
            relative_source = source_name(source)
            row = dict(item, source_file=relative_source, source_files=[relative_source])
            identity(row)
            for attr in ATTRIBUTES:
                normalized_attribute(row, attr)
            rows.append(row)
    return rows, transitive


def pair_rows(expected, actual):
    """Minimum-cost one-to-one pairing inside a package/source bucket.

    Successive shortest augmenting paths preserve duplicate declarations while
    maximizing total attribute matches. Counts never use a set of package names.
    """
    n, m = len(expected), len(actual)
    end = n + m + 1
    graph = [[] for _ in range(end + 1)]

    def edge(a, b, cost):
        forward = [b, len(graph[b]), 1, cost]
        backward = [a, len(graph[a]), 0, -cost]
        graph[a].append(forward)
        graph[b].append(backward)
        return forward

    for i in range(n):
        edge(0, i + 1, 0)
    for j in range(m):
        edge(n + j + 1, end, 0)
    candidates = []
    for i, gold in enumerate(expected):
        for j, found in enumerate(actual):
            cost = sum(normalized_attribute(gold, a) != normalized_attribute(found, a) for a in ATTRIBUTES)
            candidates.append((i, j, edge(i + 1, n + j + 1, cost)))
    for _ in range(min(n, m)):
        distances = [float("inf")] * len(graph)
        previous = [None] * len(graph)
        distances[0] = 0
        for _ in range(len(graph) - 1):
            changed = False
            for a, links in enumerate(graph):
                for k, (b, _, capacity, cost) in enumerate(links):
                    if capacity and distances[a] + cost < distances[b]:
                        distances[b] = distances[a] + cost
                        previous[b] = (a, k)
                        changed = True
            if not changed:
                break
        cursor = end
        while cursor:
            a, k = previous[cursor]
            link = graph[a][k]
            link[2] -= 1
            graph[cursor][link[1]][2] += 1
            cursor = a
    pairs = [(i, j) for i, j, link in candidates if link[2] == 0]
    used_gold, used_actual = {i for i, _ in pairs}, {j for _, j in pairs}
    return pairs, [i for i in range(n) if i not in used_gold], [j for j in range(m) if j not in used_actual]


def detection(tp, fp, fn):
    ratio = lambda a, b: a / b if b else None
    return {"TP": tp, "FP": fp, "FN": fn,
            "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
            "f1_score": ratio(2 * tp, 2 * tp + fp + fn)}


def compare_rows(expected, actual):
    gold_buckets, actual_buckets = defaultdict(list), defaultdict(list)
    for row in expected:
        gold_buckets[identity(row)].append(row)
    for row in actual:
        actual_buckets[identity(row)].append(row)
    matched, missing, extra = [], [], []
    for key in sorted(gold_buckets.keys() | actual_buckets.keys()):
        gold, found = gold_buckets[key], actual_buckets[key]
        pairs, absent, unexpected = pair_rows(gold, found)
        matched.extend({"identity": list(key), "gold": gold[i], "actual": found[j]} for i, j in pairs)
        missing.extend(gold[i] for i in absent)
        extra.extend(found[j] for j in unexpected)
    attributes = {}
    for attr in ATTRIBUTES:
        details, matches, unknown = [], 0, 0
        for pair in matched:
            gold = normalized_attribute(pair["gold"], attr)
            actual_value = normalized_attribute(pair["actual"], attr)
            if actual_value == MISSING:
                unknown += 1
                state = "unavailable"
            elif actual_value == gold:
                matches += 1
                continue
            else:
                state = "mismatch"
            details.append({"identity": pair["identity"], "expected": gold,
                            "actual": actual_value, "status": state})
        total = len(matched)
        attributes[attr] = {
            "matched": matches, "mismatched": total - matches - unknown,
            "unavailable": unknown, "paired_declarations": total,
            "agreement_over_pairs": matches / total if total else None,
            "recorded_coverage": (total - unknown) / total if total else None,
            "details": details,
        }
    strict = sum(all(normalized_attribute(p["gold"], a) == normalized_attribute(p["actual"], a)
                     for a in ATTRIBUTES) for p in matched)
    return {"detection": detection(len(matched), len(extra), len(missing)),
            "attributes": attributes, "strict_attribute_matches": strict,
            "missing": missing, "extra": extra, "pairs": matched}


def evaluate(gold, graph):
    validate_gold(gold)
    rows, transitive = extract_direct(graph)
    environment = graph.get("python_marker_environment")
    if not isinstance(environment, dict) or not set(default_environment()).issubset(environment):
        raise ValueError("complete python_marker_environment is required")
    active, inactive = [], []
    for row in gold["dependencies"]:
        applies = not row["marker"] or Marker(row["marker"]).evaluate(environment, context="requirement")
        (active if applies else inactive).append(row)
    primary = compare_rows(active, rows)
    return {
        "schema_version": 1, "measurement": "direct declaration occurrences per ecosystem/name/source",
        "evaluation_scope": gold.get("scope", "explicit gold declarations"),
        "environment": environment,
        "environment_applicable": primary,
        "all_declared": compare_rows(gold["dependencies"], rows),
        "counts": {"gold_total": len(gold["dependencies"]), "gold_active": len(active),
                   "gold_inactive": len(inactive), "actual_direct": len(rows),
                   "transitive_nodes_excluded": transitive},
        "inactive_gold": inactive,
        "version_status_counts": {status: sum(r["version_status"] == status for r in rows)
                                  for status in ("confirmed", "estimated", "unresolved")},
        "limitations": [
            "TP matches package/source occurrences; attribute errors are reported separately.",
            "Absent marker/scope fields are unavailable, never inferred from gold.",
            "Integrated PURL merging can lose multiple declarations; no reconstruction from gold.",
            "Confirmed means declared exact, not independently observed installed version.",
            "Estimated versions are registry selections, not installed versions.",
            "Specifier comparison is packaging canonical text, not arbitrary logical equivalence.",
            "Marker comparison is canonical text, not arbitrary logical equivalence.",
            "Empty metric denominators are null.",
        ],
    }


def evaluate_declarations(gold, graph):
    """Use parser-observed declarations with the existing matching/attribute rules.

    Old saved graphs fall back to the unchanged node view; no declarations are
    inferred from gold. The optional inventory is never fed into security scans.
    """
    if "declarations" not in graph:
        result = evaluate(gold, graph)
        result["input_view"] = "legacy_nodes_fallback"
        result["observed_declaration_counts"] = {
            "total": result["counts"]["actual_direct"],
            "marker_active": result["counts"]["actual_direct"],
            "raw_preserved": 0,
            "graph_package_nodes": len(graph["dependencies"]),
            "declaration_package_nodes": None,
        }
        return result
    if not isinstance(graph["declarations"], list):
        raise ValueError("declarations must be an array")
    inventory = []
    for declaration in graph["declarations"]:
        required(declaration, ("name", "ecosystem", "declared_version", "scope",
                              "marker", "marker_active", "source_file",
                              "raw_declaration", "version_status", "resolved_version"),
                 "static declaration")
        if declaration["marker_active"] is not None and not isinstance(declaration["marker_active"], bool):
            raise ValueError("marker_active must be boolean or null")
        inventory.append(dict(declaration, depth=1, source_files=[declaration["source_file"]]))
    # Mixed projects still evaluate Java direct nodes using their original schema.
    java_rows, _ = extract_direct({"dependencies": [
        row for row in graph["dependencies"] if row["ecosystem"].lower() != "pypi"]})
    all_rows, _ = extract_direct({"dependencies": inventory})
    active = [row for row in all_rows if row["marker_active"] is True]
    result = evaluate(gold, dict(graph, dependencies=active + java_rows))
    result["all_declared"] = compare_rows(gold["dependencies"], all_rows + java_rows)
    result["input_view"] = "parser_static_declarations"
    result["observed_declaration_counts"] = {
        "total": len(all_rows), "marker_active": len(active),
        "raw_preserved": sum(bool(r["raw_declaration"]) for r in all_rows),
        "graph_package_nodes": len(graph["dependencies"]),
        "declaration_package_nodes": len(graph.get("declaration_packages", [])),
    }
    result["inventory_version_status_counts"] = {
        status: sum(row["version_status"] == status for row in all_rows)
        for status in ("confirmed", "estimated", "unresolved")}
    result["declaration_errors"] = graph.get("declaration_errors", [])
    result["limitations"].append(
        "Static groups are declarations, not installed packages. Active means marker-applicable; "
        "optional/group graph selection is separate. Node-view evaluation remains available.")
    return result


def normalize_declaration_sources(graph, source_root):
    """Normalize observed source paths only, without consulting gold."""
    source_root = Path(source_root).resolve()
    def relative(value):
        path = Path(value)
        if path.is_absolute():
            return path.resolve().relative_to(source_root).as_posix()
        return source_name(value)
    all_declarations = list(graph.get("declarations", []))
    for node in graph["dependencies"] + graph.get("declaration_packages", []):
        all_declarations.extend(node.get("declarations", []))
    for declaration in all_declarations:
        declaration["source_file"] = relative(declaration["source_file"])
    for node in graph.get("declaration_packages", []):
        node["source_files"] = [relative(value) for value in node["source_files"]]
    for error in graph.get("declaration_errors", []):
        error["source_file"] = relative(error["source_file"])


class DeclarationOnlyPyPI:
    BASE_URL = "offline://registry-disabled"

    def get_available_versions(self, name):
        return []

    def get_dependencies(self, name, version, extras=None):
        return []


def analyze_worker(snapshot, destination):
    # This runs only in a fresh subprocess. Assert origins before any parsing.
    paths = [ROOT, ROOT / "python-parser", ROOT / "python-security-integration"]
    sys.path[:0] = [str(p) for p in paths]
    import integrated_parser
    import python_parser
    import python_security_adapter
    import pypi_client
    import toml_parser
    import requirement_parser
    import dependency_node
    modules = [integrated_parser, python_parser, python_security_adapter,
               pypi_client, toml_parser, requirement_parser, dependency_node]
    expected = [ROOT / "integrated_parser.py", ROOT / "python-parser/python_parser.py",
                ROOT / "python-security-integration/python_security_adapter.py",
                ROOT / "python-parser/pypi_client.py", ROOT / "python-parser/toml_parser.py",
                ROOT / "python-parser/requirement_parser.py", ROOT / "python-parser/dependency_node.py"]
    origins = {}
    for module, path in zip(modules, expected):
        if Path(module.__file__).resolve() != path.resolve():
            raise ValueError(f"Unexpected import origin: {module.__file__}")
        origins[module.__name__] = {"path": str(path.resolve()),
                                   "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    result = integrated_parser.analyze(Path(snapshot), ROOT / "target/classes",
                                       pypi_client=DeclarationOnlyPyPI())
    # Normalize only source paths; declaration attributes remain parser observations.
    normalized, _ = extract_direct(result, source_root=snapshot)
    result["dependencies"] = normalized + [n for n in result["dependencies"] if n["depth"] > 1]
    for row in normalized:
        row["source_files"] = [row["source_file"]]
    normalize_declaration_sources(result, snapshot)
    result["evaluation_provenance"] = {
        "entrypoint": str((ROOT / "integrated_parser.py").resolve()),
        "modules": origins, "network": "disabled: injected DeclarationOnlyPyPI; Python files only",
        "resolution_policy": "ranges unresolved; exact declarations retained; no transitive metadata",
        "runtime": {"python": sys.version, "executable": sys.executable, "platform": platform.platform()},
    }
    write_new(destination, result)


def load_case(manifest, case_id):
    manifest = Path(manifest).resolve()
    data = read_json(manifest)
    matches = [c for c in data["cases"] if c["id"] == case_id]
    if len(matches) != 1:
        raise ValueError("case ID must select exactly one case")
    case = matches[0]
    if not re.fullmatch("[0-9a-f]{40}", case["commit_sha"]):
        raise ValueError("case requires a full commit SHA")
    return case, manifest.parent


def analyze_source(case, base, source_root):
    source_root = Path(source_root).resolve()
    with tempfile.TemporaryDirectory(prefix="bomerang-declaration-") as temp:
        snapshot = Path(temp) / "source"
        snapshot.mkdir()
        for relative in case["dependency_files"]:
            relative = source_name(relative)
            if Path(relative).name not in {"requirements.txt", "pyproject.toml"}:
                raise ValueError("source mode currently accepts Python manifests only")
            original = (source_root / relative).resolve()
            if not original.is_relative_to(source_root):
                raise ValueError("source path escapes source root")
            content = original.read_bytes()
            if hashlib.sha256(content).hexdigest() != case["source_sha256"][relative]:
                raise ValueError(f"Source hash mismatch: {relative}")
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        output = Path(temp) / "integrated.json"
        subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()),
                        "--worker", str(snapshot), str(output)], check=True, timeout=120)
        graph = read_json(output)
        graph["evaluation_provenance"]["source_root"] = str(source_root)
        graph["evaluation_provenance"]["source_validation"] = "SHA256 verified declared files; not a full checkout verification"
        return graph


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "accuracy-tests/repository_cases.json")
    parser.add_argument("--case", default="flask-3.1.2-declarations")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--input", type=Path, help="saved integrated JSON; no parser imports or network")
    mode.add_argument("--source", type=Path, help="local pinned checkout or vendored declared-file snapshot")
    mode.add_argument("--worker", nargs=2, help=argparse.SUPPRESS)
    parser.add_argument("--declarations", action="store_true", help="Evaluate parser static declarations, with legacy-node fallback")
    parser.add_argument("--source-root", type=Path, help="normalize absolute paths in saved JSON")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--save-integrated", type=Path)
    args = parser.parse_args()
    if args.worker:
        analyze_worker(*args.worker)
        return
    if not args.output:
        parser.error("--output is required")
    for destination in (args.output, args.save_integrated):
        if destination is not None and destination.exists():
            parser.error(f"Refusing to overwrite {destination}")
    case, base = load_case(args.manifest, args.case)
    gold = read_json(base / case["gold_file"])
    if gold.get("repository") != case["repository"] or gold.get("commit_sha") != case["commit_sha"]:
        parser.error("gold repository/commit does not match the selected case")
    graph = read_json(args.input) if args.input else analyze_source(case, base, args.source)
    if args.input and args.save_integrated:
        parser.error("--save-integrated is only supported with --source")
    if args.source_root and args.declarations:
        normalize_declaration_sources(graph, args.source_root)
    rows, _ = extract_direct(graph, source_root=args.source_root)
    measured = dict(graph, dependencies=rows + [n for n in graph["dependencies"] if n["depth"] > 1])
    result = evaluate_declarations(gold, measured) if args.declarations else evaluate(gold, measured)
    result.update({
        "case": case, "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "saved_integrated_json" if args.input else "verified_source_snapshot",
        "input_file": str(args.input.resolve()) if args.input else None,
        "input_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest() if args.input else None,
        "parser_provenance": graph.get("evaluation_provenance", {"status": "not recorded in saved JSON"}),
        "evaluation_runtime": {"python": sys.version, "platform": platform.platform()},
        "gold_sha256": hashlib.sha256((base / case["gold_file"]).read_bytes()).hexdigest(),
        "evaluator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "target_environment_recorded_in_case": case["python_environment"],
    })
    if args.save_integrated:
        write_new(args.save_integrated, graph)
    write_new(args.output, result)
    print(json.dumps({"output": str(args.output), "detection": result["environment_applicable"]["detection"],
                      "attributes": {k: {a: v for a, v in value.items() if a != "details"}
                                     for k, value in result["environment_applicable"]["attributes"].items()}}))


if __name__ == "__main__":
    main()
