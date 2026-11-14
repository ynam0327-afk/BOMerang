"""Direct-pin policy and conflict propagation regressions (offline fixtures only)."""
from collections import Counter
from dataclasses import asdict
import json
from pathlib import Path
import sys
import tempfile

import pytest
from packaging.utils import canonicalize_name
from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT), str(ROOT / "python-parser"), str(ROOT / "python-security-integration")]
from python_parser import PythonParser
from pypi_client import PyPIClient
from integrated_parser import analyze
from python_security_adapter import parse_python_file, merge_packages
from integrated_security import pipeline
from cyclonedx_converter import convert_to_cyclonedx
from dashboard_export import export
from validate_cyclonedx import validate_document


class FixturePyPI(PyPIClient):
    BASE_URL = "fixture://pypi"

    def __init__(self, specifier=">=1.21.1,<3"):
        self.specifier = specifier
        self.version_calls = Counter()
        self.metadata_calls = Counter()

    def get_available_versions(self, name):
        self.version_calls[canonicalize_name(name)] += 1
        return ["2.0.7", "2.1.0", "2.8.0", "3.0.0rc1"]

    def get_release_metadata(self, name, version):
        name = canonicalize_name(name)
        self.metadata_calls[name, version] += 1
        dependencies = []
        if name == "requests":
            dependencies = ["urllib3" + self.specifier, "PySocks==1.7.1; extra == 'socks'",
                            "inactive==1.0; python_version < '2'"]
        return {"info": {"requires_dist": dependencies}}


class FixtureSecurity:
    """Synthetic identity and affected range; never a real CVE assertion."""
    def osv(self, ecosystem, name, version):
        if name != "urllib3":
            return []
        return [{"id": "BOMERANG-SYNTHETIC-URLLIB3", "aliases": ["CVE-2099-9999"],
                 "affected": [{"package": {"ecosystem": "PyPI", "name": "urllib3"},
                               "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.0"}]}]}]}]

    def nvd(self, cve):
        return [{"cve": {"id": cve, "metrics": {"cvssMetricV31": [{"source": "fixture", "cvssData": {"version": "3.1", "baseScore": 7.5}}]}}}]


def write_inputs(directory, mode="compatible", layout="requirements"):
    directory.mkdir(parents=True, exist_ok=True)
    pins = [] if mode == "unpinned" else ["urllib3==2.1.0"]
    if mode == "multiple":
        pins.append("urllib3==2.0.7")
    requirements = directory / "requirements.txt"
    entries = ["requests==2.31.0", *pins]
    if layout == "pin-first":
        entries.reverse()
    elif layout == "referenced":
        (directory / "pins.txt").write_text("\n".join(pins), encoding="utf-8")
        entries = ["requests==2.31.0", "-r pins.txt"]
    elif layout in {"pyproject", "split"}:
        (directory / "pyproject.toml").write_text('[project]\ndependencies=' + json.dumps(entries if layout == "pyproject" else ["requests==2.31.0"]), encoding="utf-8")
        if layout == "pyproject":
            return directory / "pyproject.toml"
        entries = pins
    requirements.write_text("\n".join(entries) + "\n", encoding="utf-8")
    return requirements


def nodes_by_purl(nodes):
    return {node.purl: node for node in nodes}


@pytest.mark.parametrize("layout", ["requirements", "pin-first", "referenced", "pyproject"])
def test_parser_preserves_single_compatible_pin(tmp_path, layout):
    path = write_inputs(tmp_path, layout=layout)
    client = FixturePyPI()
    nodes = nodes_by_purl(PythonParser(client).parse(str(path)))
    assert set(nodes) == {"pkg:pypi/requests@2.31.0", "pkg:pypi/urllib3@2.1.0"}
    assert nodes["pkg:pypi/requests@2.31.0"].dependencies == ["pkg:pypi/urllib3@2.1.0"]
    assert not any(node.dependency_conflicts for node in nodes.values())
    assert not client.version_calls


@pytest.mark.parametrize("layout", ["requirements", "pin-first"])
def test_incompatible_pin_is_retained_with_unresolved_edge(tmp_path, layout):
    path = write_inputs(tmp_path, layout=layout)
    nodes = nodes_by_purl(PythonParser(FixturePyPI(">=3,<4")).parse(str(path)))
    assert "pkg:pypi/urllib3@2.1.0" in nodes
    unresolved = nodes["pkg:pypi/urllib3"]
    assert unresolved.parse_status == "error"
    assert nodes["pkg:pypi/requests@2.31.0"].dependencies == [unresolved.purl]
    conflict = unresolved.dependency_conflicts[0]
    assert conflict["reason"] == "incompatible_direct_pin"
    assert conflict["required_package"] == "urllib3"
    assert conflict["required_specifier"] == "<4,>=3"
    assert conflict["selected_version"] is None
    assert conflict["direct_versions"] == ["2.1.0"]
    assert conflict["requiring_purl"] == "pkg:pypi/requests@2.31.0"
    assert conflict["direct_sources"][0]["source_file"] == str(path.resolve())
    assert nodes["pkg:pypi/urllib3@2.1.0"].dependency_conflicts == unresolved.dependency_conflicts


@pytest.mark.parametrize("uncached", [False, True])
def test_no_pin_latest_version_is_unchanged_by_caching(tmp_path, uncached):
    class UncachedParser(PythonParser):
        def _resolve_version(self, requirement):
            self._available_versions_cache.clear()
            return super()._resolve_version(requirement)
    path = write_inputs(tmp_path, "unpinned")
    path.write_text(path.read_text() + "urllib3>=1,<3\nurllib3>=1,<3\n", encoding="utf-8")
    client = FixturePyPI()
    parser = (UncachedParser if uncached else PythonParser)(client)
    nodes = nodes_by_purl(parser.parse(str(path)))
    assert set(nodes) == {"pkg:pypi/requests@2.31.0", "pkg:pypi/urllib3@2.8.0"}
    assert nodes["pkg:pypi/requests@2.31.0"].dependencies == ["pkg:pypi/urllib3@2.8.0"]
    assert client.version_calls["urllib3"] == (3 if uncached else 1)


@pytest.mark.parametrize("specifier", [">=1,<3", "", "==2.1.0"])
def test_multiple_direct_pins_never_pick_one_for_transitive_edge(tmp_path, specifier):
    path = write_inputs(tmp_path, "multiple")
    nodes = nodes_by_purl(PythonParser(FixturePyPI(specifier)).parse(str(path)))
    assert {"pkg:pypi/urllib3@2.0.7", "pkg:pypi/urllib3@2.1.0"} <= set(nodes)
    assert nodes["pkg:pypi/requests@2.31.0"].dependencies == ["pkg:pypi/urllib3"]
    assert all(node.dependency_conflicts for node in nodes.values())
    assert any(c["reason"] == "multiple_direct_pins" and c["selected_version"] is None
               for c in nodes["pkg:pypi/urllib3"].dependency_conflicts)


def test_multiple_direct_pins_conflict_without_parent(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("urllib3==2.0.7\nurllib3==2.1.0\n", encoding="utf-8")
    rows = parse_python_file(path, FixturePyPI())
    assert len(rows) == 2
    assert all(row["graph_resolution_status"] == "dependency_conflict" for row in rows)
    assert all(row["version_status"] == "confirmed" for row in rows)


@pytest.mark.parametrize("mode,specifier", [("compatible", ">=1,<3"), ("incompatible", ">=3,<4"), ("multiple", ">=1,<3")])
def test_integrated_project_pins_apply_across_input_files(tmp_path, mode, specifier):
    write_inputs(tmp_path, mode, "split")
    graph = analyze(tmp_path, ROOT / "target/classes", FixturePyPI(specifier))
    rows = {row["purl"]: row for row in graph["dependencies"]}
    expected = "pkg:pypi/urllib3@2.1.0" if mode == "compatible" else "pkg:pypi/urllib3"
    assert rows["pkg:pypi/requests@2.31.0"]["dependencies"] == [expected]
    assert "pkg:pypi/urllib3@2.8.0" not in rows
    if mode == "compatible":
        assert rows[expected]["version_status"] == "confirmed"
        assert not graph["dependency_conflicts"]
    else:
        assert graph["dependency_conflicts"]
        assert rows["pkg:pypi/urllib3@2.1.0"]["graph_resolution_status"] == "dependency_conflict"


@pytest.mark.parametrize("mode,specifier", [("incompatible", ">=3,<4"), ("multiple", ">=1,<3")])
def test_conflicts_survive_security_sbom_and_dashboard_json(tmp_path, mode, specifier):
    write_inputs(tmp_path, mode)
    graph = analyze(tmp_path, ROOT / "target/classes", FixturePyPI(specifier))
    *_, priority = pipeline(graph["dependencies"], FixtureSecurity(), nvd=True)
    dashboard = json.loads(json.dumps(export(priority)))
    bom = convert_to_cyclonedx(graph)
    assert validate_document(bom)["schema_valid"]
    assert validate_document(bom)["local_integrity_valid"]
    for package in dashboard["packages"]:
        assert package["graph_resolution_status"] == "dependency_conflict"
        assert package["dependency_conflicts"]
    for component in bom["components"]:
        props = {p["name"]: p["value"] for p in component["properties"]}
        assert props["bomerang:graph_resolution_status"] == "dependency_conflict"
        assert json.loads(props["bomerang:dependency_conflicts"])
    assert any(f["version_match"] == "affected" for p in dashboard["packages"] for f in p["findings"])
    assert dashboard["summary"]["dependency_conflict_packages"] == len(dashboard["packages"])


def test_merge_preserves_later_conflicts_without_mutating_input():
    first = {"purl": "pkg:pypi/demo@1", "name": "demo", "depth": 1, "dependency_conflicts": []}
    conflict = {"reason": "multiple_direct_pins", "required_package": "demo", "selected_version": None}
    second = {**first, "dependency_conflicts": [conflict], "graph_resolution_status": "dependency_conflict"}
    rows = [first, second]
    saved = json.dumps(rows, sort_keys=True)
    result = merge_packages(rows)
    assert result[0]["dependency_conflicts"] == [conflict]
    assert result[0]["graph_resolution_status"] == "dependency_conflict"
    assert json.dumps(rows, sort_keys=True) == saved
    bom = convert_to_cyclonedx(rows)
    props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
    assert json.loads(props["bomerang:dependency_conflicts"]) == [conflict]
    assert props["bomerang:graph_resolution_status"] == "dependency_conflict"
    assert json.dumps(rows, sort_keys=True) == saved


def test_extras_and_inactive_markers_do_not_change_pin_policy(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text('requests[socks]==2.31.0\nurllib3==2.1.0\nurllib3==2.0.7; python_version < "2"\n', encoding="utf-8")
    rows = parse_python_file(path, FixturePyPI())
    assert {r["purl"] for r in rows} == {"pkg:pypi/requests@2.31.0", "pkg:pypi/urllib3@2.1.0", "pkg:pypi/pysocks@1.7.1"}
    assert not any(r["dependency_conflicts"] for r in rows)


def test_direct_range_also_uses_compatible_single_pin(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("urllib3>=1,<3\nurllib3==2.1.0\n", encoding="utf-8")
    rows = parse_python_file(path, FixturePyPI())
    assert [r["purl"] for r in rows] == ["pkg:pypi/urllib3@2.1.0"]
    assert rows[0]["version_status"] == "confirmed"


@pytest.mark.parametrize("reference", ["-c constraints.txt", "-cconstraints.txt", "--constraint=constraints.txt"])
def test_constraints_limit_candidates_without_installing_constraint_only_packages(tmp_path, reference):
    path = tmp_path / "requirements.txt"
    path.write_text("urllib3>=1\n" + reference + "\n", encoding="utf-8")
    (tmp_path / "constraints.txt").write_text("urllib3<2.2\nconstraint-only==1\n", encoding="utf-8")
    rows = parse_python_file(path, FixturePyPI())
    assert [r["purl"] for r in rows] == ["pkg:pypi/urllib3@2.1.0"]


@pytest.mark.parametrize("reference", ["-rpins.txt", "--requirement=pins.txt"])
def test_requirements_options_and_comments_preserve_raw_declarations(tmp_path, reference):
    path = tmp_path / "requirements.txt"
    path.write_text(reference + " # included\n", encoding="utf-8")
    raw = "urllib3==2.1.0 --hash=sha256:abc # pinned"
    (tmp_path / "pins.txt").write_text(raw + "\n", encoding="utf-8")
    parser = PythonParser(FixturePyPI())
    assert [n.purl for n in parser.parse(path)] == ["pkg:pypi/urllib3@2.1.0"]
    assert parser.declarations[0]["raw_declaration"] == raw
    assert parser.declarations[0]["requirement"] == "urllib3==2.1.0"


@pytest.mark.parametrize("pin_first", [False, True])
def test_unpinned_extras_reuse_separate_pin_before_expansion(tmp_path, pin_first):
    lines = ["requests[socks]", "requests==2.31.0"]
    if pin_first:
        lines.reverse()
    path = tmp_path / "requirements.txt"
    path.write_text("\n".join(lines), encoding="utf-8")
    nodes = nodes_by_purl(PythonParser(FixturePyPI()).parse(path))
    assert "pkg:pypi/pysocks@1.7.1" in nodes
    assert "pkg:pypi/pysocks@1.7.1" in nodes["pkg:pypi/requests@2.31.0"].dependencies


def test_bare_occurrence_cannot_hide_incompatible_transitive_requirement(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("urllib3\nrequests==2.31.0\nurllib3==2.1.0\n", encoding="utf-8")
    nodes = nodes_by_purl(PythonParser(FixturePyPI(">=3")).parse(path))
    unresolved = nodes["pkg:pypi/urllib3"]
    assert unresolved.parse_status == "error"
    assert nodes["pkg:pypi/requests@2.31.0"].dependencies == [unresolved.purl]
    assert nodes["pkg:pypi/urllib3@2.1.0"].dependency_conflicts


@pytest.mark.parametrize("version,expected", [
    ("1.2.3", "==1.2.3"), ("^0", "<1.0.0,>=0"),
    ("^0.0", "<0.1.0,>=0.0"), ("~1.2", "<1.3.0,>=1.2"),
])
def test_poetry_versions_never_change_package_identity(tmp_path, version, expected):
    from toml_parser import parse_pyproject_document
    path = tmp_path / "pyproject.toml"
    path.write_text('[tool.poetry.dependencies]\ndemo=' + json.dumps(version), encoding="utf-8")
    document = parse_pyproject_document(path)
    assert not document["errors"]
    assert document["declarations"][0]["name"] == "demo"
    assert document["declarations"][0]["declared_version"] == expected


def test_optional_poetry_group_is_inventory_only_and_does_not_pin_runtime(tmp_path):
    path = tmp_path / "pyproject.toml"
    path.write_text('[project]\ndependencies=["urllib3>=1"]\n'
                    '[tool.poetry.group.docs]\noptional=true\n'
                    '[tool.poetry.group.docs.dependencies]\nurllib3="2.0.7"\n', encoding="utf-8")
    parser = PythonParser(FixturePyPI())
    assert [n.purl for n in parser.parse(path)] == ["pkg:pypi/urllib3@2.8.0"]
    optional = parser.declarations[1]
    assert optional["optional"] and not optional["active_in_graph"]
    assert optional["resolved_version"] == "2.0.7"


def test_security_cli_defaults_to_root_parser_in_fresh_process(tmp_path):
    import subprocess
    path = tmp_path / "requirements.txt"
    path.write_text("demo\n", encoding="utf-8")
    java = tmp_path / "java.json"
    java.write_text("[]", encoding="utf-8")
    script = """
import sys
sys.path.insert(0, sys.argv.pop(1))
import integrated_security
integrated_security.main()
import python_parser
print('PARSER_ORIGIN=' + python_parser.__file__)
"""
    result = subprocess.run([sys.executable, "-B", "-c", script,
                             str(ROOT / "python-security-integration"),
                             "--python-file", str(path), "--java-json", str(java),
                             "--out-dir", str(tmp_path / "out")],
                            check=True, capture_output=True, text=True, encoding="utf-8")
    assert "PARSER_ORIGIN=" + str(ROOT / "python-parser/python_parser.py") in result.stdout
    assert json.loads((tmp_path / "out/packages.json").read_text(encoding="utf-8"))[0]["declarations"]


def test_shortest_depth_and_scopes_propagate_to_previously_expanded_children(tmp_path):
    class Chain(FixturePyPI):
        def get_dependencies(self, name, version, extras=None):
            return [Requirement(raw) for raw in {"a": ["b==1"], "b": ["c==1"]}.get(name, [])]
    path = tmp_path / "pyproject.toml"
    path.write_text('[project]\ndependencies=["a==1"]\n'
                    '[tool.poetry.group.dev.dependencies]\nb="1"\n', encoding="utf-8")
    nodes = nodes_by_purl(PythonParser(Chain()).parse(path))
    assert nodes["pkg:pypi/b@1"].depth == 1
    assert nodes["pkg:pypi/c@1"].depth == 2
    assert nodes["pkg:pypi/c@1"].scopes == ["dev", "runtime"]


def test_python_declaration_context_survives_merge_and_cyclonedx(tmp_path):
    path = tmp_path / "requirements.txt"
    raw = 'requests[socks]==2.31.0; python_version >= "3" # keep raw'
    path.write_text(raw + "\nrequests==2.31.0\n", encoding="utf-8")
    rows = parse_python_file(path, FixturePyPI())
    merged = merge_packages(rows + rows)
    request = next(row for row in merged if row["name"] == "requests")
    assert request["extras"] == ["socks"]
    assert len(request["declarations"]) == 2
    assert request["declarations"][0]["raw_declaration"] == raw
    assert request["declarations"][0]["marker_raw"] == 'python_version >= "3"'
    bom = convert_to_cyclonedx(merged)
    component = next(c for c in bom["components"] if c["name"] == "requests")
    props = {p["name"]: p["value"] for p in component["properties"]}
    assert json.loads(props["bomerang:extras"]) == ["socks"]
    assert json.loads(props["bomerang:declarations"]) == request["declarations"]
    assert json.loads(props["bomerang:requirement_contexts"]) == request["requirement_contexts"]
    assert json.loads(props["bomerang:source_files"]) == [str(path)]
    assert validate_document(bom)["schema_valid"]


@pytest.mark.parametrize("stage", ["versions", "metadata"])
@pytest.mark.parametrize("error", ["timeout", "invalid-json"])
def test_registry_transport_errors_keep_other_nodes_and_record_partial_failure(tmp_path, monkeypatch, stage, error):
    import io
    import pypi_client
    path = tmp_path / "requirements.txt"
    path.write_text(("broken>=1" if stage == "versions" else "broken==1") + "\nhealthy==1\n", encoding="utf-8")
    def transport(request, timeout=10):
        if "/broken/" in request.full_url:
            if error == "timeout":
                raise TimeoutError("fixture timeout")
            return io.BytesIO(b"invalid JSON")
        return io.BytesIO(b'{"info":{"requires_dist":[]}}')
    monkeypatch.setattr(pypi_client, "urlopen", transport)
    rows = parse_python_file(path)
    broken, healthy = rows
    assert broken["parse_status"] == "error" and broken["parser_error"]
    assert broken["graph_resolution_status"] == "partial_parse_error"
    assert healthy["parse_status"] == "success"
    assert broken["resolved_version"] == (None if stage == "versions" else "1")


def test_invalid_transitive_metadata_records_diagnostics_and_keeps_valid_edges(tmp_path, monkeypatch):
    client = PyPIClient()
    monkeypatch.setattr(client, "get_release_metadata", lambda name, version:
                        {"info": {"requires_dist": ["valid==1", "invalid requirement !!!"] if name == "parent" else []}})
    path = tmp_path / "requirements.txt"
    path.write_text("parent==1\n", encoding="utf-8")
    metadata = {}
    rows = parse_python_file(path, client, metadata=metadata)
    parent = rows[0]
    assert parent["dependencies"] == ["pkg:pypi/valid@1"]
    assert parent["parse_status"] == "error"
    assert parent["metadata_errors"][0]["raw_declaration"] == "invalid requirement !!!"
    assert metadata["declaration_errors"][0]["category"] == "invalid_dependency_metadata"
    props = {p["name"]: p["value"] for p in convert_to_cyclonedx(rows)["components"][0]["properties"]}
    assert json.loads(props["bomerang:metadata_errors"]) == parent["metadata_errors"]


@pytest.mark.parametrize("specifier,expected", [(">=1rc1,<2", "1rc1"), (">=0,<2", None)])
def test_explicit_prerelease_range_is_honored(tmp_path, specifier, expected):
    class Prerelease(FixturePyPI):
        def get_available_versions(self, name):
            return ["1rc1"]
    path = tmp_path / "requirements.txt"
    path.write_text("demo" + specifier, encoding="utf-8")
    assert PythonParser(Prerelease()).parse(path)[0].resolved_version == expected


def test_nested_constraints_and_continuations_are_collected_before_resolution(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("urllib3>=1 \\\n --hash=sha256:abc # hash\n-c constraints.txt\n", encoding="utf-8")
    (tmp_path / "constraints.txt").write_text('-r nested.txt\n', encoding="utf-8")
    (tmp_path / "nested.txt").write_text('urllib3<2.2\nunused==1\n-c constraints.txt\n', encoding="utf-8")
    nodes = PythonParser(FixturePyPI()).parse(path)
    assert [n.purl for n in nodes] == ["pkg:pypi/urllib3@2.1.0"]


def test_exact_pin_incompatible_with_constraint_remains_unresolved(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("urllib3==2.1.0\n-c constraints.txt\n", encoding="utf-8")
    (tmp_path / "constraints.txt").write_text("urllib3<2\n", encoding="utf-8")
    nodes = PythonParser(FixturePyPI()).parse(path)
    assert nodes[0].resolved_version is None and nodes[0].parse_status == "error"
    assert nodes[0].dependency_conflicts[0]["reason"] == "incompatible_constraint"


def test_compatibility_integrated_cli_uses_canonical_inventory(tmp_path):
    import subprocess
    (tmp_path / "pyproject.toml").write_text('[dependency-groups]\ndev=["demo"]\n', encoding="utf-8")
    result = subprocess.run([sys.executable, "-B", str(ROOT / "python-security-integration/integrated_parser.py"), str(tmp_path)],
                            check=True, capture_output=True, text=True, encoding="utf-8")
    graph = json.loads(result.stdout)
    assert graph["dependencies"] == []
    assert graph["declarations"][0]["name"] == "demo"


def test_required_requirements_occurrence_prevents_optional_scope_after_merge(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("demo==1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text('[tool.poetry.group.dev.dependencies]\ndemo="1"\n', encoding="utf-8")
    graph = analyze(tmp_path, ROOT / "target/classes", FixturePyPI())
    assert graph["dependencies"][0]["scopes"] == ["dev", "runtime"]
    assert convert_to_cyclonedx(graph)["components"][0]["scope"] == "required"


def snapshot_cases(output):
    output.mkdir(parents=True, exist_ok=False)
    for mode, specifier, layout in [("compatible", ">=1,<3", "requirements"), ("incompatible", ">=3,<4", "requirements"),
                                    ("unpinned", ">=1,<3", "requirements"), ("multiple", ">=1,<3", "requirements"),
                                    ("split", ">=1,<3", "split")]:
        with tempfile.TemporaryDirectory(prefix="bomerang-conflict-case-") as temporary:
            directory = Path(temporary)
            path = write_inputs(directory, mode, layout)
            raw = [asdict(n) for n in PythonParser(FixturePyPI(specifier)).parse(str(path))]
            graph = analyze(directory, ROOT / "target/classes", FixturePyPI(specifier))
            *_, priority = pipeline(graph["dependencies"], FixtureSecurity(), nvd=True)
            dashboard = export(priority)
            from security_sbom_adapter import to_cyclonedx_risk
            bom = convert_to_cyclonedx(graph, risk_result=to_cyclonedx_risk(priority))
            findings = [{"purl": p["purl"], "id": f["id"], "version_match": f["version_match"], "priority_score": f["priority_score"]}
                        for p in dashboard["packages"] for f in p["findings"]]
            summary = {"purls": sorted(r["purl"] for r in graph["dependencies"]),
                       "edges": {r["purl"]: r["dependencies"] for r in graph["dependencies"]}, "findings": findings}
            with (output / (mode + ".json")).open("x", encoding="utf-8") as stream:
                json.dump({"fixture_kind": "synthetic_not_real_vulnerability_data",
                           "integrated_parser_module": sys.modules["integrated_parser"].__file__,
                           "python_parser_module": sys.modules["python_parser"].__file__,
                           "parser": raw, "graph": graph,
                           "sbom": bom, "dashboard": dashboard, "summary": summary}, stream, indent=2)
            print(mode, json.dumps(summary), flush=True)


if __name__ == "__main__":
    import argparse
    args = argparse.ArgumentParser()
    args.add_argument("--output", required=True, type=Path)
    snapshot_cases(args.parse_args().output)
