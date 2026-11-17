"""Offline HTTPX regressions: declaration analysis is not installation evidence.

Requires-Dist declarations are frozen from the HTTPX 0.28.1 / AnyIO 4.16.0
installed-sbom-20261116-180431 investigation. No benchmark input or Gold is read
or changed. Python 3.14/3.15 below are marker contexts, not installed runtimes.
The idna 2.7 leaf is only a conflicting direct-pin test input.
"""
from collections import Counter
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import sys

import packaging.markers as markers
from packaging.utils import canonicalize_name
import pytest

ROOT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT), str(ROOT / "python-parser"),
                str(ROOT / "python-security-integration")]
import pypi_client
from pypi_client import PyPIClient
from python_parser import PythonParser
from integrated_parser import analyze
from cyclonedx_converter import convert_to_cyclonedx


@pytest.fixture
def release_metadata():
    """Frozen registry declarations; leaf metadata is intentionally minimal."""
    declarations = {
        ("httpx", "0.28.1"): [
            "anyio", "certifi", "httpcore==1.*", "idna",
            'brotli; platform_python_implementation == "CPython" and extra == "brotli"',
            'brotlicffi; platform_python_implementation != "CPython" and extra == "brotli"',
            'click==8.*; extra == "cli"', 'pygments==2.*; extra == "cli"',
            'rich<14,>=10; extra == "cli"', 'h2<5,>=3; extra == "http2"',
            'socksio==1.*; extra == "socks"', 'zstandard>=0.18.0; extra == "zstd"',
        ],
        ("anyio", "4.16.0"): [
            'exceptiongroup>=1.0.2; python_version < "3.11"',
            "idna>=2.8",
            'typing_extensions>=4.16.0; python_version < "3.15"',
            'trio>=0.32.0; extra == "trio"',
        ],
        ("httpcore", "1.0.9"): [
            "certifi", "h11>=0.16",
            'anyio<5.0,>=4.0; extra == "asyncio"',
            'h2<5,>=3; extra == "http2"', 'socksio==1.*; extra == "socks"',
            'trio<1.0,>=0.22.0; extra == "trio"',
        ],
        ("h11", "0.16.0"): [],
        ("certifi", "2026.10.23"): [],
        ("idna", "3.20"): [],
        ("idna", "2.7"): [],
        ("typing-extensions", "4.16.0"): [],
    }
    return {key: {"info": {"name": key[0], "version": key[1],
                           "requires_dist": value,
                           "requires_python": ">=3.10" if key[0] == "anyio" else None}}
            for key, value in declarations.items()}


class FrozenPyPI(PyPIClient):
    """Use real extraction/marker code, replacing only registry I/O."""
    BASE_URL = "fixture://httpx-regression"

    def __init__(self, metadata):
        self.metadata = metadata
        self.metadata_calls = Counter()
        self.version_calls = Counter()

    def get_release_metadata(self, name, version):
        key = (canonicalize_name(name), version)
        self.metadata_calls[key] += 1
        assert key in self.metadata, f"Unexpected metadata lookup: {key}"
        return deepcopy(self.metadata[key])

    def get_available_versions(self, name):
        name = canonicalize_name(name)
        self.version_calls[name] += 1
        versions = [version for package, version in self.metadata if package == name]
        assert versions, f"Unexpected version lookup: {name}"
        return versions


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def unexpected_request(*args, **kwargs):
        pytest.fail("HTTPX regressions must never access the network")
    monkeypatch.setattr(pypi_client, "urlopen", unexpected_request)


@pytest.fixture
def client(release_metadata):
    return FrozenPyPI(release_metadata)


@pytest.fixture
def marker_environment(monkeypatch):
    actual = markers.default_environment()

    def select(version):
        environment = dict(actual, python_version=version,
                           python_full_version=version + ".0",
                           implementation_version=version + ".0")
        monkeypatch.setattr(markers, "default_environment", lambda: dict(environment))
        monkeypatch.setattr(pypi_client, "default_environment", lambda: dict(environment))
        return environment

    select("3.14")
    return select


def write_input(tmp_path, evidence=None, *, conflict=False):
    text = "httpx==0.28.1\n"
    if evidence == "constraint":
        (tmp_path / "constraints.txt").write_text("anyio==4.16.0\n", encoding="utf-8")
        text += "-c constraints.txt\n"
    elif evidence == "direct-pin":
        text += "anyio==4.16.0\n"
    if conflict:
        text += "idna==2.7\n"
    path = tmp_path / "requirements.txt"
    path.write_bytes(text.encode("utf-8"))
    return path


BASE_EDGES = {
    ("pkg:pypi/httpx@0.28.1", "pkg:pypi/anyio"),
    ("pkg:pypi/httpx@0.28.1", "pkg:pypi/certifi"),
    ("pkg:pypi/httpx@0.28.1", "pkg:pypi/httpcore@1.0.9"),
    ("pkg:pypi/httpx@0.28.1", "pkg:pypi/idna"),
    ("pkg:pypi/httpcore@1.0.9", "pkg:pypi/certifi"),
    ("pkg:pypi/httpcore@1.0.9", "pkg:pypi/h11@0.16.0"),
}
ANYIO_EDGES = {
    ("pkg:pypi/anyio@4.16.0", "pkg:pypi/idna@3.20"),
    ("pkg:pypi/anyio@4.16.0", "pkg:pypi/typing-extensions@4.16.0"),
}


def expected_edges(evidence):
    if not evidence:
        return BASE_EDGES
    replacements = {"pkg:pypi/anyio": "pkg:pypi/anyio@4.16.0",
                    "pkg:pypi/idna": "pkg:pypi/idna@3.20"}
    return {(parent, replacements.get(child, child)) for parent, child in BASE_EDGES} | ANYIO_EDGES


def graph_edges(rows):
    return {(row["purl"], child) for row in rows for child in row["dependencies"]}


def test_httpx_root_pin_stops_at_unresolved_anyio(tmp_path, client, marker_environment):
    path = write_input(tmp_path)
    assert path.read_bytes() == b"httpx==0.28.1\n"
    nodes = PythonParser(client).parse(str(path))
    rows = {node.purl: node for node in nodes}
    anyio = rows["pkg:pypi/anyio"]
    assert anyio.resolved_version is None
    assert anyio.declared_version is None
    assert anyio.parse_status == "success"
    assert anyio.dependencies == []
    assert len(rows) == 6
    assert graph_edges([asdict(node) for node in nodes]) == BASE_EDGES
    assert not any(purl.startswith("pkg:pypi/typing-extensions") for purl in rows)
    assert client.version_calls == Counter({"httpcore": 1, "h11": 1})
    assert client.metadata_calls == Counter({("httpx", "0.28.1"): 1,
                                            ("httpcore", "1.0.9"): 1,
                                            ("h11", "0.16.0"): 1})


@pytest.mark.parametrize("evidence", ["constraint", "direct-pin"])
def test_anyio_version_evidence_enables_transitive_graph(
        tmp_path, client, marker_environment, evidence):
    path = write_input(tmp_path, evidence)
    nodes = PythonParser(client).parse(str(path))
    rows = {node.purl: node for node in nodes}
    assert rows["pkg:pypi/anyio@4.16.0"].resolved_version == "4.16.0"
    assert graph_edges([asdict(node) for node in nodes]) == expected_edges(evidence)
    assert client.metadata_calls["anyio", "4.16.0"] == 1
    assert client.version_calls["anyio"] == 0
    assert not any(node.dependency_conflicts for node in nodes)


@pytest.mark.parametrize("version,expected", [
    ("3.14", {"idna", "typing-extensions"}),
    ("3.15", {"idna"}),
])
def test_anyio_python_marker_and_unselected_extra(
        client, marker_environment, version, expected):
    marker_environment(version)
    dependencies = client.get_dependencies("anyio", "4.16.0", extras=set())
    assert {canonicalize_name(req.name) for req in dependencies} == expected
    assert all(req.name not in {"trio", "exceptiongroup"} for req in dependencies)
    assert not client.version_calls
    # Metadata extraction says which requirements apply, never what is installed.
    assert client.metadata_calls == Counter({("anyio", "4.16.0"): 1})


def test_anyio_selected_trio_extra_is_distinct_from_base_dependencies(
        client, marker_environment):
    dependencies = client.get_dependencies("anyio", "4.16.0", extras={"trio"})
    assert {canonicalize_name(req.name) for req in dependencies} == {
        "idna", "typing-extensions", "trio"}


def test_python315_graph_excludes_typing_extensions(tmp_path, client, marker_environment):
    marker_environment("3.15")
    path = write_input(tmp_path, "constraint")
    nodes = PythonParser(client).parse(str(path))
    assert graph_edges([asdict(node) for node in nodes]) == (
        expected_edges("constraint") - {
            ("pkg:pypi/anyio@4.16.0", "pkg:pypi/typing-extensions@4.16.0")})
    assert not any(canonicalize_name(node.name) in {"typing-extensions", "trio"}
                   for node in nodes)
    assert client.version_calls["typing-extensions"] == 0
    assert client.metadata_calls["typing-extensions", "4.16.0"] == 0


def test_anyio_idna_conflict_preserves_direct_pin_and_unresolved_edge(
        tmp_path, client, marker_environment):
    path = write_input(tmp_path, "direct-pin", conflict=True)
    graph = analyze(tmp_path, ROOT / "target/classes", pypi_client=client)
    rows = {row["purl"]: row for row in graph["dependencies"]}
    pinned = rows["pkg:pypi/idna@2.7"]
    unresolved = rows["pkg:pypi/idna"]
    assert pinned["resolved_version"] == "2.7"
    assert pinned["version_status"] == "confirmed"
    assert unresolved["resolved_version"] is None
    assert unresolved["version_status"] == "unresolved"
    assert unresolved["resolution_reason"] == "dependency_conflict"
    assert unresolved["parse_status"] == "error"
    assert "pkg:pypi/idna" in rows["pkg:pypi/anyio@4.16.0"]["dependencies"]
    assert "pkg:pypi/idna@2.7" not in rows["pkg:pypi/anyio@4.16.0"]["dependencies"]
    assert "pkg:pypi/idna@3.20" not in rows
    conflict, = graph["dependency_conflicts"]
    assert conflict["reason"] == "incompatible_direct_pin"
    assert conflict["required_package"] == "idna"
    assert conflict["required_specifier"] == ">=2.8"
    assert conflict["requiring_purl"] == "pkg:pypi/anyio@4.16.0"
    assert conflict["direct_versions"] == ["2.7"]
    assert conflict["selected_version"] is None
    assert conflict["direct_sources"] == [{"version": "2.7", "source_file": str(path.resolve())}]
    assert conflict in pinned["dependency_conflicts"]
    assert conflict in unresolved["dependency_conflicts"]
    assert client.version_calls["idna"] == 0
    assert client.metadata_calls["idna", "3.20"] == 0


@pytest.mark.parametrize("evidence", [None, "constraint", "direct-pin"],
                         ids=["unresolved", "constraint", "direct-pin"])
def test_httpx_edges_and_unresolved_state_survive_json_and_cyclonedx(
        tmp_path, client, marker_environment, evidence):
    path = write_input(tmp_path, evidence)
    internal = PythonParser(client).parse(str(path))
    graph = json.loads(json.dumps(analyze(tmp_path, ROOT / "target/classes", pypi_client=client)))
    bom = json.loads(json.dumps(convert_to_cyclonedx(graph)))
    assert graph_edges([asdict(node) for node in internal]) == expected_edges(evidence)
    assert graph_edges(graph["dependencies"]) == expected_edges(evidence)
    assert {(row["ref"], child) for row in bom["dependencies"]
            for child in row["dependsOn"]} == expected_edges(evidence)
    assert graph["python_marker_environment"]["python_version"] == "3.14"
    assert not graph["dependency_conflicts"]
    assert not graph["declaration_errors"]
    rows = {row["purl"]: row for row in graph["dependencies"]}
    components = {row["bom-ref"]: row for row in bom["components"]}
    assert set(components) == set(rows)
    # certifi still has no version evidence even when AnyIO is constrained.
    unresolved_refs = {"pkg:pypi/certifi"} if evidence else {
        "pkg:pypi/anyio", "pkg:pypi/certifi", "pkg:pypi/idna"}
    assert {ref for ref, row in rows.items() if row["resolved_version"] is None} == unresolved_refs
    for ref in unresolved_refs:
        row = rows[ref]
        assert row["version_status"] == "unresolved"
        assert row["resolution_reason"] == "missing_version_specifier"
        assert row["resolution_reasons"] == ["missing_version_specifier"]
        assert row["parse_status"] == "success"
        assert row["version_evidence"] is None
        assert row["dependencies"] == []
        assert "version" not in components[ref]
        properties = {prop["name"]: prop["value"] for prop in components[ref]["properties"]}
        assert properties["bomerang:version_status"] == "unresolved"
        assert properties["bomerang:parse_status"] == "success"
    # Existing CycloneDX properties, not a new resolution_reason schema field.
    assert client.version_calls["anyio"] == 0
