"""Offline mixed Python/Maven/Gradle integration verification.

Uses existing classes, plus one temporary source compilation parity check.
External package registries and security APIs are never called.
"""
from contextlib import contextmanager
from copy import deepcopy
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import subprocess
import threading
import tomllib
from unittest.mock import patch

import pytest
from packaging.requirements import Requirement

from integrated_parser import analyze
from python_security_adapter import merge_packages
from cyclonedx_converter import convert_to_cyclonedx

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "integration-fixtures/step4"
CLASSES = ROOT / "target/classes"


class FixturePyPI:
    def __init__(self):
        self.calls = []

    def get_available_versions(self, name):
        self.calls.append(("versions", name))
        return ["1.0", "1.5", "2.0"]

    def get_dependencies(self, name, version, extras=None):
        self.calls.append(("dependencies", name))
        edges = {"py-parent": ["py-child==1.0"], "py-child": ["py-leaf==1.0"]}
        return [Requirement(value) for value in edges.get(name, [])]


def checked_analyze(project, classes=CLASSES, client=None, **options):
    try:
        return analyze(project, classes, client or FixturePyPI(), **options)
    except subprocess.CalledProcessError as exc:
        raise AssertionError(f"Java exporter exit {exc.returncode}: {exc.stderr}") from exc


@pytest.fixture(scope="module")
def project(tmp_path_factory):
    folder = tmp_path_factory.mktemp("mixed-step4") / "project"
    shutil.copytree(FIXTURES / "mixed", folder)
    return folder


@pytest.fixture(scope="module")
def java_available():
    if not shutil.which("java") or not (CLASSES / "com/bomerang/JsonDependencyExporter.class").is_file():
        pytest.skip("Existing Java exporter classes/runtime unavailable; target/classes is never rebuilt")


@pytest.fixture(scope="module")
def mixed(project, java_available):
    return checked_analyze(project)


@pytest.fixture(autouse=True)
def forbid_real_pypi(monkeypatch):
    import pypi_client
    def forbidden(*args, **kwargs):
        raise AssertionError("External PyPI is forbidden in offline integration tests")
    monkeypatch.setattr(pypi_client, "urlopen", forbidden)


def node(graph, purl):
    return next(row for row in graph["dependencies"] if row["purl"] == purl)


@contextmanager
def local_repository(directory):
    class Handler(SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass
    handler = partial(Handler, directory=str(directory))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with patch.dict("os.environ", {"BOMERANG_MAVEN_REPO_URL": f"http://127.0.0.1:{server.server_port}"}):
            yield
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture(scope="module")
def resolved(project, java_available):
    with local_repository(FIXTURES / "repository"):
        return checked_analyze(project, resolve_maven=True)


def test_all_manifest_types_discovered(mixed):
    assert {value.replace("\\", "/") for value in mixed["files"]} == {
        "requirements.txt", "pyproject.toml", "pom.xml", "build.gradle", "kotlin/build.gradle.kts"}


def test_both_ecosystems_and_gradle_origins(mixed):
    assert {r["ecosystem"] for r in mixed["dependencies"]} == {"pypi", "maven"}
    assert node(mixed, "pkg:maven/org.example/gradle-api@1.0")["ecosystem"] == "maven"
    assert node(mixed, "pkg:maven/org.example/gradle-kotlin@1.0")["ecosystem"] == "maven"


def test_purl_uniqueness_and_formats(mixed):
    purls = [r["purl"] for r in mixed["dependencies"]]
    assert len(purls) == len(set(purls)) == 20
    assert all(p.startswith(("pkg:pypi/", "pkg:maven/")) for p in purls)


def test_same_name_different_ecosystems_and_maven_groups_do_not_merge(mixed):
    wanted = {"pkg:pypi/shared@1.0", "pkg:maven/org.example/shared@1.0", "pkg:maven/org.other/shared@1.0"}
    assert wanted <= {r["purl"] for r in mixed["dependencies"]}


def test_duplicate_java_package_retains_both_sources(mixed):
    row = node(mixed, "pkg:maven/org.example/shared-java@1.0")
    assert {Path(p).name for p in row["source_files"]} == {"pom.xml", "build.gradle"}
    assert set(row["scopes"]) == {"compile", "test"}


def test_duplicate_java_scalar_scope_uses_exporter_precedence(mixed):
    assert node(mixed, "pkg:maven/org.example/shared-java@1.0")["scope"] == "compile"


def test_duplicate_java_optional_values_preserved(mixed):
    row = node(mixed, "pkg:maven/org.example/shared-java@1.0")
    assert set(row["optional_values"]) == {False, True}
    assert row["optional"] is False


def test_maven_optional_scope_and_managed_version(mixed):
    row = node(mixed, "pkg:maven/org.example/optional-only@1.0")
    assert row["optional"] is True and row["scope"] == "runtime"
    managed = node(mixed, "pkg:maven/org.example/managed-lib@2.0")
    assert managed["resolved_version"] == "2.0" and managed["scope"] == "compile"
    assert not any(r["name"] == "managed-only" for r in mixed["dependencies"])


@pytest.mark.parametrize("artifact,scope", [
    ("gradle-api", "compile"), ("gradle-provided", "provided"),
    ("gradle-runtime", "runtime"), ("gradle-test-runtime", "test"),
    ("gradle-kotlin", "compile"), ("test-java", "test"), ("provided-java", "provided"),
])
def test_java_scope_mappings(mixed, artifact, scope):
    assert node(mixed, f"pkg:maven/org.example/{artifact}@1.0")["scope"] == scope


def test_python_direct_and_transitive_depths_and_edges(mixed):
    parent = node(mixed, "pkg:pypi/py-parent@1.0")
    child = node(mixed, "pkg:pypi/py-child@1.0")
    leaf = node(mixed, "pkg:pypi/py-leaf@1.0")
    assert [parent["depth"], child["depth"], leaf["depth"]] == [1, 2, 3]
    assert parent["dependencies"] == [child["purl"]]
    assert child["dependencies"] == [leaf["purl"]]
    assert child["declarations"] == leaf["declarations"] == []


def test_java_static_mode_does_not_invent_transitives(mixed):
    assert not any(r["name"] == "java-child" for r in mixed["dependencies"])
    assert all(r["depth"] == 1 for r in mixed["dependencies"] if r["ecosystem"] == "maven")


def test_local_maven_resolves_transitives_and_preserves_runtime_scope(resolved):
    parent = node(resolved, "pkg:maven/org.example/java-parent@1.0")
    child = node(resolved, "pkg:maven/org.example/java-child@1.0")
    leaf = node(resolved, "pkg:maven/org.example/java-leaf@1.0")
    assert [parent["depth"], child["depth"], leaf["depth"]] == [1, 2, 3]
    assert {parent["scope"], child["scope"], leaf["scope"]} == {"runtime"}
    assert parent["dependencies"] == [child["purl"]]
    assert child["dependencies"] == [leaf["purl"]]


def test_library_optional_and_test_dependencies_do_not_propagate(resolved):
    assert not {"library-test", "library-optional"} & {r["name"] for r in resolved["dependencies"]}


@pytest.mark.parametrize("view", ["mixed", "resolved"])
def test_all_dependency_edges_resolve_to_existing_nodes(view, request):
    graph = request.getfixturevalue(view)
    purls = {r["purl"] for r in graph["dependencies"]}
    assert all(set(r["dependencies"]) <= purls for r in graph["dependencies"])


def test_static_inventory_is_separate_from_graph(mixed):
    assert len(mixed["declarations"]) == 15
    assert len([r for r in mixed["declarations"] if r["marker_active"]]) == 13
    assert not {"web-only", "doc-only", "pytest", "group-base", "legacy", "py-inactive"} & {
        r["name"] for r in mixed["dependencies"]}
    assert {"web-only", "doc-only", "pytest", "group-base", "legacy", "py-inactive"} <= {
        r["name"] for r in mixed["declaration_packages"]}


def test_python_same_purl_keeps_four_source_declarations(mixed):
    row = node(mixed, "pkg:pypi/shared@1.0")
    assert len(row["declarations"]) == 4
    assert {r["scope"] for r in row["declarations"]} == {None, "runtime", "optional:web", "dev"}
    assert len({r["declaration_id"] for r in row["declarations"]}) == 4


def test_marker_raw_and_inactive_declarations_preserved(mixed):
    rows = {r["name"]: r for r in mixed["declarations"]}
    assert rows["py-inactive"]["raw_declaration"] == "py-inactive==1.0; python_version < '2'"
    assert rows["py-inactive"]["marker_raw"] == "python_version < '2'"
    assert rows["py-inactive"]["marker_active"] is False
    assert rows["py-active"]["marker_active"] is True


def test_include_group_and_extras_metadata_preserved(mixed):
    rows = mixed["declarations"]
    included = next(r for r in rows if r["name"] == "group-base" and r["scope"] == "dev")
    assert included["origin_group"] == "base" and included["include_path"]
    extra = next(r for r in rows if r["name"] == "web-only")
    assert extra["extras"] == ["socks"] and extra["optional"]
    assert not extra["active_in_graph"]


def test_python_sources_are_real_declaration_files(mixed):
    included = next(r for r in mixed["declarations"] if r["name"] == "included")
    assert Path(included["source_file"]).name == "base.txt"
    assert included["source_locator"] == "line:1"


def test_version_statuses_do_not_claim_installed_versions(mixed):
    assert node(mixed, "pkg:pypi/py-runtime@1.5")["version_status"] == "estimated"
    assert node(mixed, "pkg:pypi/shared@1.0")["version_status"] == "confirmed"
    static = next(r for r in mixed["declarations"] if r["name"] == "web-only")
    assert static["version_status"] == "unresolved"
    assert static["usage_status"] == "declared_not_installation_verified"


def test_exporter_json_and_static_metadata_roundtrip(mixed):
    assert json.loads(json.dumps(mixed)) == mixed
    assert all("scope" in r and "version_status" in r for r in mixed["dependencies"])


def test_cyclonedx_uses_merged_java_scope(mixed):
    bom = convert_to_cyclonedx(mixed)
    component = next(c for c in bom["components"] if c["bom-ref"] == "pkg:maven/org.example/shared-java@1.0")
    assert component["scope"] == "required"


def test_cyclonedx_keeps_graph_components_and_edges_only(resolved):
    bom = convert_to_cyclonedx(resolved)
    refs = {c["bom-ref"] for c in bom["components"]}
    assert refs == {r["purl"] for r in resolved["dependencies"]}
    assert "pkg:pypi/web-only" not in refs
    edges = {row["ref"]: row["dependsOn"] for row in bom["dependencies"]}
    assert edges["pkg:maven/org.example/java-parent@1.0"] == ["pkg:maven/org.example/java-child@1.0"]


def test_security_pipeline_receives_graph_not_static_inventory(mixed):
    from integrated_security import pipeline
    class Security:
        def __init__(self):
            self.calls = []
        def osv(self, ecosystem, name, version):
            self.calls.append((ecosystem, name, version))
            return []
    client = Security()
    scanned, normalized, matched, priority = pipeline(mixed["dependencies"], client)
    assert len(scanned["results"]) == len(mixed["dependencies"])
    assert {call[0] for call in client.calls} == {"PyPI", "Maven"}
    assert not {"web-only", "doc-only"} & {call[1] for call in client.calls}


def test_recoverable_python_registry_error_keeps_other_ecosystems(project, java_available):
    class Broken(FixturePyPI):
        def get_available_versions(self, name):
            if name == "py-runtime":
                raise RuntimeError("offline fixture lookup failure")
            return super().get_available_versions(name)
    graph = checked_analyze(project, client=Broken())
    broken = next(r for r in graph["dependencies"] if r["name"] == "py-runtime")
    assert broken["parse_status"] == "error"
    assert "offline fixture lookup failure" in broken["parser_error"]
    assert {r["ecosystem"] for r in graph["dependencies"]} == {"pypi", "maven"}


def test_invalid_python_group_is_nonfatal_diagnostic(project, tmp_path, java_available):
    folder = tmp_path / "invalid-group"
    shutil.copytree(project, folder)
    path = folder / "pyproject.toml"
    with path.open("a", encoding="utf-8") as f:
        f.write('\nbroken = [{path="local"}]\n')
    graph = checked_analyze(folder)
    assert any(e["category"] == "unsupported_group_entry" for e in graph["declaration_errors"])
    assert node(graph, "pkg:maven/org.example/shared@1.0")


def test_malformed_toml_aborts_analysis_without_partial_return(project, tmp_path, java_available):
    folder = tmp_path / "bad-toml"
    shutil.copytree(project, folder)
    (folder / "pyproject.toml").write_text("[project\n", encoding="utf-8")
    with pytest.raises(tomllib.TOMLDecodeError):
        analyze(folder, CLASSES, FixturePyPI())


def test_malformed_pom_aborts_analysis(project, tmp_path, java_available):
    folder = tmp_path / "bad-pom"
    shutil.copytree(project, folder)
    (folder / "pom.xml").write_text("<project>", encoding="utf-8")
    with pytest.raises(subprocess.CalledProcessError) as error:
        analyze(folder, CLASSES, FixturePyPI())
    assert error.value.returncode != 0 and error.value.stderr


def test_local_maven_download_failure_is_not_reported_as_complete(project, tmp_path, java_available):
    repository = tmp_path / "repository"
    shutil.copytree(FIXTURES / "repository", repository)
    (repository / "org/example/java-child/1.0/java-child-1.0.pom").unlink()
    with local_repository(repository), pytest.raises(RuntimeError, match="incomplete"):
        analyze(project, CLASSES, FixturePyPI(), resolve_maven=True)


def test_gradle_catalog_and_project_dependencies_are_outside_current_support(tmp_path, java_available):
    (tmp_path / "build.gradle.kts").write_text('dependencies {\n implementation(libs.example)\n implementation(project(":sub"))\n}\n', encoding="utf-8")
    assert checked_analyze(tmp_path)["dependencies"] == []


def test_merge_optional_and_declared_versions_is_order_independent():
    a = {"purl": "pkg:maven/org.example/demo@1", "name": "demo", "ecosystem": "maven",
         "scope": "test", "scopes": ["test"], "optional": True, "optional_values": [True],
         "declared_versions": ["[1,2)"], "declared_version": "[1,2)", "depth": 3, "dependencies": ["child-a"]}
    b = dict(a, scope="compile", scopes=["compile"], optional=False, optional_values=[False],
             declared_versions=["1"], declared_version="1", depth=1, dependencies=["child-b"])
    original = deepcopy([a, b])
    for items in ([a, b], [b, a]):
        row = merge_packages(items)[0]
        assert row["scope"] == "compile"
        assert row["optional"] is False
        assert row["optional_values"] == [False, True]
        assert set(row["declared_versions"]) == {"1", "[1,2)"}
        assert row["depth"] == 1
        assert set(row["dependencies"]) == {"child-a", "child-b"}
    assert [a, b] == original


def test_fresh_java_source_matches_existing_exporter(project, mixed, tmp_path, java_available):
    if not shutil.which("javac"):
        pytest.skip("javac unavailable for temporary source parity check")
    classes = tmp_path / "classes"
    compilation = subprocess.run([
        "javac", "--release", "17", "-encoding", "UTF-8", "-sourcepath",
        str(ROOT / "src/main/java"), "-d", str(classes),
        str(ROOT / "src/main/java/com/bomerang/JsonDependencyExporter.java"),
    ], capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert compilation.returncode == 0, compilation.stderr
    fresh = checked_analyze(project, classes)
    fields = ("ecosystem", "purl", "scope", "scopes", "optional", "optional_values",
              "depth", "dependencies", "resolved_version")
    def signature(graph):
        return {r["purl"]: {k: r.get(k) for k in fields} for r in graph["dependencies"]}
    assert signature(fresh) == signature(mixed)
