"""Static declarations and compatibility tests; all clients are offline."""
from pathlib import Path

import pytest

from toml_parser import parse_pyproject, parse_pyproject_document


def document(tmp_path, text):
    path = tmp_path / "pyproject.toml"
    path.write_text(text, encoding="utf-8")
    return path, parse_pyproject_document(path)


def test_runtime_static_declaration(tmp_path):
    path, result = document(tmp_path, '[project]\ndependencies=["demo>=1,<3"]\n')
    row = result["declarations"][0]
    assert row["scope"] == "runtime" and row["active_in_graph"]
    assert row["declared_version"] == "<3,>=1"
    assert row["source_file"] == str(path.resolve())


def test_optional_single_group(tmp_path):
    _, result = document(tmp_path, '[project.optional-dependencies]\nweb=["Foo_Bar[SOCKS]>=1"]\n')
    row = result["declarations"][0]
    assert row["name"] == "foo-bar" and row["extras"] == ["socks"]
    assert row["dependency_group"] == "web" and row["optional"]
    assert row["scope"] == "optional:web" and not row["active_in_graph"]


def test_optional_multiple_groups_preserve_occurrences(tmp_path):
    _, result = document(tmp_path, '[project.optional-dependencies]\na=["demo"]\nb=["demo"]\n')
    rows = result["declarations"]
    assert len(rows) == 2
    assert {r["scope"] for r in rows} == {"optional:a", "optional:b"}
    assert len({r["declaration_id"] for r in rows}) == 2


def test_pep735_group(tmp_path):
    _, result = document(tmp_path, '[dependency-groups]\ndev=["pytest>=8"]\n')
    row = result["declarations"][0]
    assert row["scope"] == row["dependency_group"] == "dev"
    assert not row["optional"] and not row["graph_enabled"]


def test_include_group_preserves_origin_and_destination(tmp_path):
    _, result = document(tmp_path, '[dependency-groups]\nbase=["demo"]\nall=[{include-group="base"}, "other"]\n')
    included = [r for r in result["declarations"] if r["scope"] == "all" and r["name"] == "demo"][0]
    assert included["origin_group"] == "base"
    assert included["include_path"] == ["dependency-groups.all[0]"]
    assert not result["errors"]


def test_include_group_normalizes_reference_names(tmp_path):
    _, result = document(tmp_path, '[dependency-groups]\nfoo_bar=["demo"]\ndev=[{include-group="FOO.BAR"}]\n')
    assert len(result["declarations"]) == 2
    assert not result["errors"]


def test_include_group_cycle_is_diagnostic(tmp_path):
    _, result = document(tmp_path, '[dependency-groups]\na=[{include-group="b"}]\nb=[{include-group="a"}]\n')
    assert result["declarations"] == []
    assert {r["category"] for r in result["errors"]} == {"group_cycle"}


def test_repeated_include_is_not_silently_deduplicated(tmp_path):
    _, result = document(tmp_path, '[dependency-groups]\nbase=["demo"]\nall=[{include-group="base"},{include-group="base"}]\n')
    included = [r for r in result["declarations"] if r["scope"] == "all"]
    assert len(included) == 2
    assert len({r["declaration_id"] for r in included}) == 2


def test_unknown_group_is_diagnostic(tmp_path):
    _, result = document(tmp_path, '[dependency-groups]\ndev=[{include-group="missing"}]\n')
    assert result["errors"][0]["category"] == "unknown_group"


@pytest.mark.parametrize("entry", ['{path="local"}', '{include-group="x",extra=true}', '12'])
def test_group_extensions_are_not_pep735(tmp_path, entry):
    _, result = document(tmp_path, f'[dependency-groups]\ndev=[{entry}]\n')
    assert result["declarations"] == []
    assert result["errors"][0]["category"] == "unsupported_group_entry"


def test_invalid_group_array_is_diagnostic(tmp_path):
    _, result = document(tmp_path, '[dependency-groups]\ndev={dependencies=["demo"]}\n')
    assert "must be an array" in result["errors"][0]["message"]


def test_group_normalization_collision(tmp_path):
    _, result = document(tmp_path, '[dependency-groups]\nfoo_bar=["a"]\nfoo-bar=["b"]\n')
    assert result["declarations"] == []
    assert "collision" in result["errors"][0]["message"]


def test_active_inactive_marker_raw_text_preserved(tmp_path):
    _, result = document(tmp_path, """[project]
dependencies = [
  "demo>=1; python_version >= '3'",
  "old; python_version < '2'",
]
""")
    active, inactive = result["declarations"]
    assert active["marker_active"] is True
    assert inactive["marker_active"] is False
    assert inactive["marker_raw"] == "python_version < '2'"
    assert inactive["raw_declaration"] == "old; python_version < '2'"
    assert inactive["marker_status"] == "inactive"


def test_invalid_marker_diagnostic(tmp_path):
    _, result = document(tmp_path, '[project]\ndependencies=["demo; nonsense ???"]\n')
    assert result["declarations"] == []
    assert result["errors"][0]["marker_status"] == "error"


def test_original_graph_api_does_not_activate_static_groups(tmp_path):
    path, result = document(tmp_path, '[project]\ndependencies=["runtime"]\n[project.optional-dependencies]\nweb=["extra"]\n[dependency-groups]\ndev=["tool"]\n')
    assert [req.name for req, _ in parse_pyproject(path)] == ["runtime"]
    assert len(result["declarations"]) == 3


def test_poetry_raw_value_and_key_preserved(tmp_path):
    _, result = document(tmp_path, '[tool.poetry.group.dev.dependencies]\ndemo="^1.2"\n')
    row = result["declarations"][0]
    assert row["raw_declaration"] == "^1.2" and row["original_key"] == "demo"
    assert row["declared_version"] == "<2.0.0,>=1.2"
    assert row["scope"] == "dev" and row["graph_enabled"]


class OfflineClient:
    def __init__(self):
        self.calls = []

    def get_available_versions(self, name):
        self.calls.append(("versions", name))
        return []

    def get_dependencies(self, name, version, extras=None):
        self.calls.append(("dependencies", name))
        return []


def test_parser_keeps_graph_separate_from_all_declarations(tmp_path):
    from python_parser import PythonParser
    path, _ = document(tmp_path, '[project]\ndependencies=["demo"]\n[project.optional-dependencies]\nweb=["other==1"]\n[dependency-groups]\ndev=["tool==2"]\n')
    client = OfflineClient()
    parser = PythonParser(client)
    nodes = parser.parse(path)
    assert [node.name for node in nodes] == ["demo"]
    assert len(parser.declarations) == 3
    assert len(parser.declaration_packages) == 3
    assert client.calls == []


def test_parser_links_multiple_scopes_without_losing_raw_declarations(tmp_path):
    from python_parser import PythonParser
    path, _ = document(tmp_path, '[project]\ndependencies=["demo>=1"]\n[project.optional-dependencies]\nweb=["demo>=2"]\n[dependency-groups]\ndev=["demo<3"]\n')
    parser = PythonParser(OfflineClient())
    nodes = parser.parse(path)
    assert len(nodes) == len(parser.declaration_packages) == 1
    assert {row["scope"] for row in nodes[0].declarations} == {"runtime", "optional:web", "dev"}
    assert {row["raw_declaration"] for row in nodes[0].declarations} == {"demo>=1", "demo>=2", "demo<3"}


def test_parser_inactive_marker_static_only(tmp_path):
    from python_parser import PythonParser
    path, _ = document(tmp_path, """[project]
dependencies = ["old==1; python_version < '2'"]
""")
    parser = PythonParser(OfflineClient())
    assert parser.parse(path) == []
    assert len(parser.declarations) == 1
    assert parser.declarations[0]["marker_active"] is False
    assert parser.declarations[0]["version_status"] == "confirmed"


def test_parser_requirement_file_origin_and_inactive_marker(tmp_path):
    from python_parser import PythonParser
    path = tmp_path / "requirements.txt"
    path.write_text("-r base.txt\n", encoding="utf-8")
    (tmp_path / "base.txt").write_text("demo\nold; python_version < '2'\n", encoding="utf-8")
    parser = PythonParser(OfflineClient())
    assert [n.name for n in parser.parse(path)] == ["demo"]
    assert len(parser.declarations) == 2
    assert {Path(r["source_file"]).name for r in parser.declarations} == {"base.txt"}


def test_parser_resets_static_inventory_between_calls(tmp_path):
    from python_parser import PythonParser
    path, _ = document(tmp_path, '[project]\ndependencies=["demo"]\n')
    parser = PythonParser(OfflineClient())
    parser.parse(path)
    path.write_text('[project]\ndependencies=[]\n', encoding="utf-8")
    assert parser.parse(path) == []
    assert parser.declarations == parser.declaration_packages == []


def test_invalid_marker_does_not_abort_other_dependencies(tmp_path):
    from python_parser import PythonParser
    path, _ = document(tmp_path, '[project]\ndependencies=["bad; what ???", "good"]\n')
    parser = PythonParser(OfflineClient())
    assert [n.name for n in parser.parse(path)] == ["good"]
    assert parser.declaration_errors[0]["category"] == "invalid_marker"


def test_node_declarations_survive_dataclass_serialization(tmp_path):
    from dataclasses import asdict
    from python_parser import PythonParser
    path, _ = document(tmp_path, '[project]\ndependencies=["demo", "demo>=1"]\n')
    parser = PythonParser(OfflineClient())
    row = asdict(parser.parse(path)[0])
    assert len(row["declarations"]) == 2
    assert {d["raw_declaration"] for d in row["declarations"]} == {"demo", "demo>=1"}


def test_node_default_declaration_lists_are_independent():
    from dependency_node import DependencyNode
    a = DependencyNode("a", "pypi")
    b = DependencyNode("b", "pypi")
    a.declarations.append({"name": "a"})
    assert b.declarations == []


def test_adapter_preserves_inventory_and_existing_list_api(tmp_path):
    from python_security_adapter import parse_python_file
    path, _ = document(tmp_path, '[project]\ndependencies=["demo"]\n[project.optional-dependencies]\nweb=["demo>=2", "other"]\n')
    metadata = {}
    rows = parse_python_file(path, OfflineClient(), metadata=metadata)
    assert isinstance(rows, list) and len(rows) == 1
    assert len(metadata["declarations"]) == 3
    assert len(rows[0]["declarations"]) == 2
    assert len(metadata["declaration_packages"]) == 2
    assert rows[0]["version_status"] == "unresolved"


def test_adapter_purl_merge_keeps_distinct_declarations_once(tmp_path):
    from python_security_adapter import parse_python_file, merge_packages
    path, _ = document(tmp_path, '[project]\ndependencies=["demo", "demo>=1"]\n')
    rows = parse_python_file(path, OfflineClient())
    merged = merge_packages(rows + rows)
    assert len(merged) == 1
    assert len(merged[0]["declarations"]) == 2


def test_adapter_metadata_records_invalid_group_without_graph_loss(tmp_path):
    from python_security_adapter import parse_python_file
    path, _ = document(tmp_path, '[project]\ndependencies=["good"]\n[dependency-groups]\ndev=[{path="x"}]\n')
    metadata = {}
    rows = parse_python_file(path, OfflineClient(), metadata=metadata)
    assert [r["name"] for r in rows] == ["good"]
    assert metadata["declaration_errors"][0]["category"] == "unsupported_group_entry"


def test_runtime_version_selection_is_retained_per_declaration(tmp_path):
    from python_security_adapter import parse_python_file
    class Versions(OfflineClient):
        def get_available_versions(self, name):
            return ["1.0", "1.9"]
    path, _ = document(tmp_path, '[project]\ndependencies=["demo>=1"]\n[project.optional-dependencies]\nweb=["demo>=1"]\n')
    metadata = {}
    rows = parse_python_file(path, Versions(), metadata=metadata)
    runtime, optional = metadata["declarations"]
    assert rows[0]["resolved_version"] == "1.9"
    assert runtime["version_status"] == "estimated"
    assert optional["version_status"] == "unresolved"
    assert optional["usage_status"] == "declared_not_installation_verified"


def test_root_integrated_output_separates_graph_and_static_declarations(tmp_path):
    from integrated_parser import analyze
    path, _ = document(tmp_path, """[project]
dependencies = ["runtime", "old; python_version < '2'"]
[project.optional-dependencies]
web = ["extra"]
[dependency-groups]
dev = ["tool"]
""")
    graph = analyze(tmp_path, Path("target/classes"), OfflineClient())
    assert [r["name"] for r in graph["dependencies"]] == ["runtime"]
    assert len(graph["declarations"]) == len(graph["declaration_packages"]) == 4
    assert len([r for r in graph["declarations"] if r["marker_active"]]) == 3
    assert graph["declaration_errors"] == []


def test_security_and_cyclonedx_keep_using_graph_not_static_inventory(tmp_path):
    from integrated_parser import analyze
    from integrated_security import pipeline
    from cyclonedx_converter import convert_to_cyclonedx
    path, _ = document(tmp_path, '[project]\ndependencies=["runtime==1"]\n[project.optional-dependencies]\nweb=["extra==1"]\n')
    graph = analyze(tmp_path, Path("target/classes"), OfflineClient())
    class Security:
        def __init__(self):
            self.calls = []
        def osv(self, ecosystem, name, version):
            self.calls.append(name)
            return []
    client = Security()
    outputs = pipeline(graph["dependencies"], client)
    assert client.calls == ["runtime"]
    assert len(outputs[0]["results"]) == 1
    bom = convert_to_cyclonedx(graph)
    assert [c["name"] for c in bom["components"]] == ["runtime"]
    assert graph["declarations"][1]["optional"]


def test_root_same_purl_multiple_files_retains_declaration_origins(tmp_path):
    from integrated_parser import analyze
    document(tmp_path, '[project]\ndependencies=["demo"]\n')
    sub = tmp_path / "sub"
    sub.mkdir()
    document(sub, '[dependency-groups]\ndev=["demo"]\n')
    graph = analyze(tmp_path, Path("target/classes"), OfflineClient())
    assert len(graph["declaration_packages"]) == 1
    assert len(graph["declaration_packages"][0]["declarations"]) == 2
    assert len({r["source_file"] for r in graph["declarations"]}) == 2


def test_referenced_manifest_is_not_counted_twice(tmp_path):
    from integrated_parser import analyze
    sub = tmp_path / "sub"
    sub.mkdir()
    (tmp_path / "requirements.txt").write_text("-r sub/requirements.txt\n", encoding="utf-8")
    (sub / "requirements.txt").write_text("demo\n", encoding="utf-8")
    graph = analyze(tmp_path, Path("target/classes"), OfflineClient())
    assert len(graph["declarations"]) == 1


def test_java_python_mixed_graph_with_static_inventory(tmp_path):
    from integrated_parser import analyze
    classes = Path(__file__).resolve().parent / "target/classes"
    if not (classes / "com/bomerang/JsonDependencyExporter.class").is_file():
        pytest.skip("existing Java exporter classes unavailable")
    document(tmp_path, '[project]\ndependencies=["demo"]\n[dependency-groups]\ndev=["pytest"]\n')
    (tmp_path / "pom.xml").write_text("<project><dependencies><dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>1</version></dependency></dependencies></project>", encoding="utf-8")
    graph = analyze(tmp_path, classes, OfflineClient())
    assert {r["ecosystem"] for r in graph["dependencies"]} == {"maven", "pypi"}
    assert len(graph["declarations"]) == 2


def test_static_evaluation_preserves_conditions_and_separate_active_view(tmp_path):
    from integrated_parser import analyze
    from evaluate_repository_parsing import evaluate_declarations
    from packaging.markers import default_environment
    document(tmp_path, """[project]
dependencies = ["demo>=1", "old; python_version < '2'"]
[dependency-groups]
dev = ["demo>=2"]
""")
    graph = analyze(tmp_path, Path("target/classes"), OfflineClient())
    expected = []
    for row in graph["declarations"]:
        expected.append({key: row[key] for key in ("name", "ecosystem", "declared_version", "scope", "marker", "source_file")})
        expected[-1]["source_file"] = "pyproject.toml"
        expected[-1]["evidence"] = "test fixture declarations"
    from evaluate_repository_parsing import normalize_declaration_sources
    normalize_declaration_sources(graph, tmp_path)
    result = evaluate_declarations({"dependencies": expected}, graph)
    assert result["all_declared"]["detection"]["TP"] == 3
    assert result["environment_applicable"]["detection"]["TP"] == 2
    assert result["environment_applicable"]["detection"]["FP"] == 0


def test_flask_static_declarations_match_unchanged_gold():
    from evaluate_repository_parsing import load_case, analyze_source, read_json, evaluate_declarations
    root = Path(__file__).resolve().parent
    case, base = load_case(root / "accuracy-tests/repository_cases.json", "flask-3.1.2-declarations")
    graph = analyze_source(case, base, base / case["vendored_source"])
    result = evaluate_declarations(read_json(base / case["gold_file"]), graph)
    assert result["all_declared"]["detection"] == {
        "TP": 32, "FP": 0, "FN": 0, "precision": 1.0, "recall": 1.0, "f1_score": 1.0}
    assert result["environment_applicable"]["detection"]["TP"] == 30
    assert len(graph["dependencies"]) == 6
    assert result["observed_declaration_counts"]["raw_preserved"] == 32
    assert result["environment_applicable"]["attributes"]["marker"]["matched"] == 30


def test_static_evaluation_falls_back_for_unchanged_step2_result():
    from evaluate_repository_parsing import read_json, evaluate_declarations
    root = Path(__file__).resolve().parent
    graph = read_json(root / "accuracy-tests/results/flask-integrated-final.json")
    gold = read_json(root / "accuracy-tests/gold/flask.json")
    result = evaluate_declarations(gold, graph)
    assert result["input_view"] == "legacy_nodes_fallback"
    assert result["all_declared"]["detection"]["TP"] == 6
    assert result["all_declared"]["detection"]["FN"] == 26


def test_cli_declaration_mode_source_and_saved_match(tmp_path):
    import subprocess
    import sys
    import json
    root = Path(__file__).resolve().parent
    graph, source, saved = [tmp_path / n for n in ("graph.json", "source.json", "saved.json")]
    command = [sys.executable, "-B", str(root / "evaluate_repository_parsing.py"), "--declarations"]
    subprocess.run(command + ["--source", str(root / "accuracy-tests/sources/flask"),
                             "--save-integrated", str(graph), "--output", str(source)],
                   check=True, capture_output=True, text=True)
    subprocess.run(command + ["--input", str(graph), "--output", str(saved)],
                   check=True, capture_output=True, text=True)
    a, b = [json.loads(p.read_text(encoding="utf-8")) for p in (source, saved)]
    assert a["environment_applicable"] == b["environment_applicable"]
    assert a["all_declared"] == b["all_declared"]
    assert a["all_declared"]["detection"]["FN"] == 0


def test_pep503_purl_and_declaration_link_use_same_normalization(tmp_path):
    from python_parser import PythonParser
    path, _ = document(tmp_path, '[project]\ndependencies=["Demo.Pkg"]\n[dependency-groups]\ndev=["demo_pkg"]\n')
    parser = PythonParser(OfflineClient())
    node = parser.parse(path)[0]
    assert node.purl == "pkg:pypi/demo-pkg"
    assert len(node.declarations) == 2
    assert len(parser.declaration_packages) == 1


def test_requirements_invalid_marker_is_diagnostic(tmp_path):
    from python_parser import PythonParser
    path = tmp_path / "requirements.txt"
    path.write_text("bad; nonsense ???\ngood\n", encoding="utf-8")
    parser = PythonParser(OfflineClient())
    assert [n.name for n in parser.parse(path)] == ["good"]
    assert parser.declaration_errors[0]["marker_status"] == "error"


def test_marker_evaluation_error_retains_static_declaration(tmp_path):
    from python_parser import PythonParser
    path, _ = document(tmp_path, """[project]
dependencies = ["demo; 'x' in extras"]
""")
    parser = PythonParser(OfflineClient())
    assert parser.parse(path) == []
    assert parser.declarations[0]["marker_status"] == "error"
    assert parser.declarations[0]["marker_active"] is None
    assert parser.declaration_errors[0]["marker_status"] == "error"


def test_url_semicolon_does_not_corrupt_raw_marker(tmp_path):
    _, result = document(tmp_path, """[project]
dependencies = ["demo @ https://example.invalid/file;param.whl ; python_version >= '3'"]
""")
    assert result["declarations"][0]["marker_raw"] == "python_version >= '3'"


def test_optional_pin_does_not_change_runtime_resolution(tmp_path):
    from python_parser import PythonParser
    path, _ = document(tmp_path, '[project]\ndependencies=["demo"]\n[project.optional-dependencies]\nweb=["demo==9"]\n')
    parser = PythonParser(OfflineClient())
    graph = parser.parse(path)
    assert graph[0].resolved_version is None
    assert parser.declarations[1]["resolved_version"] == "9"
    assert not parser.declarations[1]["active_in_graph"]


def test_transitive_nodes_are_not_reclassified_as_direct_declarations(tmp_path):
    from python_parser import PythonParser
    from packaging.requirements import Requirement
    class Transitive(OfflineClient):
        def get_dependencies(self, name, version, extras=None):
            return [Requirement("child==1")] if name == "parent" else []
    path, _ = document(tmp_path, '[project]\ndependencies=["parent==1"]\n')
    parser = PythonParser(Transitive())
    graph = parser.parse(path)
    assert len(graph) == 2 and len(parser.declarations) == 1
    parent, child = graph
    assert parent.dependencies == [child.purl]
    assert len(parent.declarations) == 1 and child.declarations == []
