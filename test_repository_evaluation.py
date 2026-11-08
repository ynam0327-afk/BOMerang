"""Offline tests for direct declaration evaluation; no external services."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib

from packaging.markers import default_environment
import pytest

from evaluate_repository_parsing import evaluate, extract_direct, analyze_source, load_case

ROOT = Path(__file__).resolve().parent


def gold_row(name="demo", version=">=1", scope="runtime", marker=None):
    return {"name": name, "ecosystem": "pypi", "declared_version": version,
            "scope": scope, "source_file": "pyproject.toml", "marker": marker,
            "evidence": {"raw": name + version, "locator": "project.dependencies"}}


def actual(name="demo", version=">=1", scope="runtime", marker=None, depth=1):
    return {"name": name, "ecosystem": "pypi", "declared_version": version,
            "scope": scope, "source_file": "pyproject.toml", "marker": marker,
            "depth": depth, "resolved_version": None, "version_status": "unresolved"}


def run(expected, found):
    return evaluate({"dependencies": expected},
                    {"dependencies": found, "python_marker_environment": default_environment()})


def metric(result):
    return result["environment_applicable"]["detection"]


def test_all_dependencies_match():
    result = run([gold_row()], [actual()])
    assert metric(result) == {"TP": 1, "FP": 0, "FN": 0,
                             "precision": 1.0, "recall": 1.0, "f1_score": 1.0}
    assert result["environment_applicable"]["strict_attribute_matches"] == 1


def test_missing_dependency():
    result = run([gold_row(), gold_row("second")], [actual()])
    assert metric(result)["FN"] == 1
    assert metric(result)["recall"] == 0.5


def test_extra_dependency():
    result = run([gold_row()], [actual(), actual("unexpected")])
    assert metric(result)["FP"] == 1
    assert metric(result)["precision"] == 0.5


def test_pep503_name_normalization():
    assert metric(run([gold_row("Foo_Bar.BAZ")], [actual("foo-bar-baz")]))["TP"] == 1


def test_multiple_conditions_preserved_and_reversed():
    first = 'python_version >= "3.0"'
    second = 'sys_platform != "impossible-os"'
    result = run([gold_row(marker=first), gold_row(marker=second)],
                 [actual(marker=second), actual(marker=first)])
    assert metric(result)["TP"] == 2
    assert result["environment_applicable"]["attributes"]["marker"]["matched"] == 2


def test_collapsed_conditions_are_missing_occurrences():
    result = run([gold_row(marker='python_version >= "3.0"'),
                  gold_row(marker='sys_platform != "impossible-os"')], [actual()])
    assert metric(result)["FN"] == 1
    assert metric(result)["TP"] == 1


def test_version_mismatch_does_not_change_detection():
    result = run([gold_row(version=">=2")], [actual()])
    assert metric(result)["TP"] == 1
    assert result["environment_applicable"]["attributes"]["declared_version"]["mismatched"] == 1


def test_specifier_order_is_canonical():
    result = run([gold_row(version=">=1,<3")], [actual(version="<3,>=1")])
    assert result["environment_applicable"]["attributes"]["declared_version"]["matched"] == 1


def test_scope_mismatch():
    result = run([gold_row(scope="dev")], [actual()])
    assert result["environment_applicable"]["attributes"]["scope"]["mismatched"] == 1


def test_marker_mismatch():
    result = run([gold_row(marker='python_version >= "3.0"')], [actual()])
    assert result["environment_applicable"]["attributes"]["marker"]["mismatched"] == 1


def test_missing_marker_is_unavailable_even_when_gold_has_none():
    row = actual()
    del row["marker"]
    result = run([gold_row()], [row])
    assert result["environment_applicable"]["attributes"]["marker"]["unavailable"] == 1
    assert result["environment_applicable"]["strict_attribute_matches"] == 0


def test_transitive_not_false_positive():
    result = run([gold_row()], [actual(), actual("transitive", depth=2)])
    assert metric(result)["FP"] == 0
    assert result["counts"]["transitive_nodes_excluded"] == 1


@pytest.mark.parametrize("field", ["name", "ecosystem", "depth", "declared_version",
                                   "resolved_version", "version_status", "source_file"])
def test_missing_required_dependency_fields(field):
    row = actual()
    del row[field]
    with pytest.raises(ValueError):
        run([gold_row()], [row])


def test_missing_dependencies_array():
    with pytest.raises(ValueError, match="missing fields"):
        evaluate({"dependencies": []}, {"python_marker_environment": default_environment()})


def test_missing_marker_environment():
    with pytest.raises(ValueError, match="python_marker_environment"):
        evaluate({"dependencies": []}, {"dependencies": []})


def test_empty_gold_and_result():
    result = run([], [])
    assert metric(result) == {"TP": 0, "FP": 0, "FN": 0,
                             "precision": None, "recall": None, "f1_score": None}


def test_empty_gold_has_false_positive():
    assert metric(run([], [actual()]))["FP"] == 1


def test_inactive_declarations_reported_separately():
    result = run([gold_row(marker='python_version < "2"')], [])
    assert metric(result)["FN"] == 0
    assert result["all_declared"]["detection"]["FN"] == 1
    assert result["counts"]["gold_inactive"] == 1


def test_versions_not_equated_with_installed_version():
    rows = [actual("fixed"), actual("selected"), actual("unknown")]
    rows[0].update(version_status="confirmed", resolved_version="1")
    rows[1].update(version_status="estimated", resolved_version="9")
    result = run([gold_row(r["name"]) for r in rows], rows)
    assert result["version_status_counts"] == {"confirmed": 1, "estimated": 1, "unresolved": 1}


def test_invalid_depth_and_status():
    for changes in ({"depth": 0}, {"depth": True}, {"version_status": "installed"},
                    {"resolved_version": "1"}):
        row = actual()
        row.update(changes)
        with pytest.raises(ValueError):
            run([gold_row()], [row])


def test_source_files_do_not_merge_by_basename():
    gold = [gold_row(), dict(gold_row(), source_file="sub/pyproject.toml")]
    assert metric(run(gold, [actual()]))["FN"] == 1


def test_absolute_source_needs_explicit_root(tmp_path):
    row = actual()
    row["source_file"] = str(tmp_path / "pyproject.toml")
    with pytest.raises(ValueError):
        extract_direct({"dependencies": [row]})
    assert extract_direct({"dependencies": [row]}, tmp_path)[0][0]["source_file"] == "pyproject.toml"


def test_maven_identity_is_case_sensitive():
    gold = dict(gold_row("Library"), ecosystem="maven", group="org.example")
    row = dict(actual("library"), ecosystem="maven", group="org.example")
    assert metric(run([gold], [row]))["FP"] == 1


def test_gold_is_independent_complete_transcription():
    case, base = load_case(ROOT / "accuracy-tests/repository_cases.json", "flask-3.1.2-declarations")
    gold = json.loads((base / case["gold_file"]).read_text(encoding="utf-8"))
    source = base / case["vendored_source"] / "pyproject.toml"
    from packaging.requirements import Requirement
    upstream = tomllib.loads(source.read_text(encoding="utf-8"))
    expected = []
    for text in upstream["project"]["dependencies"]:
        expected.append(("runtime", text))
    for group, declarations in upstream["project"]["optional-dependencies"].items():
        expected.extend(("optional:" + group, text) for text in declarations)
    for group, declarations in upstream["dependency-groups"].items():
        expected.extend((group, text) for text in declarations)
    assert [(row["scope"], row["evidence"]["raw"]) for row in gold["dependencies"]] == expected
    for row in gold["dependencies"]:
        req = Requirement(row["evidence"]["raw"])
        assert req.name == row["name"]
        assert (str(req.specifier) or None) == row["declared_version"]
        assert (str(req.marker) if req.marker else None) == row["marker"]
        line = source.read_text(encoding="utf-8").splitlines()[row["evidence"]["line"] - 1]
        assert row["evidence"]["raw"] in line
    assert hashlib.sha256(source.read_bytes()).hexdigest() == case["source_sha256"]["pyproject.toml"]


def test_source_mode_imports_root_parser_and_retains_missing_marker(tmp_path):
    case, base = load_case(ROOT / "accuracy-tests/repository_cases.json", "flask-3.1.2-declarations")
    graph = analyze_source(case, base, base / case["vendored_source"])
    modules = graph["evaluation_provenance"]["modules"]
    assert Path(modules["integrated_parser"]["path"]) == ROOT / "integrated_parser.py"
    assert Path(modules["python_parser"]["path"]) == ROOT / "python-parser/python_parser.py"
    gold = json.loads((base / case["gold_file"]).read_text(encoding="utf-8"))
    result = evaluate(gold, graph)
    assert result["counts"]["actual_direct"] == 6
    assert result["counts"]["gold_total"] == 32
    assert result["environment_applicable"]["attributes"]["marker"]["unavailable"] == 6


def test_modified_source_rejected(tmp_path):
    case, base = load_case(ROOT / "accuracy-tests/repository_cases.json", "flask-3.1.2-declarations")
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies=[]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        analyze_source(case, base, tmp_path)


def test_cli_saved_and_source_results_agree_and_do_not_overwrite(tmp_path):
    integrated, source_report, offline_report = [tmp_path / name for name in ("graph.json", "source.json", "offline.json")]
    source = ROOT / "accuracy-tests/sources/flask"
    common = [sys.executable, "-B", str(ROOT / "evaluate_repository_parsing.py")]
    subprocess.run(common + ["--source", str(source), "--save-integrated", str(integrated),
                              "--output", str(source_report)], check=True, capture_output=True, text=True)
    subprocess.run(common + ["--input", str(integrated), "--output", str(offline_report)],
                   check=True, capture_output=True, text=True)
    first, second = [json.loads(p.read_text(encoding="utf-8")) for p in (source_report, offline_report)]
    assert first["environment_applicable"] == second["environment_applicable"]
    before = offline_report.read_bytes()
    failed = subprocess.run(common + ["--input", str(integrated), "--output", str(offline_report)],
                            capture_output=True, text=True)
    assert failed.returncode != 0
    assert offline_report.read_bytes() == before


def test_multiple_source_files_normalization_is_idempotent():
    row = actual()
    row["source_files"] = ["pyproject.toml", "sub/pyproject.toml"]
    first, _ = extract_direct({"dependencies": [row]})
    second, _ = extract_direct({"dependencies": first})
    assert len(first) == len(second) == 2
    assert first == second
    gold = [gold_row(), dict(gold_row(), source_file="sub/pyproject.toml")]
    assert metric(run(gold, second))["TP"] == 2
    assert metric(run(gold, second))["FP"] == 0
