"""Declaration linking and canonical source behavior across optimized paths."""
from dependency_node import DependencyNode
from python_parser import PythonParser
from toml_parser import make_declaration, parse_pyproject_document


class OfflineClient:
    def get_dependencies(self, *args, **kwargs):
        return []


def test_declaration_candidates_keep_names_ranges_and_ambiguity(tmp_path):
    parser = PythonParser(OfflineClient())
    nodes = {}
    for name, normalized, version in [("Demo_Package", "demo-package", "1.0"),
                                      ("demo.package", "demo-package", "2.0"),
                                      ("Other", "other", "1.0")]:
        purl = f"pkg:pypi/{normalized}@{version}"
        nodes[purl] = DependencyNode(name=name, ecosystem="pypi", resolved_version=version, purl=purl)
    declarations = ["DEMO.PACKAGE>=1,<2", "demo-package>=1,<3", "Other>=1",
                    "demo_package>=1,<2; python_version < '2'", "demo_package==2.0"]
    parser.declarations = [make_declaration(raw, None, tmp_path / "requirements.txt", f"line:{i}")
                           for i, raw in enumerate(declarations, 1)]
    parser._finalize_declarations(nodes)
    assert [d["resolved_version"] for d in parser.declarations] == ["1.0", None, "1.0", None, "2.0"]
    assert [d["version_status"] for d in parser.declarations] == ["estimated", "unresolved", "estimated", "unresolved", "confirmed"]
    assert nodes["pkg:pypi/demo-package@1.0"].declarations == [parser.declarations[0]]
    assert nodes["pkg:pypi/other@1.0"].declarations == [parser.declarations[2]]


def test_requirements_source_identity_matches_public_declaration_api(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    root = tmp_path / "requirements.txt"
    root.write_text("-r nested/pins.txt\n", encoding="utf-8")
    target = nested / "pins.txt"
    target.write_text("Demo_Package==1.0\n", encoding="utf-8")
    parser = PythonParser(OfflineClient())
    parser.parse(str(nested / ".." / "requirements.txt"))
    expected = make_declaration("Demo_Package==1.0", None, target, "line:1", kind="requirements")
    actual = parser.declarations[0]
    assert actual["declaration_id"] == expected["declaration_id"]
    assert actual["source_file"] == str(target.resolve())
    assert actual["raw_declaration"] == expected["raw_declaration"]


def test_toml_relative_sources_and_diagnostics_match_absolute_sources(tmp_path, monkeypatch):
    path = tmp_path / "pyproject.toml"
    monkeypatch.chdir(tmp_path)
    documents = [
        '[project]\ndependencies=["Demo_Package==1.0", "bad requirement ?"]\n[dependency-groups]\ndev=[{path="local"}]\n',
        '[tool.poetry.dependencies]\nDemo_Package="^1.0"\nbroken={path="local"}\n',
    ]
    for text in documents:
        path.write_text(text, encoding="utf-8")
        absolute = parse_pyproject_document(str(path.resolve()))
        relative = parse_pyproject_document("pyproject.toml")
        assert relative == absolute
        assert relative["errors"]
        assert all(error["source_file"] == str(path.resolve()) for error in relative["errors"])
