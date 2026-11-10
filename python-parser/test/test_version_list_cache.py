"""Regressions for per-analysis PyPI version-list reuse."""
from unittest.mock import Mock

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from python_parser import PythonParser


class CountingClient:
    def __init__(self, dependencies=None):
        self.get_available_versions = Mock(return_value=["1.0.0", "1.5.0", "2.0.0"])
        dependency_map = dependencies or {}
        self.get_dependencies = Mock(side_effect=lambda name, version, extras=None:
            [Requirement(raw) for raw in dependency_map.get(canonicalize_name(name), [])])


def parse_text(parser, tmp_path, text, name="requirements.txt"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return {node.purl: node for node in parser.parse(str(path))}


def test_shared_transitive_version_list_is_fetched_once(tmp_path):
    client = CountingClient({"parent-a": ["shared>=1.0"], "parent-b": ["shared>=1.0"]})
    nodes = parse_text(PythonParser(client), tmp_path, "parent-a==1.0.0\nparent-b==1.0.0\n")

    client.get_available_versions.assert_called_once_with("shared")
    assert client.get_dependencies.call_count == 3
    assert len(nodes) == 3
    for parent in ("parent-a", "parent-b"):
        assert nodes[f"pkg:pypi/{parent}@1.0.0"].dependencies == ["pkg:pypi/shared@2.0.0"]


@pytest.mark.parametrize("file_name,text", [
    ("requirements.txt", "shared>=1,<2\nshared>=2,<3\n"),
    ("pyproject.toml", '[project]\ndependencies = ["shared>=1,<2", "shared>=2,<3"]\n'),
])
def test_each_range_selects_its_own_version(tmp_path, file_name, text):
    client = CountingClient()
    parser = PythonParser(client)
    nodes = parse_text(parser, tmp_path, text, file_name)

    client.get_available_versions.assert_called_once_with("shared")
    assert set(nodes) == {"pkg:pypi/shared@1.5.0", "pkg:pypi/shared@2.0.0"}
    assert [item["resolved_version"] for item in parser.declarations] == ["1.5.0", "2.0.0"]
    assert all(item["version_status"] == "estimated" for item in parser.declarations)


def test_cache_key_normalizes_case_and_separators(tmp_path):
    client = CountingClient()
    nodes = parse_text(PythonParser(client), tmp_path,
                       "My_Package>=1\nmy-package>=1\nMY.PACKAGE>=1\nmy__..--package>=1\n")

    client.get_available_versions.assert_called_once_with("My_Package")
    assert set(nodes) == {"pkg:pypi/my-package@2.0.0"}
    assert client.get_dependencies.call_count == 1


def test_failed_lookup_can_retry_within_same_parse(tmp_path):
    client = CountingClient()
    client.get_available_versions.side_effect = [RuntimeError("temporary PyPI failure"), ["1.5.0"]]
    nodes = parse_text(PythonParser(client), tmp_path, "shared>=3\nshared>=1,<2\nshared>=1,<2\n")

    assert client.get_available_versions.call_count == 2
    assert nodes["pkg:pypi/shared"].parse_status == "error"
    assert nodes["pkg:pypi/shared"].error_message == "temporary PyPI failure"
    assert nodes["pkg:pypi/shared@1.5.0"].parse_status == "success"
    assert client.get_dependencies.call_count == 1


@pytest.mark.parametrize("same_file", [True, False])
def test_new_parse_fetches_fresh_versions(tmp_path, same_file):
    client = CountingClient()
    parser = PythonParser(client)
    first = parse_text(parser, tmp_path, "shared>=1\n")
    client.get_available_versions.return_value = ["3.0.0"]
    second_dir = tmp_path if same_file else tmp_path / "other"
    second_dir.mkdir(exist_ok=True)
    second = parse_text(parser, second_dir, "shared>=1\n")

    assert set(first) == {"pkg:pypi/shared@2.0.0"}
    assert set(second) == {"pkg:pypi/shared@3.0.0"}
    assert client.get_available_versions.call_count == 2
    assert client.get_dependencies.call_count == 2


def test_successful_empty_version_list_is_cached(tmp_path):
    client = CountingClient()
    client.get_available_versions.return_value = []
    nodes = parse_text(PythonParser(client), tmp_path, "shared>=1\nshared>=2\n")

    client.get_available_versions.assert_called_once_with("shared")
    assert set(nodes) == {"pkg:pypi/shared"}
    assert nodes["pkg:pypi/shared"].parse_status == "success"
    client.get_dependencies.assert_not_called()


def test_unsatisfied_range_does_not_cache_resolution_failure(tmp_path):
    client = CountingClient()
    nodes = parse_text(PythonParser(client), tmp_path, "shared>=3\nshared>=1,<2\n")

    client.get_available_versions.assert_called_once_with("shared")
    assert set(nodes) == {"pkg:pypi/shared", "pkg:pypi/shared@1.5.0"}
    assert nodes["pkg:pypi/shared"].resolved_version is None
    assert nodes["pkg:pypi/shared@1.5.0"].resolved_version == "1.5.0"
