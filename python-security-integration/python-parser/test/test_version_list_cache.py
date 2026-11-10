from packaging.requirements import Requirement
from python_parser import PythonParser


class CountingClient:
    def __init__(self):
        self.version_calls = 0
        self.dependency_calls = {}
        self.fail_next = False

    def get_available_versions(self, name):
        self.version_calls += 1
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("Simulated lookup failure")
        return ["1.0.0", "2.0.0"]

    def get_dependencies(self, name, version, extras=None):
        key = (name, version)
        self.dependency_calls[key] = (
            self.dependency_calls.get(key, 0) + 1
        )
        if name in {"parent-a", "parent-b"}:
            return [Requirement("shared>=1,<3")]
        return []


def test_shared_lookup_once_and_graph_preserved(tmp_path):
    source = tmp_path / "requirements.txt"
    source.write_text(
        "parent-a==1.0.0\nparent-b==1.0.0\n",
        encoding="utf-8",
    )
    client = CountingClient()
    nodes = PythonParser(client).parse(str(source))

    assert client.version_calls == 1
    assert len(nodes) == 3
    assert {n.purl for n in nodes} == {
        "pkg:pypi/parent-a@1.0.0",
        "pkg:pypi/parent-b@1.0.0",
        "pkg:pypi/shared@2.0.0",
    }
    assert client.dependency_calls == {
        ("parent-a", "1.0.0"): 1,
        ("parent-b", "1.0.0"): 1,
        ("shared", "2.0.0"): 1,
    }
    for node in nodes:
        assert node.parse_status == "success"
        if node.name in {"parent-a", "parent-b"}:
            assert node.dependencies == ["pkg:pypi/shared@2.0.0"]


def test_cache_reset_between_analyses(tmp_path):
    source = tmp_path / "requirements.txt"
    source.write_text("shared>=1,<3\n", encoding="utf-8")
    client = CountingClient()
    parser = PythonParser(client)

    first = parser.parse(str(source))
    assert client.version_calls == 1
    second = parser.parse(str(source))

    assert client.version_calls == 2
    assert first[0].resolved_version == "2.0.0"
    assert second[0].resolved_version == "2.0.0"


def test_constraints_evaluated_separately(tmp_path):
    source = tmp_path / "requirements.txt"
    source.write_text(
        "parent-a>=1,<2\nparent-b>=2,<3\n",
        encoding="utf-8",
    )

    class Client(CountingClient):
        def get_dependencies(self, name, version, extras=None):
            if name == "parent-a":
                return [Requirement("shared>=1,<2")]
            if name == "parent-b":
                return [Requirement("shared>=2,<3")]
            return []

    client = Client()
    nodes = PythonParser(client).parse(str(source))
    by_name = {n.name: n for n in nodes if n.name.startswith("parent-")}

    assert by_name["parent-a"].dependencies == ["pkg:pypi/shared@1.0.0"]
    assert by_name["parent-b"].dependencies == ["pkg:pypi/shared@2.0.0"]
    assert client.version_calls == 3


def test_normalized_names_share_cache(tmp_path):
    source = tmp_path / "requirements.txt"
    source.write_text(
        "Shared_Name>=1\nshared-name>=1\n",
        encoding="utf-8",
    )
    client = CountingClient()
    nodes = PythonParser(client).parse(str(source))

    assert client.version_calls == 1
    assert len(nodes) == 1
    assert nodes[0].purl == "pkg:pypi/shared-name@2.0.0"


def test_failed_lookup_can_retry(tmp_path):
    source = tmp_path / "requirements.txt"
    source.write_text(
        "shared>=1\nshared>=1\n",
        encoding="utf-8",
    )
    client = CountingClient()
    client.fail_next = True
    nodes = PythonParser(client).parse(str(source))

    assert client.version_calls == 2
    assert any(n.parse_status == "error" for n in nodes)
    assert any(
        n.purl == "pkg:pypi/shared@2.0.0"
        and n.parse_status == "success"
        for n in nodes
    )
