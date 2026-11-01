
from packaging.requirements import Requirement
from python_parser import PythonParser


class FakeExtrasPyPIClient:
    """네트워크 없이 extras와 재귀 의존성을 검증하는 클라이언트."""

    def __init__(self):
        self.calls = []

    def get_available_versions(self, package_name):
        versions = {
            "base-child": ["1.0.0"],
            "socks-child": ["1.0.0"],
            "socks-grandchild": ["1.0.0"],
            "cli-child": ["1.0.0"],
            "cli-grandchild": ["1.0.0"],
        }
        return versions.get(package_name, [])

    def get_dependencies(self, package_name, version, extras=None):
        selected = set(extras or set())
        self.calls.append((package_name, version, frozenset(selected)))

        if package_name == "demo-package":
            result = [Requirement("base-child==1.0.0")]

            if "socks" in selected:
                result.append(Requirement("socks-child==1.0.0"))

            if "cli" in selected:
                result.append(Requirement("cli-child==1.0.0"))

            return result

        if package_name == "socks-child":
            return [Requirement("socks-grandchild==1.0.0")]

        if package_name == "cli-child":
            return [Requirement("cli-grandchild==1.0.0")]

        if package_name == "cycle-a":
            return [Requirement("cycle-b==1.0.0")]

        if package_name == "cycle-b":
            return [Requirement("cycle-a==1.0.0")]

        return []


def parse_requirements(tmp_path, content):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(content, encoding="utf-8")

    client = FakeExtrasPyPIClient()
    parser = PythonParser(pypi_client=client)
    nodes = parser.parse(str(requirements))

    return {node.name: node for node in nodes}, client


def test_01_base_dependency(tmp_path):
    nodes, _ = parse_requirements(
        tmp_path,
        "demo-package==1.0.0\n"
    )

    assert "demo-package" in nodes
    assert "base-child" in nodes
    assert "socks-child" not in nodes
    assert "cli-child" not in nodes


def test_02_socks_extra_transitive(tmp_path):
    nodes, client = parse_requirements(
        tmp_path,
        "demo-package[socks]==1.0.0\n"
    )

    assert "base-child" in nodes
    assert "socks-child" in nodes
    assert "socks-grandchild" in nodes

    assert (
        "demo-package",
        "1.0.0",
        frozenset({"socks"})
    ) in client.calls


def test_03_unselected_extra_excluded(tmp_path):
    nodes, _ = parse_requirements(
        tmp_path,
        "demo-package[socks]==1.0.0\n"
    )

    assert "cli-child" not in nodes
    assert "cli-grandchild" not in nodes


def test_04_multiple_extras_merged(tmp_path):
    nodes, _ = parse_requirements(
        tmp_path,
        "demo-package[socks]==1.0.0\n"
        "demo-package[cli]==1.0.0\n"
    )

    assert "base-child" in nodes
    assert "socks-child" in nodes
    assert "socks-grandchild" in nodes
    assert "cli-child" in nodes
    assert "cli-grandchild" in nodes


def test_05_circular_dependency(tmp_path):
    nodes, _ = parse_requirements(
        tmp_path,
        "cycle-a==1.0.0\n"
    )

    assert "cycle-a" in nodes
    assert "cycle-b" in nodes
    assert nodes["cycle-a"].is_circular or nodes["cycle-b"].is_circular
