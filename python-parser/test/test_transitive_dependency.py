from packaging.requirements import Requirement

from python_parser import PythonParser


class FakePyPIClient:

    def get_dependencies(self, package_name, version, extras=None):

        if package_name == "requests":
            return [
                Requirement("urllib3<3,>=1.21.1"),
                Requirement("certifi>=2017.4.17")
            ]

        if package_name == "parent":
            return[
                Requirement("child")
            ]

        return []

    # 실제 PyPI 조회 없이 빈 목록 반환 - 임시조치
    def get_available_versions(self, package_name):
        return []


def test_transitive_dependencies(tmp_path):

    requirements = tmp_path / "requirements.txt"

    requirements.write_text(
        "requests==2.32.5\n",
        encoding="utf-8"
    )

    parser = PythonParser(
        pypi_client=FakePyPIClient()
    )

    nodes = parser.parse(
        str(requirements)
    )

    nodes_by_name = {
        node.name: node
        for node in nodes
    }

    assert "requests" in nodes_by_name
    assert "urllib3" in nodes_by_name
    assert "certifi" in nodes_by_name

    requests = nodes_by_name["requests"]

    assert requests.depth == 1
    assert requests.resolved_version == "2.32.5"

    assert "pkg:pypi/urllib3" in requests.dependencies
    assert "pkg:pypi/certifi" in requests.dependencies

    urllib3 = nodes_by_name["urllib3"]

    assert urllib3.depth == 2
    assert urllib3.resolved_version is None
    assert urllib3.declared_version == "<3,>=1.21.1"


def test_transitive_dependency_reuses_direct_version(tmp_path):
    requirements = tmp_path / "requirements.txt"

    requirements.write_text(
        "parent==1.0.0\n"
        "child==2.0.0\n",
        encoding="utf-8"
    )

    parser = PythonParser(
        pypi_client=FakePyPIClient()
    )

    nodes = parser.parse(str(requirements))
    nodes_by_purl = {node.purl: node for node in nodes}

    # 직접 의존성 child의 버전 확인
    child = nodes_by_purl["pkg:pypi/child@2.0.0"]
    assert child.resolved_version == "2.0.0"

    # parent의 하위 의존성도 같은 버전의 노드를 참조해야 함
    parent = nodes_by_purl["pkg:pypi/parent@1.0.0"]
    assert "pkg:pypi/child@2.0.0" in parent.dependencies

    # 버전 없는 별도 노드가 생성되지 않아야 함
    assert "pkg:pypi/child" not in nodes_by_purl
