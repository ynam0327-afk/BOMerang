from packaging.requirements import Requirement

from python_parser import PythonParser


class FakePyPIClient:

    def get_dependencies(self, package_name, version):

        if package_name == "requests":
            return [
                Requirement("urllib3<3,>=1.21.1"),
                Requirement("certifi>=2017.4.17")
            ]

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