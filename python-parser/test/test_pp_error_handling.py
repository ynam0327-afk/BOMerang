from python_parser import PythonParser


class FakePyPIClient:
    def get_available_versions(self, package_name):
        raise RuntimeError("PyPI connection failed")

    def get_dependencies(self, package_name, version):
        raise RuntimeError("PyPI connection failed")


def test_version_lookup_failure_keeps_node(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "requests>=2.0\n",
        encoding="utf-8"
    )

    parser = PythonParser(FakePyPIClient())
    nodes = parser.parse(str(requirements))

    assert len(nodes) == 1

    node = nodes[0]
    assert node.name == "requests"
    assert node.resolved_version is None
    assert node.purl == "pkg:pypi/requests"
    assert node.parse_status == "error"
    assert "PyPI connection failed" in node.error_message


def test_dependency_purl_matches_actual_node(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "requests==2.32.5\n",
        encoding="utf-8"
    )

    class VersionedFakePyPIClient:
        def get_available_versions(self, package_name):
            return ["2.0.0", "2.2.0"]

        def get_dependencies(self, package_name, version):
            if package_name == "requests":
                from packaging.requirements import Requirement
                return [Requirement("urllib3>=2.0")]

            return []

    parser = PythonParser(VersionedFakePyPIClient())
    nodes = parser.parse(str(requirements))

    requests_node = next(
        node for node in nodes if node.name == "requests"
    )
    urllib3_node = next(
        node for node in nodes if node.name == "urllib3"
    )

    assert urllib3_node.purl == "pkg:pypi/urllib3@2.2.0"
    assert urllib3_node.purl in requests_node.dependencies
