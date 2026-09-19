from python_parser import PythonParser

class FakePyPIClient:

    def get_dependencies(self, package_name, version):
        return []

def test_parse_requirements(tmp_path):
    requirements = tmp_path / "requirements.txt"

    requirements.write_text(
        """
        requests==2.32.5
        flask>=3.0
        numpy
        # comment
        """,
        encoding="utf-8"
    )

    parser = PythonParser(pypi_client=FakePyPIClient())
    nodes = parser.parse(str(requirements))

    assert len(nodes) == 3

    assert nodes[0].name == "requests"
    assert nodes[0].declared_version == "==2.32.5"
    assert nodes[0].resolved_version == "2.32.5"
    assert nodes[0].depth == 1
    assert nodes[0].ecosystem == "pypi"

    assert nodes[1].name == "flask"
    assert nodes[1].declared_version == ">=3.0"
    assert nodes[1].resolved_version is None

    assert nodes[2].name == "numpy"
    assert nodes[2].declared_version is None
    assert nodes[2].resolved_version is None