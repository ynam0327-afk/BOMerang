from python_parser import PythonParser

class FakePyPIClient:

    def get_dependencies(self, package_name, version):
        return []

def test_requirements_file_reference(tmp_path):

    requirements = tmp_path / "requirements.txt"
    base = tmp_path / "base.txt"

    requirements.write_text(
        """
        -r base.txt
        requests==2.32.5
        """,
        encoding="utf-8"
    )

    base.write_text(
        """
        flask==3.0.3
        sqlalchemy>=2.0
        """,
        encoding="utf-8"
    )

    parser = PythonParser(
    pypi_client=FakePyPIClient())
    nodes = parser.parse(str(requirements))

    assert len(nodes) == 3

    names = {node.name for node in nodes}

    assert "requests" in names
    assert "flask" in names
    assert "sqlalchemy" in names

def test_circular_file_reference(tmp_path):

    requirements = tmp_path / "requirements.txt"
    base = tmp_path / "base.txt"

    requirements.write_text(
        "-r base.txt\nrequests==2.32.5\n",
        encoding="utf-8"
    )

    base.write_text(
        "-r requirements.txt\nflask==3.0.3\n",
        encoding="utf-8"
    )

    parser = PythonParser(pypi_client=FakePyPIClient())
    nodes = parser.parse(str(requirements))

    assert len(nodes) == 2

    names = {node.name for node in nodes}

    assert "requests" in names
    assert "flask" in names