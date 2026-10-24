from toml_parser import parse_pyproject


def test_parse_project_dependencies(tmp_path):
    file = tmp_path / "pyproject.toml"

    file.write_text(
        """
[project]
name = "test-project"
version = "1.0.0"

dependencies = [
    "requests==2.32.5",
    "urllib3>=2.0",
    "packaging"
]
""",
        encoding="utf-8"
    )

    requirements = parse_pyproject(str(file))

    assert len(requirements) == 3

    assert requirements[0][0].name == "requests"
    assert str(requirements[0][0].specifier) == "==2.32.5"

    assert requirements[1][0].name == "urllib3"
    assert str(requirements[1][0].specifier) == ">=2.0"

    assert requirements[2][0].name == "packaging"
    assert str(requirements[2][0].specifier) == ""

def test_parse_poetry_dependencies(tmp_path):
    file = tmp_path / "pyproject.toml"

    file.write_text(
        """
[tool.poetry]
name = "test-project"
version = "1.0.0"

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.32.0"
packaging = ">=23.0"
""",
        encoding="utf-8"
    )

    requirements = parse_pyproject(str(file))

    assert len(requirements) == 2

    assert requirements[0][0].name == "requests"
    assert str(requirements[0][0].specifier) == "<3.0.0,>=2.32.0"

    assert requirements[1][0].name == "packaging"
    assert str(requirements[1][0].specifier) == ">=23.0"

def test_parse_poetry_unpinned_dependency(tmp_path):
    file = tmp_path / "pyproject.toml"

    file.write_text(
        """
[tool.poetry.dependencies]
requests = "*"
""",
        encoding="utf-8"
    )

    requirements = parse_pyproject(str(file))

    assert len(requirements) == 1
    assert requirements[0][0].name == "requests"
    assert str(requirements[0][0].specifier) == ""

def test_parse_poetry_dependency_group(tmp_path):
    file = tmp_path / "pyproject.toml"

    file.write_text(
        """
[tool.poetry.group.dev.dependencies]
pytest = "^8.0"

[tool.poetry.group.test.dependencies]
pytest-cov = "^5.0"
""",
        encoding="utf-8"
    )

    requirements = parse_pyproject(str(file))

    assert len(requirements) == 2

    assert requirements[0][0].name == "pytest"
    assert requirements[0][1] == "dev"

    assert requirements[1][0].name == "pytest-cov"
    assert requirements[1][1] == "test"

