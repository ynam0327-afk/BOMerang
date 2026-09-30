from python_parser import PythonParser


def test_python_parser_pyproject(tmp_path):
    file = tmp_path / "pyproject.toml"

    file.write_text(
        """
[project]
name = "test-project"
version = "1.0.0"

dependencies = [
    "requests==2.32.5",
    "urllib3>=2.0"
]
""",
        encoding="utf-8"
    )

    parser = PythonParser()
    nodes = parser.parse(str(file))

    for node in nodes:
        print(node)

    requests = next(
        node for node in nodes
        if node.purl == "pkg:pypi/requests@2.32.5"
    )

    assert requests.name == "requests"
    assert requests.declared_version == "==2.32.5"
    assert requests.resolved_version == "2.32.5"

    '''urllib3 = next(
        node for node in nodes
        if node.name == "urllib3"
        and node.declared_version == ">=2.0"
    )

    # resolved_version은 정확한 버전일 때만 저장하고 범위 지정은 null로 한다는 규칙
    # 여러 dependency가 같은 purl을 요구할 때 declared_version을
    # 어떻게 표현할 것인지 다시 맞춰봐야 할 문제 발견

    assert urllib3.resolved_version is None'''

# 테스트
def test_python_parser_poetry_pyproject(tmp_path):
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

    parser = PythonParser()
    nodes = parser.parse(str(file))

    requests = next(
        node for node in nodes
        if node.name == "requests"
    )

    packaging = next(
        node for node in nodes
        if node.name == "packaging"
    )

    assert requests.declared_version == "<3.0.0,>=2.32.0"
    assert requests.resolved_version is None

    assert packaging.declared_version == ">=23.0"
    assert packaging.resolved_version is None

    assert not any(node.name == "python" for node in nodes)

def test_python_parser_poetry_group(tmp_path):
    file = tmp_path / "pyproject.toml"

    file.write_text(
        """
[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
""",
        encoding="utf-8"
    )

    parser = PythonParser()
    nodes = parser.parse(str(file))

    pytest = next(
        node for node in nodes
        if node.name == "pytest"
    )

    assert pytest.scope == "dev"