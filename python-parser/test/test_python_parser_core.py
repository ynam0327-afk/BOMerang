from packaging.requirements import Requirement

from python_parser import PythonParser, make_purl


class FakePyPIClient:
    """
    실제 PyPI API에 접속 아님
    테스트용 dependency 정보를 반환하는 가짜 PyPI Client
    """

    def __init__(self, dependency_map):
        self.dependency_map = dependency_map
        self.call_count = {}

    def get_dependencies(self, package_name, version):
        key = (package_name.lower(), version)

        self.call_count[key] = self.call_count.get(key, 0) + 1

        return self.dependency_map.get(key, [])

# 1. requirements.txt만 지원하는가?
def test_supports_requirements_txt():
    parser = PythonParser(
        pypi_client=FakePyPIClient({})
    )

    assert parser.supports("requirements.txt")
    assert not parser.supports("pom.xml")
    assert not parser.supports("build.gradle")

# 2. PyPI 규칙에 따라 purl을 만드는가?
def test_make_purl():
    assert make_purl("requests", "2.32.5") == \
        "pkg:pypi/requests@2.32.5"

    assert make_purl("my_package", "1.0.0") == \
        "pkg:pypi/my-package@1.0.0"

    assert make_purl("requests") == \
        "pkg:pypi/requests"

# 3. 정확한 버전이 주어질 때
def test_exact_version_is_resolved(tmp_path):
    requirements = tmp_path / "requirements.txt"

    requirements.write_text(
        "requests==2.32.5\n",
        encoding="utf-8"
    )

    fake_client = FakePyPIClient({
        ("requests", "2.32.5"): []
    })

    parser = PythonParser(fake_client)

    nodes = parser.parse(str(requirements))

    assert len(nodes) == 1

    node = nodes[0]

    assert node.name == "requests"
    assert node.declared_version == "==2.32.5"
    assert node.resolved_version == "2.32.5"
    assert node.purl == "pkg:pypi/requests@2.32.5"

# 4. 버전 범위만 주어질 때
def test_version_range_is_not_resolved(tmp_path):
    requirements = tmp_path / "requirements.txt"

    requirements.write_text(
        "requests>=2.0,<3.0\n",
        encoding="utf-8"
    )

    fake_client = FakePyPIClient({})

    parser = PythonParser(fake_client)

    nodes = parser.parse(str(requirements))

    assert len(nodes) == 1

    node = nodes[0]

    assert node.name == "requests"
    assert node.declared_version == "<3.0,>=2.0"
    # requirements.txt의 원문 그대로 보존해야할지에 대해 결정 필요
    assert node.resolved_version is None
    assert node.purl == "pkg:pypi/requests"

    assert fake_client.call_count == {}

# 5. 버전이 없다면?
def test_package_without_version_is_unresolved(tmp_path):
    requirements = tmp_path / "requirements.txt"

    requirements.write_text(
        "requests\n",
        encoding="utf-8"
    )

    fake_client = FakePyPIClient({})

    parser = PythonParser(fake_client)

    nodes = parser.parse(str(requirements))

    assert len(nodes) == 1

    node = nodes[0]

    assert node.name == "requests"
    assert node.declared_version is None
    assert node.resolved_version is None
    assert node.purl == "pkg:pypi/requests"

    assert fake_client.call_count == {}

# 6. 파일 참조 = -r 재귀 처리
def test_requirements_file_reference(tmp_path):
    base = tmp_path / "base.txt"
    root = tmp_path / "requirements.txt"

    base.write_text(
        "requests==2.32.5\n",
        encoding="utf-8"
    )

    root.write_text(
        "-r base.txt\n",
        encoding="utf-8"
    )

    fake_client = FakePyPIClient({
        ("requests", "2.32.5"): []
    })

    parser = PythonParser(fake_client)

    nodes = parser.parse(str(root))

    assert len(nodes) == 1
    assert nodes[0].name == "requests"
    assert nodes[0].resolved_version == "2.32.5"

# 7. 전이 의존성 = PyPI metadata 기반 재귀
def test_transitive_dependency_is_parsed(tmp_path):
    requirements = tmp_path / "requirements.txt"

    requirements.write_text(
        "requests==2.32.5\n",
        encoding="utf-8"
    )

    fake_client = FakePyPIClient({
        ("requests", "2.32.5"): [
            Requirement("urllib3==2.2.1")
        ],
        ("urllib3", "2.2.1"): []
    })

    parser = PythonParser(fake_client)

    nodes = parser.parse(str(requirements))

    node_map = {
        node.purl: node
        for node in nodes
    }

    assert "pkg:pypi/requests@2.32.5" in node_map
    assert "pkg:pypi/urllib3@2.2.1" in node_map

# 8. depth와 dependency 연결(PURL reference)
def test_depth_and_dependency_reference(tmp_path):
    requirements = tmp_path / "requirements.txt"

    requirements.write_text(
        "requests==2.32.5\n",
        encoding="utf-8"
    )

    fake_client = FakePyPIClient({
        ("requests", "2.32.5"): [
            Requirement("urllib3==2.2.1")
        ],
        ("urllib3", "2.2.1"): []
    })

    parser = PythonParser(fake_client)

    nodes = parser.parse(str(requirements))

    node_map = {
        node.purl: node
        for node in nodes
    }

    requests_node = node_map[
        "pkg:pypi/requests@2.32.5"
    ]

    urllib3_node = node_map[
        "pkg:pypi/urllib3@2.2.1"
    ]

    assert requests_node.depth == 1
    assert urllib3_node.depth == 2

    assert requests_node.dependencies == [
        "pkg:pypi/urllib3@2.2.1"
    ]

# 9. 중복 탐색 방지(expanded_nodes)
def test_duplicate_dependency_is_expanded_only_once(tmp_path):
    requirements = tmp_path / "requirements.txt"

    requirements.write_text(
        "requests==2.32.5\n"
        "flask==3.0.0\n",
        encoding="utf-8"
    )

    fake_client = FakePyPIClient({
        ("requests", "2.32.5"): [
            Requirement("urllib3==2.2.1")
        ],
        ("flask", "3.0.0"): [
            Requirement("urllib3==2.2.1")
        ],
        ("urllib3", "2.2.1"): []
    })

    parser = PythonParser(fake_client)

    nodes = parser.parse(str(requirements))

    node_map = {
        node.purl: node
        for node in nodes
    }

    assert "pkg:pypi/urllib3@2.2.1" in node_map

    assert fake_client.call_count[
        ("urllib3", "2.2.1")
    ] == 1

# 10. 순환 의존성, package cycle 감지
def test_circular_dependency_is_detected(tmp_path):
    requirements = tmp_path / "requirements.txt"

    requirements.write_text(
        "package-a==1.0.0\n",
        encoding="utf-8"
    )

    fake_client = FakePyPIClient({
        ("package-a", "1.0.0"): [
            Requirement("package-b==1.0.0")
        ],
        ("package-b", "1.0.0"): [
            Requirement("package-a==1.0.0")
        ]
    })

    parser = PythonParser(fake_client)

    nodes = parser.parse(str(requirements))

    node_map = {
        node.purl: node
        for node in nodes
    }

    package_a = node_map[
        "pkg:pypi/package-a@1.0.0"
    ]

    package_b = node_map[
        "pkg:pypi/package-b@1.0.0"
    ]

    assert package_a.is_circular is True
    assert package_b.is_circular is True