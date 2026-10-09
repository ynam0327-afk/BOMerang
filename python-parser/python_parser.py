from packaging.version import Version
from pathlib import Path

from toml_parser import parse_pyproject

from dependency_node import DependencyNode
from requirement_parser import parse_requirement
from pypi_client import PyPIClient

# 중복 dependency 재탐색 & Node 정보 갱신 정책 -- 테스트&통합에서 문제 가능성 있음

_UNSET = object()
    # 버전 인자 전달 X vs 버전 조회: None
def make_purl(name: str, version: str | None = None) -> str:
    # PyPI package의 PURL을 생성
    normalized_name = name.lower().replace("_", "-")
    # PyPI 패키지에서는 처리할 기호 추가 예정

    if version:
        return f"pkg:pypi/{normalized_name}@{version}"

    return f"pkg:pypi/{normalized_name}"

class PythonParser:

    def __init__(self, pypi_client=None):
        self.pypi_client = pypi_client or PyPIClient()
        
    def supports(self, file_name: str) -> bool:
        return Path(file_name).name in {
        "requirements.txt",
        "pyproject.toml"
    }# 2차 : requirements.txt + toml 지원

    def parse(self, file_path: str) -> list[DependencyNode]:
        visited_files = set() # 파일 순환 참조 방지 (!= 패키지 순환)
        nodes = {} # 최종 DependencyNode 저장

        expanded_nodes = set()
        
        self._parse_file(
            Path(file_path).resolve(),
            visited_files,
            nodes,
            expanded_nodes
        )

        return list(nodes.values())

    def _parse_file(
        self,
        file_path: Path,
        visited_files: set,
        nodes: dict,
        expanded_nodes: set
    ):
        # 방문 참조 처리:이미 방문한 파일이면 다시 파싱하지 않는다.
        if file_path in visited_files:
            return

        visited_files.add(file_path)

        if file_path.name == "pyproject.toml":
            requirements = parse_pyproject(str(file_path))

            for requirement, scope in requirements:
                self._parse_package(
                    requirement,
                    file_path,
                    depth=1,
                    nodes=nodes,
                    recursion_stack=set(),
                    expanded_nodes=expanded_nodes,
                    scope=scope
                )
            return

        with file_path.open("r", encoding="utf-8") as file:
            for line in file:

                result = parse_requirement(line)

                if result is None:
                    continue

                result_type, value = result

                # 다른 requirements 파일 참조
                if result_type == "file":

                    referenced_file = (
                        file_path.parent / value
                    ).resolve() # 재귀적으로 파일을 읽고, 파일 순환 참조 방지

                    self._parse_file(
                        referenced_file,
                        visited_files,
                        nodes,
                        expanded_nodes
                    )

                # 패키지
                elif result_type == "package":

                    self._parse_package(
                        value,
                        file_path,
                        depth=1,
                        nodes=nodes,
                        recursion_stack=set(), # 패키지 재귀마다 전달
                        expanded_nodes=expanded_nodes
                    )

    def _parse_package(
        self,
        requirement,
        source_file: Path,
        depth: int,
        nodes: dict,
        recursion_stack: set,
        expanded_nodes: set,
        scope: str | None = None,
        resolved_version = _UNSET,
        resolution_error: RuntimeError | None = None
    ):
        name = requirement.name
        declared_version = self._get_declared_version(requirement)

        if resolved_version is _UNSET:
            if not requirement.specifier:
                resolved_version = None
            else:
                try:
                    resolved_version = self._resolve_version(requirement)
                except RuntimeError as e:
                    resolved_version = None # 다음 노드 생성 코드 진행 가능
                    resolution_error = e

        purl = make_purl(
            name,
            resolved_version
        )

        # 1. 이미 만들어진 Node인지 확인
        if purl in nodes:

            node = nodes[purl]

            # 더 얕은 depth로 발견되었다면 depth를 갱신한다.
            if depth < node.depth:
                node.depth = depth
        # 이외의 PURL 정보의 갱신은 1차에서 구현하지 않는다.

        # 2. 처음 발견한 패키지라면 Node 생성
        else:
            node = DependencyNode(
                name=name,
                ecosystem="pypi",
                declared_version=declared_version,
                resolved_version=resolved_version,
                purl=purl,
                depth=depth,
                scope=scope,
                source_file=source_file.name, # 1차 구현에서는 유지
                parse_status="success"
            )

            nodes[purl] = node

        # 버전 조회가 실패하더라도 패키지 정보 유지 -- 노드 기록
        if resolution_error is not None:
            node.parse_status = "error"
            node.error_message = str(resolution_error)
            return

        #3. 정확한 버전을 모르면 PyPI metadata를 조회하지 않는다.
        if resolved_version is None:
            return

        # 4. 현재 재귀 경로에서 이미 발견된 패키지인지 확인
        if purl in recursion_stack:

            node.is_circular = True

            return

        # 추가: 이미 하위 의존생 탐색을 완료한 패키지인가?
        if purl in expanded_nodes:
            return

        recursion_stack.add(purl) # finally: recursion_stack.remove(purl)

        try:
            # 5. PyPI에서 해당 패키지의 dependency 조회
            dependencies = self.pypi_client.get_dependencies(
                name,
                resolved_version
            )        

            for dependency in dependencies:
                # get_dependencies()가 반환한 의존성마다
                # 하위 의존성 버전 조회(1회)
                dependency_resolution_error = None

                try:
                    dependency_resolved_version = self._resolve_version(dependency)
                except RuntimeError as e:
                    dependency_resolved_version = None
                    dependency_resolution_error = e

                # 실제 선택된 버전 기준 PURL 생성
                dependency_purl = make_purl(
                dependency.name,
                dependency_resolved_version
                )

                # 현재 Node에 dependency PURL 추가
                if dependency_purl not in node.dependencies:
                    node.dependencies.append(dependency_purl)

                # 순환 참조 확인
                if dependency_purl in recursion_stack:
                    node.is_circular = True

                    if dependency_purl in nodes:
                        nodes[dependency_purl].is_circular = True
                    continue

                # 앞에서 조회한 버전을 재사용해 노드를 생성한다.
                self._parse_package(
                    dependency,
                    source_file,
                    depth + 1,
                    nodes,
                    recursion_stack,
                    expanded_nodes,
                    scope=scope,
                    resolved_version=dependency_resolved_version,
                    resolution_error=dependency_resolution_error
                )
        except RuntimeError as e:
            node.parse_status = "error"
            node.error_message = str(e)
            return # PyPI 오류 처리 추가
        
        finally:
            recursion_stack.remove(purl) # 재귀가 끝나면 스택에서 제거
            expanded_nodes.add(purl) # 하위 의존성 탐색 완료

    def _get_declared_version(self, requirement):

        if not requirement.specifier:
            return None

        return str(requirement.specifier)

    def _get_resolved_version(self, requirement):

        specifiers = list(requirement.specifier)

        if len(specifiers) == 1:

            specifier = specifiers[0]

            if specifier.operator == "==":
                return specifier.version

        return None

    def _resolve_version(self, requirement):
        # PyPI 후보 버전 중 requirement 조건 만족하는 버전 선택
        resolved_version = self._get_resolved_version(requirement)
        # 정확한 버전은 기존 로직 사용
        if resolved_version is not None:
            return resolved_version

        # 버전 조건이 없는 경우
        if not requirement.specifier:
            return None

        try:
            available_versions = self.pypi_client.get_available_versions(
                requirement.name
            )
        except RuntimeError:
            raise # 오류 삼키기 방지 -- UP

        candidates = []

        for version in available_versions:
            try:
                parsed_version = Version(version)

                if requirement.specifier.contains(
                    parsed_version,
                    prereleases=False
                ):
                    candidates.append(parsed_version)

            except Exception:
                continue

        if not candidates:
            return None

        return str(max(candidates)) # 버전 범위 중 가장 최신 버전