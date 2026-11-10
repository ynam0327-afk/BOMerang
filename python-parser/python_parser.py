from packaging.version import Version
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from pathlib import Path
import sys

from toml_parser import parse_pyproject, parse_pyproject_document, make_declaration

from dependency_node import DependencyNode
from requirement_parser import parse_requirement
from pypi_client import PyPIClient

# 중복 dependency 재탐색 & Node 정보 갱신 정책 -- 테스트&통합에서 문제 가능성 있음

_UNSET = object()
    # 버전 인자 전달 X vs 버전 조회: None
def make_purl(name: str, version: str | None = None) -> str:
    # PyPI package의 PURL을 생성
    normalized_name = canonicalize_name(name)
    # PyPI 패키지에서는 처리할 기호 추가 예정

    if version:
        return f"pkg:pypi/{normalized_name}@{version}"

    return f"pkg:pypi/{normalized_name}"

class PythonParser:

    def __init__(self, pypi_client=None):
        self.pypi_client = pypi_client or PyPIClient()
        self._available_versions_cache = {}
        self._declared_exact_versions = {}
        self.declarations = []
        self.declaration_errors = []
        self.declaration_packages = []
        # 확정 버전 저장 공간

    def _is_applicable(self, requirement) -> bool:
        """현재 실행 환경에서 적용되는 의존성인지 확인한다."""
        if requirement.marker is None:
            return True

        try:
            return requirement.marker.evaluate({"extra": ""})
        except Exception:
            return False  # Static extraction records the marker error.
    
    def supports(self, file_name: str) -> bool:
        return Path(file_name).name in {
        "requirements.txt",
        "pyproject.toml"
    }# 2차 : requirements.txt + toml 지원

    def _collect_declared_versions(
            self,
            file_path: Path,
            visited_files: set,
    ):
        file_path = file_path.resolve()
        if file_path in visited_files:
            return

        visited_files.add(file_path)

        if file_path.name == "pyproject.toml":
            requirements = parse_pyproject(str(file_path))

            for requirement, _scope in requirements:
                if not self._is_applicable(requirement):
                    continue

                version = self._get_resolved_version(requirement)

                if version is not None:
                    name = canonicalize_name(requirement.name)
                    self._declared_exact_versions.setdefault(name, set()).add(version)

            return

        with file_path.open("r", encoding="utf-8-sig") as files:
            for line in files:
                result = parse_requirement(line)

                if result is None:
                    continue

                result_type, value = result
                if result_type == "file":
                    referenced_file = (file_path.parent / value).resolve()

                    self._collect_declared_versions(
                        referenced_file,
                        visited_files,
                    )

                elif result_type == "package":
                    if not self._is_applicable(value):
                        continue
                    version = self._get_resolved_version(value)

                    if version is not None:
                        name = canonicalize_name(value.name)
                        self._declared_exact_versions.setdefault(name, set()).add(version)

    def parse(self, file_path: str) -> list[DependencyNode]:
        # Version lists belong to this analysis, including referenced files.
        self._available_versions_cache = {}
        self._declared_exact_versions = {}
        self.declarations = []
        self.declaration_errors = []
        self.declaration_packages = []

        self._collect_declared_versions(
            Path(file_path).resolve(),
            set()
        )
       
        visited_files = set() # 파일 순환 참조 방지 (!= 패키지 순환)
        nodes = {} # 최종 DependencyNode 저장
        expanded_nodes = set()
        
        self._parse_file(
            Path(file_path).resolve(),
            visited_files,
            nodes,
            expanded_nodes
        )

        self._merge_unresolved_nodes(nodes)
        self._finalize_declarations(nodes)

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
            document = parse_pyproject_document(str(file_path))
            self.declarations.extend(document["declarations"])
            self.declaration_errors.extend(document["errors"])
            requirements = parse_pyproject(str(file_path))

            for requirement, scope in requirements:
                if not self._is_applicable(requirement):
                    continue

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

        with file_path.open("r", encoding="utf-8-sig") as file:
            for line_number, line in enumerate(file, 1):

                result = parse_requirement(line)

                if result is None:
                    raw = line.strip()
                    if raw and not raw.startswith(("#", "-")):
                        try:
                            make_declaration(raw, None, file_path, f"line:{line_number}", kind="requirements")
                        except Exception as exc:
                            self.declaration_errors.append({
                                "source_file": str(file_path), "source_locator": f"line:{line_number}",
                                "raw_declaration": raw, "category": "invalid_requirement",
                                "marker_status": "error" if ";" in raw else None,
                                "message": str(exc)})
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
                    declaration = make_declaration(
                        line.strip(), None, file_path, f"line:{line_number}", kind="requirements")
                    self.declarations.append(declaration)
                    if not declaration["active_in_graph"]:
                        continue

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

        # 같은 패키지라도 선택한 extras가 다르면 추가 탐색
        expansion_key = (
            purl,
            frozenset(requirement.extras)
        )

        if expansion_key in expanded_nodes:
            return

        recursion_stack.add(purl) # finally: recursion_stack.remove(purl)

        try:
            # 5. PyPI에서 해당 패키지의 dependency 조회
            print(f"[DEBUG] 의존성 조회: {name}=={resolved_version}", file=sys.stderr,flush=True)
            
            dependencies = self.pypi_client.get_dependencies(
                name,
                resolved_version,
                extras=set(requirement.extras)
            )        

            for dependency in dependencies:
                # PyPIClient.get_dependencies()에서 이미
                # Environment Marker와 extras 조건을 평가했으므로
                # 여기서 다시 필터링하지 않는다.
                dependency_resolution_error = None

                try:
                    dependency_resolved_version, dependency_resolution_error = (
                        self._resolve_transitive_version(dependency)
                    )
                except RuntimeError as e:
                    dependency_resolved_version = None
                    dependency_resolution_error = e

                # 실제 선택된 버전 기준 PURL 생성
                dependency_purl = make_purl(
                    dependency.name,
                    dependency_resolved_version,
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
            expanded_nodes.add(expansion_key)

    # 후처리 함수 - 버전 없는 노드를 확정 버전 노드와 통합(안전할때만)
    def _merge_unresolved_nodes(self, nodes):
    
        versioned_by_name = {}
            # 패키지 이름별로 확인된 버전을 수집한다.
        for purl, node in nodes.items():
            if node.resolved_version is None:
                continue

            name = canonicalize_name(node.name)
            versioned_by_name.setdefault(name, {})[
                    node.resolved_version
            ] = purl
        
        remap = {}

        # 같은 이름의 확정 버전이 하나뿐인 경우에만 통합 후보로 등록한다.
        for purl, node in nodes.items():
            if node.resolved_version is not None:
                continue
            name = canonicalize_name(node.name)
            candidates = versioned_by_name.get(name, {})

            if len(candidates) != 1:
                continue

            version, target_purl = next(iter(candidates.items()))

            # 기존 버전 조건이 있다면 후보 버전이 조건을 만족해야 한다.
            if node.declared_version:
                try:
                    if not SpecifierSet(node.declared_version).contains(
                        Version(version),
                        prereleases=False,
                    ):
                        continue
                except Exception:
                    continue

            remap[purl] = target_purl
        if not remap:
            return

        # 모든 노드의 의존성 참조를 새 PURL로 변경한다.
        for node in nodes.values():
            node.dependencies = list(dict.fromkeys(
                remap.get(dep, dep)
                for dep in node.dependencies
            ))

        # 기존 노드의 일부 정보도 대상 노드에 반영한다.
        for old_purl, target_purl in remap.items():
            old_node = nodes[old_purl]
            target_node = nodes[target_purl]

            target_node.depth = min(
                target_node.depth,
                old_node.depth,
            )
            target_node.dependencies = list(dict.fromkeys(
                target_node.dependencies + old_node.dependencies
            ))
            target_node.is_circular = (
                target_node.is_circular or old_node.is_circular
            )
            del nodes[old_purl]


    def _finalize_declarations(self, nodes):
        """Link observed graph versions without resolving optional/static entries."""
        from packaging.requirements import Requirement
        from packaging.utils import canonicalize_name
        packages = {}
        for node in nodes.values():
            node.declarations = []
        for declaration in self.declarations:
            req = Requirement(declaration["requirement"])
            version = self._get_resolved_version(req)
            candidates = [node for node in nodes.values()
                          if canonicalize_name(node.name) == declaration["name"]
                          and node.resolved_version is not None
                          and (not req.specifier or req.specifier.contains(node.resolved_version))]
            if version is None and declaration["active_in_graph"] and len(candidates) == 1:
                version = candidates[0].resolved_version
            declaration["resolved_version"] = version
            declaration["version_status"] = (
                "unresolved" if version is None else
                "confirmed" if self._get_resolved_version(req) is not None else "estimated")
            declaration["purl"] = make_purl(declaration["name"], version)
            purl = declaration["purl"]
            package = packages.setdefault(purl, {
                "name": declaration["name"], "ecosystem": "pypi", "purl": purl,
                "declared_version": declaration["declared_version"],
                "resolved_version": version, "version_status": declaration["version_status"],
                "depth": 1, "dependencies": [], "declarations": [], "source_files": [],
                "scope": declaration["scope"], "parse_status": "success",
                "usage_status": "declaration_inventory_not_installed_graph",
            })
            package["declarations"].append(declaration)
            if declaration["source_file"] not in package["source_files"]:
                package["source_files"].append(declaration["source_file"])
            if purl in nodes:
                nodes[purl].declarations.append(declaration)
        self.declaration_packages = list(packages.values())

    def _get_declared_version(self, requirement):

        if not requirement.specifier:
            return None

        return str(requirement.specifier)

    def _get_resolved_version(self, requirement):

        specifiers = list(requirement.specifier)

        if len(specifiers) == 1:

            specifier = specifiers[0]

            if specifier.operator == "==" and not specifier.version.endswith(".*") :
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
            name = canonicalize_name(requirement.name)
            if name not in self._available_versions_cache:
                # Store only successful lookups; exceptions remain retryable.
                self._available_versions_cache[name] = (
                    self.pypi_client.get_available_versions(requirement.name)
                )
            available_versions = self._available_versions_cache[name]
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

    def _resolve_transitive_version(self, requirement):
        name = canonicalize_name(requirement.name)
        pinned_versions = self._declared_exact_versions.get(name, set())

        # 직접 의존성의 정확한 버전이 없으면 기존 로직 사용
        if not pinned_versions:
            try:
                return self._resolve_version(requirement), None
            except RuntimeError as exc:
                return None, str(exc)

        # 하위 의존성에 버전 조건이 없으면
        # 직접 의존성의 버전을 재사용한다.
        if not requirement.specifier:
            return max(pinned_versions, key=Version), None

        # 직접 의존성의 버전 중 조건을 만족하는 버전만 선택
        compatible_versions = [
            version
            for version in pinned_versions
            if requirement.specifier.contains(
                Version(version),
                prereleases=False,
            )
        ]

        # 조건을 만족하는 버전이 없으면 충돌 처리
        if not compatible_versions:
            versions = ", ".join(sorted(pinned_versions))
            return None, (
                f"No compatible direct dependency version for "
                f"{name}: {versions}, required {requirement.specifier}"
            )

        # 호환되는 버전 중 가장 최신 버전 선택
        return max(compatible_versions, key=Version), None