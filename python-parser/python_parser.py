from packaging.version import Version
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from pathlib import Path
import sys

from toml_parser import parse_pyproject, parse_pyproject_document, make_declaration

from dependency_node import DependencyNode
from requirement_parser import parse_requirement, iter_requirement_lines
from pypi_client import PyPIClient

# 중복 dependency 재탐색 & Node 정보 갱신 정책 -- 테스트&통합에서 문제 가능성 있음

_UNSET = object()


def _satisfies(specifiers, version):
    # Explicit prerelease bounds opt in; an unspecified policy keeps releases only.
    return specifiers.contains(version, prereleases=bool(specifiers.prereleases))
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
        self._declared_version_sources = {}
        self.dependency_conflicts = []
        self.declarations = []
        self.declaration_errors = []
        self.declaration_packages = []
        self._constraints = {}
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
            constraint=False,
    ):
        file_path = file_path.resolve()
        key = (file_path, constraint)
        if key in visited_files:
            return

        visited_files.add(key)

        if file_path.name == "pyproject.toml":
            requirements = parse_pyproject(str(file_path))

            for requirement, _scope in requirements:
                if not self._is_applicable(requirement):
                    continue

                version = self._get_resolved_version(requirement)

                if version is not None:
                    name = canonicalize_name(requirement.name)
                    self._declared_exact_versions.setdefault(name, set()).add(version)
                    self._declared_version_sources.setdefault(name, {}).setdefault(version, set()).add(str(file_path))

            return

        with file_path.open("r", encoding="utf-8-sig") as files:
            for _line_number, line in iter_requirement_lines(files):
                result = parse_requirement(line)

                if result is None:
                    continue

                result_type, value = result
                if result_type in {"file", "constraint"}:
                    referenced_file = (file_path.parent / value).resolve()

                    self._collect_declared_versions(
                        referenced_file,
                        visited_files,
                        constraint=constraint or result_type == "constraint",
                    )

                elif result_type == "package":
                    if not self._is_applicable(value):
                        continue
                    if constraint:
                        self._constraints.setdefault(canonicalize_name(value.name), []).append(value)
                        continue
                    version = self._get_resolved_version(value)

                    if version is not None:
                        name = canonicalize_name(value.name)
                        self._declared_exact_versions.setdefault(name, set()).add(version)
                        self._declared_version_sources.setdefault(name, {}).setdefault(version, set()).add(str(file_path))

    def parse(self, file_path: str, *, project_files=None) -> list[DependencyNode]:
        # Version lists belong to this analysis, including referenced files.
        self._available_versions_cache = {}
        self._declared_exact_versions = {}
        self._declared_version_sources = {}
        self.dependency_conflicts = []
        self.declarations = []
        self.declaration_errors = []
        self.declaration_packages = []
        self._constraints = {}

        # All inputs selected by one integrated analysis share direct pins.
        # Only constraints are collected here; graph traversal remains per file.
        collected_files = set()
        for direct_file in [file_path, *(project_files or [])]:
            self._collect_declared_versions(Path(direct_file).resolve(), collected_files)
       
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
        self._recompute_graph_metadata(nodes)
        self._apply_dependency_conflicts(nodes)
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
            for line_number, line in iter_requirement_lines(file):

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
                        line.strip(), None, file_path, f"line:{line_number}", kind="requirements",
                        resolved_source=str(file_path), requirement=value)
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
        resolution_error: RuntimeError | str | None = None,
        requiring_purl: str | None = None
    ):
        name = requirement.name
        declared_version = self._get_declared_version(requirement)

        if resolved_version is _UNSET:
            if (not requirement.specifier
                    and canonicalize_name(name) not in self._declared_exact_versions
                    and canonicalize_name(name) not in self._constraints):
                resolved_version = None
            else:
                try:
                    if (not requirement.url and self._get_resolved_version(requirement) is None
                            and canonicalize_name(name) in self._declared_exact_versions):
                        resolved_version, resolution_error = self._resolve_transitive_version(requirement)
                    else:
                        resolved_version = self._resolve_version(requirement)
                except RuntimeError as e:
                    resolved_version = None # 다음 노드 생성 코드 진행 가능
                    resolution_error = e

        conflict = self._direct_pin_conflict(requirement, source_file, requiring_purl)
        if conflict is not None and conflict not in self.dependency_conflicts:
            self.dependency_conflicts.append(conflict)

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

        context = {"requirement": str(requirement), "declared_version": declared_version,
                   "marker": str(requirement.marker) if requirement.marker else None,
                   "extras": sorted(canonicalize_name(extra) for extra in requirement.extras),
                   "scope": scope, "source_file": str(source_file.resolve()),
                   "requiring_purl": requiring_purl}
        if context not in node.requirement_contexts:
            node.requirement_contexts.append(context)
        for attribute, values in (("scopes", [scope or "runtime"]),
                                  ("declared_versions", [declared_version] if declared_version else []),
                                  ("markers", [context["marker"]] if context["marker"] else []),
                                  ("extras", context["extras"]),
                                  ("source_files", [context["source_file"]])):
            setattr(node, attribute, sorted(set(getattr(node, attribute)) | set(values)))

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

            diagnostics = getattr(self.pypi_client, "get_dependency_diagnostics", None)
            if diagnostics:
                for diagnostic in diagnostics(name, resolved_version):
                    error = dict(diagnostic, source_file=str(source_file.resolve()),
                                 requiring_purl=purl, category="invalid_dependency_metadata")
                    if error not in node.metadata_errors:
                        node.metadata_errors.append(error)
                    if error not in self.declaration_errors:
                        self.declaration_errors.append(error)
                if node.metadata_errors:
                    node.parse_status = "error"
                    node.error_message = "Invalid PyPI dependency metadata; see metadata_errors"

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
                    resolution_error=dependency_resolution_error,
                    requiring_purl=purl
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
            if node.parse_status == "error":
                continue
            name = canonicalize_name(node.name)
            candidates = versioned_by_name.get(name, {})

            if len(candidates) != 1:
                continue

            version, target_purl = next(iter(candidates.items()))

            # 기존 버전 조건이 있다면 후보 버전이 조건을 만족해야 한다.
            if any(context.get("requirement", "").find(" @ ") >= 0
                   for context in node.requirement_contexts):
                continue
            versions = set(node.declared_versions)
            if node.declared_version:
                versions.add(node.declared_version)
            if versions:
                try:
                    if not all(_satisfies(SpecifierSet(specifier), Version(version))
                               for specifier in versions):
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
            for attribute in ("scopes", "extras", "markers", "declared_versions", "source_files"):
                setattr(target_node, attribute, sorted(set(getattr(target_node, attribute)) |
                                                       set(getattr(old_node, attribute))))
            for context in old_node.requirement_contexts:
                if context not in target_node.requirement_contexts:
                    target_node.requirement_contexts.append(context)
            del nodes[old_purl]

    def _recompute_graph_metadata(self, nodes):
        """Shortest paths and scopes must propagate after all direct roots exist."""
        from collections import deque
        queue = deque(node for node in nodes.values() if node.depth == 1)
        distances = {node.purl: 1 for node in queue}
        while queue:
            node = queue.popleft()
            for purl in node.dependencies:
                if purl not in nodes:
                    continue
                child = nodes[purl]
                distance = distances[node.purl] + 1
                scopes = sorted(set(child.scopes) | set(node.scopes))
                changed = scopes != child.scopes
                child.scopes = scopes
                if distance < distances.get(purl, float("inf")):
                    distances[purl] = distance
                    changed = True
                if changed:
                    queue.append(child)
        for purl, node in nodes.items():
            node.depth = distances.get(purl, node.depth)
            if node.scope is not None and "runtime" in node.scopes:
                node.scope = "runtime"


    def _direct_pin_conflict(self, requirement, source_file, requiring_purl):
        name = canonicalize_name(requirement.name)
        versions = sorted(self._declared_exact_versions.get(name, set()), key=Version)
        if not versions:
            return None
        if len(versions) > 1:
            reason = "multiple_direct_pins"
        elif requirement.specifier and not _satisfies(requirement.specifier, Version(versions[0])):
            reason = "incompatible_direct_pin"
        elif name in self._constraints and not _satisfies(self._constrained_requirement(requirement).specifier, Version(versions[0])):
            reason = "incompatible_constraint"
        else:
            return None
        return {
            "required_package": name,
            "required_specifier": str(requirement.specifier) or None,
            "requiring_purl": requiring_purl,
            "selected_version": None,
            "direct_versions": versions,
            "reason": reason,
            "source_file": str(source_file.resolve()),
            "direct_sources": [
                {"version": version, "source_file": source}
                for version in versions
                for source in sorted(self._declared_version_sources.get(name, {}).get(version, set()))
            ],
        }

    def _apply_dependency_conflicts(self, nodes):
        for node in nodes.values():
            node.dependency_conflicts = [
                conflict for conflict in self.dependency_conflicts
                if canonicalize_name(node.name) == conflict["required_package"]
                or node.purl == conflict["requiring_purl"]
            ]
            if node.dependency_conflicts:
                node.graph_resolution_status = "dependency_conflict"

    def _finalize_declarations(self, nodes):
        """Link observed graph versions without resolving optional/static entries."""
        from packaging.requirements import Requirement
        from packaging.utils import canonicalize_name
        packages = {}
        versioned_by_name = {}
        for node in nodes.values():
            node.declarations = []
            if node.resolved_version is not None:
                versioned_by_name.setdefault(canonicalize_name(node.name), []).append(node)
        for declaration in self.declarations:
            req = Requirement(declaration["requirement"])
            version = self._get_resolved_version(req)
            candidates = [node for node in versioned_by_name.get(declaration["name"], [])
                          if not req.specifier or _satisfies(req.specifier, node.resolved_version)]
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
            if purl in nodes and declaration["active_in_graph"]:
                package["dependency_conflicts"] = list(nodes[purl].dependency_conflicts)
                package["graph_resolution_status"] = nodes[purl].graph_resolution_status
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
        original = requirement
        requirement = self._constrained_requirement(requirement)
        resolved_version = self._get_resolved_version(requirement)
        # 정확한 버전은 기존 로직 사용
        if resolved_version is not None:
            if not _satisfies(requirement.specifier, resolved_version):
                raise RuntimeError(f"Incompatible constraints for {original}")
            return resolved_version

        exact = self._get_resolved_version(original)
        if exact is not None:
            if not _satisfies(requirement.specifier, exact):
                raise RuntimeError(f"Incompatible constraints for {original}")
            return exact

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

                if _satisfies(requirement.specifier, parsed_version):
                    candidates.append(parsed_version)

            except Exception:
                continue

        if not candidates:
            return None

        return str(max(candidates)) # 버전 범위 중 가장 최신 버전

    def _resolve_transitive_version(self, requirement):
        requirement = self._constrained_requirement(requirement)
        name = canonicalize_name(requirement.name)
        pinned_versions = self._declared_exact_versions.get(name, set())

        if not pinned_versions:
            try:
                return self._resolve_version(requirement), None
            except RuntimeError as exc:
                return None, str(exc)

        if len(pinned_versions) > 1:
            versions = ", ".join(sorted(pinned_versions, key=Version))
            return None, f"Multiple direct dependency versions for {name}: {versions}"

        version = next(iter(pinned_versions))
        if not requirement.specifier or _satisfies(requirement.specifier, Version(version)):
            return version, None

        # Preserve the direct node and the unresolved requirement separately.
        return None, (
            f"No compatible direct dependency version for "
            f"{name}: {version}, required {requirement.specifier}"
        )

    def _constrained_requirement(self, requirement):
        from packaging.requirements import Requirement
        constraints = self._constraints.get(canonicalize_name(requirement.name), [])
        if not constraints or requirement.url:
            return requirement
        result = Requirement(str(requirement))
        for constraint in constraints:
            result.specifier &= constraint.specifier
        return result
