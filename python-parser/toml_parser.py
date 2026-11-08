import tomllib
from pathlib import Path
from packaging.requirements import Requirement


def _parse_poetry_dependency(name: str, version: str) -> Requirement | None:
    """
    Poetry dependency의 버전 표현을 PEP 508 Requirement로 변환한다.
    """

    if version == "*":
        return Requirement(name)

    if version.startswith("^"):
        version = version[1:]
        parts = version.split(".")

        major = int(parts[0])

        if major > 0:
            upper = f"{major + 1}.0.0"
        elif len(parts) > 1 and int(parts[1]) > 0:
            upper = f"0.{int(parts[1]) + 1}.0"
        else:
            upper = f"0.0.{int(parts[2]) + 1}"

        return Requirement(f"{name}>={version},<{upper}")

    return Requirement(f"{name}{version}")


def parse_pyproject(file_path: str) -> list[tuple[Requirement, str]]:
    """
    pyproject.toml의 의존성을 파싱한다.

    지원 범위:
    - PEP 621 [project].dependencies
    - Poetry [tool.poetry.dependencies]
    - Poetry [tool.poetry.group.*.dependencies]
    """

    path = Path(file_path)

    with path.open("rb") as file:
        data = tomllib.load(file)

    requirements = []

    # PEP 621
    project = data.get("project", {})
    dependencies = project.get("dependencies", [])

    if isinstance(dependencies, list):
        for dependency in dependencies:
            if not isinstance(dependency, str):
                continue

            try:
                requirements.append(
                    (Requirement(dependency), "runtime")
                )
            except Exception:
                continue

    # Poetry
    poetry = data.get("tool", {}).get("poetry", {})

    # Poetry 기본 dependency
    poetry_dependencies = poetry.get("dependencies", {})

    if isinstance(poetry_dependencies, dict):
        for name, version in poetry_dependencies.items():

            if name.lower() == "python":
                continue

            if not isinstance(version, str):
                continue

            try:
                requirement = _parse_poetry_dependency(name, version)

                if requirement:
                    requirements.append(
                        (requirement, "runtime")
                    )
            except Exception:
                continue

    # Poetry dependency groups
    groups = poetry.get("group", {})

    if isinstance(groups, dict):
        for scope, group in groups.items():

            if not isinstance(group, dict):
                continue

            dependencies = group.get("dependencies", {})

            if not isinstance(dependencies, dict):
                continue

            for name, version in dependencies.items():

                if name.lower() == "python":
                    continue

                if not isinstance(version, str):
                    continue

                try:
                    requirement = _parse_poetry_dependency(
                        name,
                        version
                    )

                    if requirement:
                        requirements.append(
                            (requirement, scope)
                        )
                except Exception:
                    continue

    return requirements

# Additive static-declaration API. parse_pyproject above retains its graph contract.
def make_declaration(raw, scope, source_file, locator, *, kind="runtime",
                     group=None, optional=False, graph_enabled=True,
                     include_path=(), origin_group=None, requirement=None):
    import hashlib
    import json
    from packaging.utils import canonicalize_name
    req = requirement if requirement is not None else Requirement(raw)
    try:
        active = req.marker is None or req.marker.evaluate({"extra": ""})
        status, marker_error = ("active" if active else "inactive"), None
    except Exception as exc:
        active, status, marker_error = None, "error", str(exc)
    marker_raw = None
    if req.marker is not None:
        from packaging.markers import Marker
        for index, char in enumerate(raw):
            if char != ";":
                continue
            candidate = raw[index + 1:].strip()
            try:
                if str(Marker(candidate)) == str(req.marker):
                    marker_raw = candidate
                    break
            except Exception:
                continue
    source = str(Path(source_file).resolve())
    key = json.dumps([source, locator, scope, list(include_path)], ensure_ascii=True)
    return {
        "declaration_id": hashlib.sha256(key.encode()).hexdigest(),
        "raw_declaration": raw, "requirement": str(req),
        "name": canonicalize_name(req.name), "original_name": req.name,
        "ecosystem": "pypi", "declared_version": str(req.specifier) or None,
        "extras": sorted(canonicalize_name(extra) for extra in req.extras),
        "scope": scope, "dependency_group": group, "optional": optional,
        "declaration_kind": kind, "source_file": source, "source_locator": locator,
        "origin_group": origin_group, "include_path": list(include_path),
        "marker": str(req.marker) if req.marker else None,
        "marker_raw": marker_raw,
        "marker_active": active, "marker_status": status, "marker_error": marker_error,
        "graph_enabled": graph_enabled,
        "active_in_graph": graph_enabled and active is True,
        "usage_status": "declared_not_installation_verified",
        "resolved_version": None, "version_status": "unresolved",
        "parse_status": "success" if marker_error is None else "error",
    }


def parse_pyproject_document(file_path):
    """All static declarations plus diagnostics; never activates optional groups."""
    import re
    from packaging.utils import canonicalize_name
    path = Path(file_path)
    with path.open("rb") as stream:
        data = tomllib.load(stream)
    declarations, errors = [], []

    def error(locator, raw, message, category="invalid_declaration"):
        errors.append({"source_file": str(path.resolve()), "source_locator": locator,
                       "raw_declaration": raw, "category": category, "message": message,
                       "marker_status": "error" if category == "invalid_marker" else None})

    def add(raw, scope, locator, **metadata):
        if not isinstance(raw, str):
            error(locator, raw, "Dependency must be a PEP 508 string")
            return
        try:
            declaration = make_declaration(raw, scope, path, locator, **metadata)
            declarations.append(declaration)
            if declaration["marker_error"]:
                error(locator, raw, declaration["marker_error"], "invalid_marker")
        except Exception as exc:
            error(locator, raw, str(exc), "invalid_marker" if ";" in raw else "invalid_requirement")

    project = data.get("project", {})
    runtime = project.get("dependencies", [])
    if isinstance(runtime, list):
        for index, raw in enumerate(runtime):
            add(raw, "runtime", f"project.dependencies[{index}]")
    else:
        error("project.dependencies", runtime, "dependencies must be an array")

    def group_names(groups, locator):
        if not isinstance(groups, dict):
            error(locator, groups, "groups must be a table")
            return {}, set()
        names, collisions = {}, set()
        for name in groups:
            normalized = canonicalize_name(name)
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name):
                error(locator + "." + name, name, "Invalid group name")
                collisions.add(normalized)
            if normalized in names:
                collisions.add(normalized)
                error(locator + "." + name, name, "Normalized group name collision")
            names[normalized] = name
        return names, collisions

    optional = project.get("optional-dependencies", {})
    names, collisions = group_names(optional, "project.optional-dependencies")
    for normalized, name in names.items():
        if normalized in collisions:
            continue
        entries = optional[name]
        locator = "project.optional-dependencies." + name
        if not isinstance(entries, list):
            error(locator, entries, "Optional group must be an array")
            continue
        for index, raw in enumerate(entries):
            add(raw, "optional:" + name, f"{locator}[{index}]", kind="optional",
                group=name, optional=True, graph_enabled=False)

    groups = data.get("dependency-groups", {})
    names, collisions = group_names(groups, "dependency-groups")

    def expand(name, target, stack, include_path):
        normalized = canonicalize_name(name)
        locator = "dependency-groups." + name
        if normalized in stack:
            error(locator, list(include_path), "Circular include-group reference", "group_cycle")
            return
        if len(stack) >= 100:
            error(locator, list(include_path), "include-group depth exceeds 100", "group_depth")
            return
        entries = groups[name]
        if not isinstance(entries, list):
            error(locator, entries, "PEP 735 group must be an array")
            return
        for index, raw in enumerate(entries):
            entry_locator = f"{locator}[{index}]"
            if isinstance(raw, str):
                add(raw, target, entry_locator, kind="dependency_group", group=target,
                    graph_enabled=False, include_path=include_path, origin_group=name)
            elif isinstance(raw, dict) and set(raw) == {"include-group"} and isinstance(raw["include-group"], str):
                requested = canonicalize_name(raw["include-group"])
                if requested not in names:
                    error(entry_locator, raw, "Unknown include-group target", "unknown_group")
                elif requested in collisions:
                    error(entry_locator, raw, "Ambiguous include-group target", "invalid_group")
                else:
                    expand(names[requested], target, stack + (normalized,),
                           include_path + (entry_locator,))
            else:
                error(entry_locator, raw,
                      "PEP 735 supports strings or a single include-group string; extension objects are unsupported",
                      "unsupported_group_entry")

    for normalized, name in names.items():
        if normalized not in collisions:
            expand(name, name, (), ())

    # Reuse the established Poetry conversion, retaining source keys and values.
    poetry = data.get("tool", {}).get("poetry", {})
    poetry_sets = [("runtime", poetry.get("dependencies", {}), "tool.poetry.dependencies")]
    for name, group in poetry.get("group", {}).items():
        if isinstance(group, dict):
            poetry_sets.append((name, group.get("dependencies", {}), f"tool.poetry.group.{name}.dependencies"))
    for scope, dependencies, locator in poetry_sets:
        if not isinstance(dependencies, dict):
            error(locator, dependencies, "Poetry dependencies must be a table")
            continue
        for name, version in dependencies.items():
            if name.lower() == "python":
                continue
            if not isinstance(version, str):
                error(locator + "." + name, version, "Poetry table dependencies are not supported")
                continue
            try:
                req = _parse_poetry_dependency(name, version)
                declaration = make_declaration(
                    version, scope, path, locator + "." + name, kind="poetry",
                    group=None if scope == "runtime" else scope, requirement=req)
                declaration["original_key"] = name
                declarations.append(declaration)
            except Exception as exc:
                error(locator + "." + name, version, str(exc))
    return {"declarations": declarations, "errors": errors}
