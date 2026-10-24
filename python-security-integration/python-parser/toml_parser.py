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