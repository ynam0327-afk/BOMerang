import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from packaging.requirements import Requirement


class PyPIClient:
    BASE_URL = "https://pypi.org/pypi"
    # HTTP 요청을 위해 라이브러리를 사용하지 않고, 간단하게 호출하는 방향

    def get_release_metadata(self, package_name: str, version: str) -> dict:
        url = f"{self.BASE_URL}/{package_name}/{version}/json"

        request = Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "BOMerang-SBOM-Parser"
            }
        )

        try:
            with urlopen(request, timeout=10) as response:
                return json.loads(response.read().decode("utf-8"))

        except HTTPError as e:
            raise RuntimeError(
                f"PyPI API request failed: {e.code} "
                f"({package_name}=={version})"
            ) from e

        except URLError as e:
            raise RuntimeError(
                f"Could not connect to PyPI: {e.reason}"
            ) from e

    def get_dependencies(
        self,
        package_name: str,
        version: str
    ) -> list[Requirement]:

        metadata = self.get_release_metadata(
            package_name,
            version
        )

        requires_dist = metadata.get("info", {}).get(
            "requires_dist"
        ) or []

        dependencies = []

        for requirement_string in requires_dist:
            try:
                requirement = Requirement(
                    requirement_string
                )
                dependencies.append(requirement)

            except Exception:
                # 해석할 수 없는 dependency는 일단 무시
                continue

        return dependencies