import json # PyPI API 응답을 통한 JSON 형식 텍스트 데이터
from urllib.error import HTTPError, URLError
# 네트워크 요청 중 발생 에러 처리 클래스
# HTTP 상태 코드 에러 / 네트워크 레벨 장애
from urllib.request import Request, urlopen
# 파이썬 내장 기능으로 HTTP 요청 전송을 위한 임포트

from packaging.requirements import Requirement
from packaging.version import Version, InvalidVersion
# PyPI 메타데이터의 requires_dist 필드의 문자열 파싱 및 구조화 의존성
# 객체 변환을 위해 임포트

class PyPIClient: # PyPI와 통신 역할 캡슐화 클래스
    BASE_URL = "https://pypi.org/pypi" # PyPI 공식 JSON API 기본 경로
    # HTTP 요청을 위해 라이브러리를 사용하지 않고, 간단하게 호출하는 방향

    # 패키지의 메타데이터 조회 -> 딕셔너리 형태 반환 메서드
    # PyPI JSON API 호출
    def get_release_metadata(self, package_name: str, version: str) -> dict:
        url = f"{self.BASE_URL}/{package_name}/{version}/json"
        # 특정 패키지와 버전의 메타데이터 반환 PyPIJSONAPI 엔드포인트 URL 포맷팅

        request = Request( # HTTP 요청 객체
            url,
            headers={
                "Accept": "application/json", # JSON 형식
                "User-Agent": "BOMerang-SBOM-Parser"
            }
        )

        try: # urlopen : HTTP GET 요청 전송(무한대기 방지 10초)
            with urlopen(request, timeout=10) as response:
                return json.loads(response.read().decode("utf-8")) # load : 파이썬 딕셔너리 변환 후 반환

        except HTTPError as e:
            raise RuntimeError(
                f"PyPI API request failed: {e.code} "
                f"({package_name}=={version})"
            ) from e # 원본 예외 트레이스백 유지

        except URLError as e:
            raise RuntimeError(
                # PyPI API 실패시 처리 : 팀과 합의 필요
                # 전체 파서 실패 or 해당 노드만 에러
                f"Could not connect to PyPI: {e.reason}"
            ) from e

    def get_available_versions(self, package_name: str) -> list[str]:
        ## PyPI에서 사용 가능한 패키지 버전 목록 조회
        url = f"{self.BASE_URL}/{package_name}/json"

        request = Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "BOMerang-SBOM-Parser"
            }
        )

        try:
            with urlopen(request, timeout=10) as response:
                data = json.loads(
                response.read().decode("utf-8")
            )

        except HTTPError as e:
            raise RuntimeError(
                f"PyPI API request failed: {e.code} "
                f"({package_name})"
            ) from e

        except URLError as e:
            raise RuntimeError(
                f"Could not connect to PyPI: {e.reason}"
            ) from e

        versions = []

        releases = data.get("releases", {})

        for version, files in releases.items():
            try:
                Version(version)
            except InvalidVersion:
                continue

            # yanked 된 release는 후보에서 제외
            if files and all(
                file_info.get("yanked", False)
                for file_info in files
            ):
                continue

            versions.append(version)

        return sorted(
            versions,
            key=Version
        )

    # requires_dist 추출 및 Requirement 객체 변환
    def get_dependencies(
    self,
    package_name: str,
    version: str,
    extras: set[str] | None = None
) -> list[Requirement]:

        metadata = self.get_release_metadata(
            package_name,
            version
        )

        requires_dist = metadata.get("info", {}).get(
            "requires_dist"
        ) or []

        dependencies = []

        # 선택된 extra가 없으면 기본 의존성만 분석
        selected_extras = set(extras or set())

        # 기본 설치 환경과 선택된 extra 환경을 각각 평가
        environments = [""] + sorted(selected_extras)

        for requirement_string in requires_dist:
            try:
                requirement = Requirement(requirement_string)

                if requirement.marker is not None:
                # 하나 이상의 환경에서 조건을 만족해야 포함
                    if not any(
                        requirement.marker.evaluate(
                            environment={"extra": extra}
                        )
                        for extra in environments
                    ):
                        continue

                dependencies.append(requirement)

            except Exception:
                continue

        return dependencies