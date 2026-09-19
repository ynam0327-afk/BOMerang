# SBOM 생성을 위해 패키지 의존성 정보를 모델링한 파이썬 데이터클래스
from dataclasses import dataclass, field
# 클래스를 간결하게 정의 : 자동으로 생성하여 디버깅 및 내용 기반 비교 가능
from typing import Optional
# 매개변수가 특정 타입이나 None임을 명시하는 타입 힌트


@dataclass # dataclass(데코레이터) 적용 -> DependencyNode 클래스 선언 -> 속성 정의만으로 객체 인스턴스화 가능
class DependencyNode:
    """
    언어별 파서에 사용하는 일반적 의존 모델
    파서는 내부적으로 의존성 그래프를 생성하여 해결 가능
    '전이적 의존성'과 '순환 참조' 감지
    최종 SBOM 표현은 평탄화된 노드 목록을 사용할 예정(dependency + PURL 참조)
    """

    # Package identity 패키지 기본 식별자
    name: str
    ecosystem: str # 패키지 생태계 또는 매니저 종류(pypi, maven 등)
    group: Optional[str] = None
    # Java Maven groupId 지원(공통 스키마 문제를 위해 남겨둠)

    # Version information
    declared_version: Optional[str] = None # 파일에 개발자가 선언한 버전 제약 조건
    resolved_version: Optional[str] = None # 의존성 해석 이후, 확정된 버전

    # SBOM identification
    purl: Optional[str] = None # 패키지를 일관되게 고유 식별할 수 있는 표준 규격

    # Dependency relationships
    # Each item is a PURL of another DependencyNode.
    dependencies: list[str] = field(default_factory=list)
    # DependencyNode 객체의 리스트가 아닌@PURL 문자열 목록(평탄화)
    

    # Graph information
    depth: int = 1 # 전이의존성은 depth+1 적용

    # Dependency metadata
    scope: Optional[str] = None # 의존성이 사용되는 범위(1차구현에선 아직 다루지 않음)
    # 파이썬에서는 정확한 scope를 부여하기 애매함. 파일 처리 정책 필요.
    source_file: Optional[str] = None
    # 의존성이 추출된 원본 파일 경로 : 추적성 확보
    # Python Parser에서 None이 아닌 값을 넣는 것을 결정할 것

    # Parsing information
    parse_status: str = "success"
    error_message: Optional[str] = None

    # Circular dependency detection
    is_circular: bool = False
    # 파일 참조와 패키지 의존성의 각 순환은 별개의 사이클이라 분리 필요.