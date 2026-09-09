from dataclasses import dataclass, field
# 클래스를 간결하게 정의 : 자동으로 생성하여 디버깅 및 내용 기반 비교 가능
from typing import Optional
# 매개변수가 특정 타입이나 None임을 명시하는 타입 힌트


@dataclass
class DependencyNode:
    """
    언어별 파서에 사용하는 일반적 의존 모델

    파서는 내부적으로 의존성 그래프를 생성하여 해결 가능
    전이적 의존성과 순환 참조 감지
    최종 SBOM 표현은 평탄화된 노드 목록을 사용할 예정(dependency + PURL 참조)
    """

    # Package identity
    name: str
    ecosystem: str

    # Version information
    declared_version: Optional[str] = None
    resolved_version: Optional[str] = None

    # SBOM identification
    purl: Optional[str] = None

    # Dependency relationships
    # Each item is a PURL of another DependencyNode.
    dependencies: list[str] = field(default_factory=list)

    # Graph information
    depth: int = 0
    # 실제 파서에서는 depth + 1을 넣어주자

    # Dependency metadata
    scope: Optional[str] = None
    # 파이썬에서는 정확한 scope를 부여하기 애매함. 파일 처리 정책 필요.
    source_file: Optional[str] = None

    # Parsing information
    parse_status: str = "success"
    error_message: Optional[str] = None

    # Circular dependency detection
    is_circular: bool = False
    # 파일 참조와 패키지 의존성의 각 순환은 별개의 사이클이라 분리 필요.