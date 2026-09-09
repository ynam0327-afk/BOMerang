from packaging.requirements import Requirement
# packaging 라이브러리의 Requirement로 처리

def parse_requirement(line: str):
    """
    requirements.txt의 한 줄을 파싱한다.

    반환:
        Requirement 객체
        또는 파일 참조 정보
        또는 None
    """

    line = line.strip()

    # 빈 줄/주석
    if not line or line.startswith("#"):
        return None

    # 파일 참조 -r base.txt
    if line.startswith("-r "):
        return ("file", line[3:].strip())

    # --requirement base.txt
    if line.startswith("--requirement "):
        return ("file", line[len("--requirement "):].strip())

    # 기타 pip 옵션
    if line.startswith("-"):
        return None

    try:
        return ("package", Requirement(line))
    except Exception:
        return None