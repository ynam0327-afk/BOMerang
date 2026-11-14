from packaging.requirements import Requirement
import re
# packaging 라이브러리(PEP 508)의 Requirement로 처리

def normalize_requirement_line(line: str) -> str:
    """Remove pip comments/options without damaging URL fragments or markers."""
    line = re.sub(r"\s+#.*$", "", line.strip())
    return re.sub(r"\s+--hash(?:=|\s+)\S+", "", line).strip()


def iter_requirement_lines(stream):
    pending, start = "", 1
    for number, line in enumerate(stream, 1):
        if line.lstrip().startswith("#"):
            continue
        if not pending:
            start = number
        line = line.rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        yield start, pending + line
        pending = ""
    if pending:
        yield start, pending


def parse_requirement(line: str):
    """
    requirements.txt의 한 줄을 파싱한다.
    반환:
        Requirement 객체 - 패키지 정보
        또는 파일 참조 정보 - 다른 파일 경로
        또는 None - 아무것도 아님
    """

    line = normalize_requirement_line(line)

    # 빈 줄/주석 : 의존성 정보 아님 - 파싱 X
    if not line or line.startswith("#"):
        return None

    # 1차 pip 코어의 범위는 requirements.txt의 패키지 선언과 -r 파일 참조
    # 파일 참조 -r base.txt
    for pattern, kind in ((r"^(?:-r\s*|--requirement(?:\s+|=))(.+)$", "file"),
                          (r"^(?:-c\s*|--constraint(?:\s+|=))(.+)$", "constraint")):
        match = re.match(pattern, line)
        if match:
            return kind, match[1].strip().strip("\"'")

    # 기타 pip 옵션은 현재 무시 : 1차 의존성 분석 대상이 아님
    if line.startswith("-"):
        return None

    try:
        return ("package", Requirement(line)) # 위 가정문(필터) 통과한 문자열 = 실제 패키지 선언문 간주
    except Exception:
        return None # 문법 오류 발생시 예외 - None 반환
