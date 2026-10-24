from packaging.requirements import Requirement
# packaging 라이브러리(PEP 508)의 Requirement로 처리

def parse_requirement(line: str):
    """
    requirements.txt의 한 줄을 파싱한다.
    반환:
        Requirement 객체 - 패키지 정보
        또는 파일 참조 정보 - 다른 파일 경로
        또는 None - 아무것도 아님
    """

    line = line.strip() # 공백/주석 전처리

    # 빈 줄/주석 : 의존성 정보 아님 - 파싱 X
    if not line or line.startswith("#"):
        return None

    # 1차 pip 코어의 범위는 requirements.txt의 패키지 선언과 -r 파일 참조
    # 파일 참조 -r base.txt
    if line.startswith("-r "):
        return ("file", line[3:].strip()) # 뒤에건 참조경로임

    # --requirement base.txt
    if line.startswith("--requirement "):
        return ("file", line[len("--requirement "):].strip())

    # 기타 pip 옵션은 현재 무시 : 1차 의존성 분석 대상이 아님
    if line.startswith("-"):
        return None

    try:
        return ("package", Requirement(line)) # 위 가정문(필터) 통과한 문자열 = 실제 패키지 선언문 간주
    except Exception:
        return None # 문법 오류 발생시 예외 - None 반환