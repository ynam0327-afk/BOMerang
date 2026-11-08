# 실제 저장소 직접 선언 평가

평가 대상: pallets/flask 3.1.2,
commit `2c1b30d0503cfb064f1cb252e6614a06915a362a`.
라이선스: BSD-3-Clause. `sources/flask/LICENSE.txt` 보존.

## 범위와 정답

`repository_cases.json`은 원본 URL, 고정 커밋, 파일 SHA256, 실행 환경,
정답 경로, 조회 목적을 기록한다. `gold/flask.json`은 원본을 수동 전사한
32개 선언이다: runtime 7개, optional 2개, PEP 735 그룹 23개.
빌드 도구 flit_core 및 tool.tox 명령 안의 설치 명령은 범위 밖이다.
전체 저장소의 모든 파일이나 설치된 환경의 정확도를 주장하지 않는다.

각 gold 행은 package, ecosystem, version constraint, scope/group, source,
marker, 원본 문자열, 줄 번호, 커밋 고정 URL을 포함한다.
정답은 BOMerang 출력에서 생성하지 않았다. 테스트는 표준 tomllib로 원본
세 섹션을 독립적으로 읽어 전사 누락과 줄 번호를 검증한다.
동일 패키지의 서로 다른 그룹/조건부 선언도 각각 하나의 행이다.

`sources/flask/`는 전체 clone이 아니라 고정 커밋의 선언 파일과 라이선스
원본 바이트 스냅샷이다. 평가기는 분석 전에 manifest SHA256을 검사한다.
다른 커밋의 파일은 거부하며 실제 Git HEAD 확인을 대신한다고 주장하지 않는다.
외부 API 접근이 필요했던 URL과 목적은 manifest의 acquisition에 기록했다.
평가기 자체에는 다운로드 기능이 없고 테스트에도 네트워크가 필요 없다.

## 실행

프로젝트 루트 PowerShell, Python 3.11+ 및 packaging, pytest 사용:

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python evaluate_repository_parsing.py --source accuracy-tests/sources/flask --save-integrated accuracy-tests/results/flask-integrated.json --output accuracy-tests/results/flask-source.json
python evaluate_repository_parsing.py --input accuracy-tests/results/flask-integrated.json --output accuracy-tests/results/flask-offline.json
python -m pytest --import-mode=importlib -p no:cacheprovider -q test_repository_evaluation.py
```

기존 출력 파일은 덮어쓰지 않는다. 재측정은 새 출력 경로를 사용한다.
`--manifest`, `--case`로 사례를 선택할 수 있다.
전체 checkout을 준비한 경우 `--source PATH_TO_CHECKOUT`으로 실행해도
manifest에 등록한 파일만 해시 검증 후 임시 디렉터리에 복사하여 분석한다.
따라서 예제 앱이나 다른 모듈을 우연히 합치지 않는다.

오프라인 입력은 루트 integrated_parser의 JSON 객체
(`dependencies`, `python_marker_environment`)여야 한다.
직접 노드는 name, ecosystem, depth=1, declared_version, resolved_version,
version_status, source_file 또는 source_files가 필요하다.
절대 출처 경로가 있으면 당시 프로젝트 루트를 `--source-root PATH`로 제공한다.
이 평가기가 저장한 JSON은 출처를 상대 경로로 바꾸므로 이 옵션이 필요 없다.
잘못된 필수 필드/환경은 오류로 종료한다. scope/marker 누락은
unavailable로 보고하며 gold에서 보충하지 않는다.

## 실행 격리와 버전

source 모드는 새 Python subprocess에서 **루트 integrated_parser.py**의
analyze를 호출한다. 루트 python-parser 및 python-security-integration의
adapter만 import되는지 절대 경로를 검사하고 모듈 경로/코드 SHA256을
integrated JSON과 결과에 보존한다. 기존 parser 구현과 target/classes를
수정하거나 컴파일하지 않는다. Python 선언 파일만 허용한다.

주입한 DeclarationOnlyPyPI는 후보와 전이 목록을 빈 배열로 반환한다.
PyPI/OSV/NVD/Maven 조회, 패키지 설치, 저장소 코드 실행은 수행하지 않는다.
정확 버전은 선언값을 유지하고 범위 버전은 unresolved가 된다.
confirmed는 선언이 exact라는 의미이며 실제 설치 확인이 아니다.
estimated는 레지스트리에서 선택한 값이며 설치 버전과 동일시하지 않는다.
offline 모드에서는 입력에 기록된 상태를 그대로 세고, 이전 import 출처가
없으면 not recorded로 명시한다. evaluator 자신이 import한 모듈을 과거
JSON 생산 모듈로 오인하지 않는다.

## 지표 해석

- 기본 지표 environment_applicable: 기록된 Python marker 환경에서
  활성인 gold 선언과 비교한다. 현재 Python 3.14에서는 30개가 활성이다.
- all_declared: marker 활성 여부와 무관하게 gold 32개 전체와 비교한다.
  이는 선언 수집 관점의 지표이며 비활성 선언 누락을 런타임 오류로 단정하지 않는다.
- 식별 단위: (ecosystem, normalized package name, repository-relative source).
  PyPI는 PEP 503, Maven은 대소문자를 유지한 group:artifact.
- 동일 키에 여러 선언이 있으면 다중집합으로 일대일 대응한다. scope/marker/
  버전 속성 일치 수를 최대화하는 최소 비용 대응을 사용한다.
  이 때문에 하나로 병합된 조건부 선언을 여러 TP로 복제하지 않는다.
- TP/FP/FN은 선언 발생 횟수의 탐지 지표이고 속성 오차와 분리된다.
  precision=TP/(TP+FP), recall=TP/(TP+FN),
  F1=2TP/(2TP+FP+FN). 분모가 0이면 null.
- 속성별 matched/mismatched/unavailable, 비교 쌍 수,
  agreement_over_pairs와 recorded_coverage를 제공한다.
  속성 지표 분모는 TP 쌍이며 FN/FP는 탐지 지표에서 별도 표시된다.
- depth>1은 FP를 포함한 직접 선언 지표에서 제외한다.
- 버전 조건은 packaging의 정규화 문자열, marker는 Marker의 정규화 문자열로
  비교한다. 논리적으로 동치인 모든 표현을 증명하는 비교기는 아니다.
- 기존 통합 출력은 PURL로 병합되고 marker를 보존하지 않는다.
  누락된 관측값을 gold로 복원하지 않으므로 marker 일치율/coverage가 낮아질 수 있다.
  하나의 합쳐진 노드를 임의로 여러 선언으로 확장하지 않는다.
- build-system, tool.tox, 전이 그래프, 취약점 및 설치 가능성은 이번 범위 밖이다.
  OSV 버전/CVE 매칭 평가와 다른 평가다.

## 원본 및 재현성

원본 링크, SHA256, 라이선스, 실제 작성 환경은 repository_cases.json 참조.
결과에는 gold SHA256, offline 입력 SHA256, 평가 실행 환경과 parser import
근거를 기록한다. saved JSON의 source commit은 생산자 기록이므로 이 모드에서
원본 checkout의 커밋을 독립 검증했다고 주장하지 않는다.
기존 pypi-extras-live 샘플과 다른 미추적 결과는 보존한다.


## 공개 CI fixture

원본 결과·백업은 로컬에 보존하며 GitHub 업로드 대상에서 제외합니다.
CI 재현에는 `ci/fixtures/flask-step2-integrated.json`의 경로 정리 사본을 사용합니다.
`ci/run_checks.py`가 기존 회귀 테스트의 상대 경로에 배치합니다.
Flask 원본 스냅샷·gold·평가 규칙은 변경하지 않았습니다. 사용법은 `ci/README.md`를 참조하세요.
