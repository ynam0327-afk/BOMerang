# 12주차 Python 파서 정확도·충돌 추적 개선

2026-11-10 (Asia/Seoul). 이 문서는 정확도 개선 단계의 로컬 검증 기록이다. 원격 반영을 위한 최종 검증은 [최종 정리 기록](week12-release-validation.md)을 참고한다.
기존 버전 목록 캐시와 이전 작업 파일을 보존했다.

## 실제 입력과 재현 결과

실제 입력은 ../microblog/requirements.txt이다. 44번째 줄은 requests==2.31.0,
52번째 줄은 urllib3==2.1.0이다. 지원되는 분석 입력 파일은 이 파일 하나다.
입력 SHA256은 d1a46ab01c6ac7cc9eac794307a7ea706ba3ab599da1c5ade066a4b66a924d6b이며 전후 동일하다.

실제 PyPI 응답을 저장한 뒤 수정 후에는 동일 응답을 재사용했다.
requests==2.31.0의 실제 requires_dist는 urllib3 (<3,>=1.21.1)이다. 직접 고정된 2.1.0은 이를 만족한다.
원본 메타데이터는 microblog-before/pypi-snapshot.json에 있다.

| 단계 | 이번 수정 전 현행 코드 | 수정 후 |
|---|---|---|
| PythonParser 단독 | urllib3@2.1.0 하나 | 동일 |
| 루트 integrated_parser JSON | urllib3@2.1.0 하나 | 동일 |
| CycloneDX SBOM | urllib3@2.1.0 하나 | 동일 |
| dashboard_export 응답 데이터 | urllib3@2.1.0 하나 | 동일 |

현재 입력과 현재 루트 코드에서는 중복이 재현되지 않았다.
과거 microblog-result.json은 UTF-16이며 debug 출력 뒤 통합 JSON에 2.1.0과 2.8.0이 이미 함께 있다.
따라서 그 결과의 중복은 SBOM 변환 이전부터 존재한다.
반면 microblog_result.json과 microblog_output.txt에는 2.1.0만 있다.
과거 명령·파서 사본·PyPI 응답이 없어 과거 실행의 정확한 원인은 확정하지 못했다.

최초 피드백의 2.0.7은 원본 입력과 명령이 확인되지 않은 별도 미확인 사례다.
현재 2.1.0의 분석 결과와 혼동하지 않는다. 아래 합성 다중 고정 테스트에 쓰인 2.0.7도
최초 피드백을 재현했다는 증거가 아니다.

저장소에는 루트와 python-security-integration 하위에 파서/통합 분석기 사본이 있다.
이번 제품 수정의 기준은 루트 integrated_parser.py 및 루트 python-parser이다.
신규 측정기는 루트 import 경로를 우선하고 실제 모듈 경로를 증거에 남긴다.
레거시 26개 회귀도 기존처럼 별도 프로세스에서 검증했다.

## 재현하여 수정한 원인

- 같은 프로젝트의 직접 고정 버전이 다른 입력 파일에 있으면 파일별 파서가 그 제약을 놓쳤다.
  pyproject.toml에 requests, requirements.txt에 urllib3==2.1.0을 선언한 합성 사례에서
  통합 분석의 Python 버전 해석 단계부터 2.1.0과 2.8.0이 함께 생성됐다.
  SBOM과 대시보드는 이 중복을 입력 그대로 전달했다.
- 서로 다른 직접 고정 버전이 있으면 전이 해석이 호환 후보 중 최신 버전을 임의로 선택했다.
- 비호환 단일 고정 버전은 기존에도 미해결 오류 노드를 보존했지만 충돌이 오류 문자열에만 남았다.
  SBOM·대시보드에 구조화된 상태와 원인이 전달되지 않았다.

선택된 프로젝트 입력 파일 및 -r 참조 파일의 활성 직접 고정 버전을 해석 전에 공유하도록 수정했다.
단일 고정 버전이 범위를 만족하면 재사용하고, 직접 고정 버전이 없으면 기존 최신 적합 정식 버전을 선택한다.
직접 범위 선언에도 동일한 단일 고정 버전 우선 정책을 적용한다.

범위를 만족하지 않으면 직접 고정 노드를 유지하고 전이 연결은 버전 없는 미해결 PURL로 남긴다.
여러 직접 고정 버전도 선언 노드를 모두 보존하며 전이 연결에서 임의의 하나를 선택하지 않는다.
예를 들어 urllib3>=3과 직접 urllib3==2.1.0이 충돌하면 직접 노드는 pkg:pypi/urllib3@2.1.0이고,
requests의 연결은 pkg:pypi/urllib3이다. 정상 해결된 설치 환경으로 표시하지 않는다.

선택된 Python 입력 파일들은 하나의 분석 제약 집합이다.
여러 독립 환경을 담은 저장소는 기존 exclude_dirs를 사용하거나 환경별로 별도 분석해야 한다.
이 기능은 전체 패키지 설치 환경을 푸는 solver가 아니다.

## 충돌 정보와 전파

관련 노드 및 통합 JSON에 dependency_conflicts를 기록한다.
부모·미해결 요구·보존된 직접 노드의 graph_resolution_status는 dependency_conflict가 된다.
다른 파일에 선언된 직접 노드에도 해당 상태를 반영한다.

예시:

```json
{
  "required_package": "urllib3",
  "required_specifier": "<4,>=3",
  "requiring_purl": "pkg:pypi/requests@2.31.0",
  "selected_version": null,
  "direct_versions": ["2.1.0"],
  "reason": "incompatible_direct_pin",
  "source_file": ".../requirements.txt",
  "direct_sources": [{"version": "2.1.0", "source_file": ".../requirements.txt"}]
}
```

다중 고정의 reason은 multiple_direct_pins이다. 충돌 중에는 정상 선택된 전이 버전이 없으므로
selected_version은 null이다. 보존된 선언 버전과 근거 파일은 direct_versions/direct_sources로 추적한다.
직접 선언 자체는 confirmed를 유지하며, 이는 선언 근거를 뜻하고 설치 환경 검증 성공을 뜻하지 않는다.
미해결 전이 노드는 unresolved다. 추정 버전의 최신 적합 선택·근거 정책도 유지했다.

보안 어댑터는 직접 고정 버전 재사용 시 해당 선언 파일을 version_evidence에 기록한다.
다른 파일의 직접 고정을 사용해도 근거 없는 unresolved로 잘못 분류하지 않는다.
CVE 매칭·점수 계산 구현은 변경하지 않았다.

CycloneDX 컴포넌트 properties에 bomerang:dependency_conflicts(JSON 문자열)와
bomerang:graph_resolution_status를 보존하며 같은 PURL의 병합 시 후속 충돌도 합친다.
대시보드 packages 응답에 두 필드를 전달하고 summary에 dependency_conflict_packages 수를 기록한다.

별도 대시보드 HTTP 서버/API 구현이나 연결 정보는 저장소에서 확인되지 않았다.
검증 범위는 실제 보안 파이프라인을 거친 dashboard_export.export()와 JSON 직렬화 응답 계약이다.
외부 팀 서비스의 HTTP 응답·화면이 새 필드를 전달·표시하는지는 미확인이다.

## 변경 전후 결과

실제 microblog는 전후 56개 노드, 57개 의존 관계로 동일하다.
추가·제거 PURL 및 의존 관계 변화가 없으며 requests는 계속 urllib3@2.1.0으로 연결된다.
추가된 메타데이터는 직접 버전 재사용 근거·요구 범위 observations와 충돌 필드다.

| 실제 microblog 지표 | 변경 전 | 변경 후 |
|---|---:|---:|
| 패키지 노드 | 56 | 56 |
| 의존 관계 | 57 | 57 |
| 패키지별 affected 취약점 매칭 | 60 | 60 |
| OSV 조회 성공 | 55 | 동일 응답 재사용 |
| 버전 미확정으로 조회 건너뛰기 | 1 | 1 |

OSV 조회 오류는 0건이다. 17개 패키지에서 총 60개 패키지별 매칭이 affected이며 모두 동일하다.
60은 패키지별 매칭 수이며 서로 다른 CVE ID 60개라는 뜻은 아니다.
NVD 추가 조회는 하지 않았으므로 새로운 수치 CVSS 점수를 검증한 결과로 해석하지 않는다.
원본 OSV, 정규화·매칭·우선순위·대시보드·SBOM 및 비교 결과는 microblog-security/에 있다.

아래는 고정 합성 응답의 별도 회귀 사례다. CVE-2099-9999는 합성 식별자이며 실제 취약점 주장이 아니다.

| 합성 사례 | 노드 전→후 | PURL·관계 변화 | 합성 취약점 매칭 |
|---|---:|---|---|
| 호환 단일 고정 | 2→2 | requests→urllib3@2.1.0 유지 | 동일 |
| 비호환 단일 고정 | 3→3 | 직접 2.1.0 + 미해결 연결 유지, 구조화 충돌 추가 | 동일 |
| 직접 고정 없음 | 2→2 | requests→urllib3@2.8.0 유지 | 동일 |
| 서로 다른 직접 고정 | 3→4 | 두 고정 PURL 유지, 임의 2.1.0 연결 대신 미해결 PURL 추가 | 두 선언 버전별 매칭 유지 |
| 두 파일에 분리 | 3→2 | urllib3@2.8.0 제거, requests→urllib3@2.1.0으로 수정 | 불필요한 2.8.0 not_affected 제거, 2.1.0 affected 유지 |

전체 전후 PURL·관계·매칭 항목은 case-comparison.json에 있다.
비교 기준인 cases-before-root/는 원래 루트 코드와 이전 캐시를 임시 사본에 복원해 실행했다.
초기 탐색 cases-before/는 레거시 통합 모듈을 불러온 사실을 확인하여 판단 기준에서 제외했고 그대로 보존했다.

## 검증

| 검증 | 결과 |
|---|---:|
| Python 파서 기존 및 캐시 회귀 | 68 PASS |
| 신규 정확도·전파 회귀 | 20 PASS |
| 관련 합계 | 88 PASS |
| 전체 CI main (위 테스트 포함) | 337 PASS |
| security-review | 95 PASS |
| legacy-parser | 26 PASS |
| 전체 CI | 458 PASS, 실패/오류/건너뛰기 0 |
| Java exporter/bridge 임시 사본 컴파일 | PASS |
| Flask 전체 선언 정확도 | TP=32, FP=0, FN=0 |
| CycloneDX·보안 정책·참조 무결성 | PASS |
| 실제 microblog 전후 SBOM 스키마·참조 | PASS |
| git diff --check | PASS |

최종 전체 CI 증거는 ci-final/summary.json과 각 JUnit·로그에 있다. 앞선 ci/ 결과도 보존했다.
기존 테스트 중 여러 직접 고정에서 최신을 고르도록 요구하던 1개만 명시된 새 정책에 맞춰 충돌을 요구하도록 바꿨다.
다른 기존 테스트의 기대 결과는 변경하지 않았다. 신규 20개에 맞춰 CI의 main 기대 수 337개, 총 458개로 갱신했다.

신규 테스트는 선언 순서·참조 파일·pyproject, 호환·비호환·무고정·다중 고정,
파일 간 제약 공유, extras/marker, 근거 보존, JSON/SBOM/대시보드 및 같은 PURL 병합을 검사한다.
캐시가 있는 경우 실제 목록 호출 1회, 없는 경우 3회여도 선택 결과가 동일함을 검증했다.

benchmark_api_calls.py도 임시 사본에서 재실행했다.
버전 목록 1회·메타데이터 3회·노드 3개로 기존 api-calls-after.json 전체와 동일하다.
원래 캐시 키 canonicalize_name, 성공 시에만 캐싱, parse 시작 시 초기화,
조건별 독립 선택과 extras/marker/PURL/재귀/메타데이터 중복 방지를 유지했다.

환경은 Windows 11, Python 3.14.3, JDK 25.0.3이며 Java에는 --release 17을 적용했다.
기존 ci/requirements.txt 고정 패키지를 사용했다. GitHub Actions 원격 실행은 수행하지 않았다.

## 변경 파일

제품 코드:

- python-parser/python_parser.py
- python-parser/dependency_node.py
- python-security-integration/python_security_adapter.py
- integrated_parser.py
- cyclonedx_converter.py
- dashboard_export.py

테스트·검증·문서:

- python-parser/test/test_python_parser_core.py: 정책 테스트 1개 갱신
- test_python_dependency_conflicts.py: 신규 20개 테스트 및 합성 비교 실행기
- ci/run_checks.py
- ci/README.md
- .github/workflows/python-tests.yml
- ci/measure_python_conflicts.py: 신규 실제 입력/PyPI 스냅샷 실행기
- ci/compare_python_conflicts.py: 신규 OSV 비교 실행기
- docs/week12-python-parser-accuracy.md: 이 보고서
- performance-results/week12-accuracy/: 신규 전후 분석·보안·벤치마크·CI 증거

주요 증거 경로:

- microblog-before/ 및 microblog-after/: 실제 입력의 parser.json, graph.json, bom.cdx.json, schema.json, pypi-snapshot.json, summary.json
- cases-before-root/ 및 cases-after/: 합성 사례의 파서·통합·SBOM·대시보드·매칭
- case-comparison.json: 합성 사례의 추가/제거 PURL 및 변경 관계
- microblog-security/comparison.json 및 osv-snapshot.json: 실제 OSV 전후 비교
- microblog-security/before-*.json 및 after-*.json: 실제 보안 파이프라인 각 단계
- api-calls.json: 이전 캐시 성능 결과와 동일함을 확인한 측정
- ci-final/: 최종 CI 요약·로그·JUnit·Flask·SBOM·정책 검증
- preservation.json: 작업 시작 시 기존 미추적/target 파일의 SHA256 및 보존 검증

## 재실행

아래 출력 경로는 존재하지 않는 새 경로를 사용한다.

```powershell
$env:PYTHONPATH = '.;python-parser;python-security-integration'
$env:PYTHONUTF8 = '1'
$env:PYTHONDONTWRITEBYTECODE = '1'
python -B -m pytest --import-mode=importlib -p no:cacheprovider -q python-parser/test test_python_dependency_conflicts.py
python -B ci/run_checks.py --output performance-results/week12-accuracy-ci-new
python -B ci/measure_python_conflicts.py ../microblog/requirements.txt --output performance-results/week12-accuracy-replay-new --snapshot performance-results/week12-accuracy/microblog-before/pypi-snapshot.json
python -B test_python_dependency_conflicts.py --output performance-results/week12-accuracy-cases-new
python -B ci/compare_python_conflicts.py performance-results/week12-accuracy/microblog-before performance-results/week12-accuracy/microblog-after --output performance-results/week12-accuracy-security-new --snapshot performance-results/week12-accuracy/microblog-security/osv-snapshot.json
```

## 기존 작업 보존

작업 시작 시 기존 미추적 파일 및 target/classes 파일 116개의 SHA256이 모두 동일하다.
CI도 target/classes 전체 70개 파일이 실행 전후 동일함을 확인했다.
이전 캐시 테스트·벤치마크·로그·성능 결과·최적화 보고서와 Java .class를 보존했다.
microblog 원본 입력의 SHA256도 동일하다. 기존 로컬 구현 위에 필요한 변경을 추가했다.
새 측정은 week12-accuracy/에 기록했고 이전 API 호출 before/after 결과를 덮어쓰지 않았다.

측정 원본과 개인 검증 산출물은 로컬에 보존하며 이 저장소에는 포함하지 않는다. 위의 핵심 결과와 공개 검증 실행기로 검토·재현한다.
