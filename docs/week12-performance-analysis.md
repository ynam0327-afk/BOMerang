# 12주차 Python 파서 성능 저하 분석 및 개선

검증일: 2026-11-10 (Asia/Seoul). main에서 로컬 구현·검증 완료.
이 성능 검증 단계에서는 push·merge·reset을 수행하지 않았다. 원격 반영을 위한 최종 검증은 [최종 정리 기록](week12-release-validation.md)을 참고한다. 기존 미추적 파일·로그·측정·Java .class를 보존했다.

## 결론

기존 기록의 requirements 500개 평균 380.720→562.663ms는 약 47.79% 증가다.
그러나 HEAD와 현재 정확도 개선본을 같은 입력으로 워밍업·교차 측정했을 때 이 증가율은 재현되지 않았다.
최초 진단 중앙값은 HEAD 452.032ms, 정확도 개선본 457.545ms(+1.22%)이고
IQR은 각각 41.841ms와 54.088ms였다. 작은 차이를 일관된 회귀로 단정할 수 없다.
그렇다고 과거 증가가 없었다고 판단하지도 않는다. 과거 실행의 환경 부하·출력 대상 등 원인을 확정할 자료가 부족하다.

실제 cProfile에서는 두 버전에 공통된 선언 후처리의 전체 노드 반복 검색과
동일 파일의 반복 Path.resolve()가 주요 비용이었다. 이 두 부분만 개선했다.
버전 목록 캐시, 직접 고정 정책, 충돌 검사 및 SBOM·대시보드 전달은 유지했다.
최종 결과는 아래 동일 실행 내 비교로 평가하며 서로 다른 시점의 최저값을 골라 비교하지 않았다.

## 기존 before/after 파일 분석

분석한 원본은 performance-results/requirements-{before,after}.txt,
recursive-{before,after}.txt, toml-{before,after}.txt이다. 원본을 수정하지 않았다.

| 항목 | 기존 before 평균(ms) | 기존 after 평균(ms) | 증가 |
|---|---:|---:|---:|
| requirements 500 | 380.720 | 562.663 | 47.79% |
| 재귀 깊이 10 | 4.561 | 7.930 | 73.87% |
| PEP 621 100 | 42.138 | 81.972 | 94.53% |
| Poetry 100 | 50.843 | 81.292 | 59.89% |

requirements 반복은 5회, 재귀/TOML은 10회이며 명시적 워밍업이 없다.
전체 원본은 순수 Mock PyPI를 쓰며 고정 버전이어서 get_available_versions 호출이 0이다.
따라서 이 자료만으로 버전 목록 캐시의 API 지연 절감 효과를 측정할 수 없다.

원본 스크립트는 stdout만 메모리로 돌리고 stderr는 그대로 두며 노드마다 flush=True로 디버그 출력을 한다.
콘솔·파일·파이프의 출력 비용과 실행 환경 변동이 시간에 섞인다.
예를 들어 기록된 재귀 깊이 10 after 평균은 7.930ms지만 중앙값은 5.615ms다.
입력·환경·순서·원시 샘플이 함께 기록되어 있지 않아 과거 증가의 정확한 원인을 소급 확정할 수 없다.
Windows 경로 API 비용은 측정으로 확인했으나 OneDrive 동기화 자체가 과거 증가 원인인지는 계측하지 않았다.

## 비교 방법과 안전성

HEAD는 6d92b684571634440e42bec39bdb04768495818b이다.
작업 파일에 HEAD를 덮어쓰지 않고 별도 variants/head/python-parser에 추출했다.
정확도 개선본도 변경 전에 diagnosis/variants/current에 모든 파서 모듈을 복사하고 SHA256을 기록했다.
최종 비교는 이 사본을 accuracy로, 실제 수정 코드를 current로 불렀다.
HEAD는 캐시·새 충돌 정책이 없는 역사적 기준이며 실제 개선율은 accuracy→current로 계산했다.

Python 3.14.3, packaging 26.3, Windows 11의 동일 환경과 동일 입력 파일을 사용했다.
각 변형은 별도 지속 Python 프로세스이며 매 측정마다 새 파서와 Mock 클라이언트를 생성했다.
사례별 3회 워밍업 후 15회 측정했고, HEAD/정확도 개선본/최종본 순서를 회전·역순 교차했다.
한 번에 한 프로세스만 파싱하며 CI는 측정이 끝난 뒤 실행했다.
환경의 다른 부하는 통제했다고 주장하지 않는다.

타이머는 parse() 본문만 포함하며 프로세스 생성·IPC·클라이언트 생성·검증 해시 계산을 제외한다.
표준 비교에서는 stdout/stderr를 메모리로 받아 순수 파싱 비용을 비교했다.
같은 디버그 코드를 실제 파일에 flush하는 requirements 500 별도 사례도 측정했다.
원본 스크립트 3개도 수정 없이 각 변형에서 실행했고 stdout/stderr를 별도 신규 파일로 저장했다.
원본 스크립트와 제어 실험의 문법·패키지 수·깊이는 동일하며 각 제어 사례의 실제 파일은 변형 간 공유한다.

각 샘플에서 노드 수·PURL·선택 버전·연결·깊이·오류·순환 상태의 해시를 확인했다.
정확도 개선본과 최종본은 전체 노드·선언·declaration_packages·오류 데이터 해시도 비교했다.
cProfile은 시간 측정 후 별도 실행했고 .prof, 상위 함수 표, 전체 호출 통계를 저장했다.
프로파일 시간은 계측 오버헤드를 포함하므로 일반 벤치마크 시간과 직접 비교하지 않는다.

## 확인한 병목과 변경

### 1. 선언마다 전체 노드를 검사

병목 함수는 _finalize_declarations이다.
기존에는 선언 D개마다 노드 N개를 순회하면서 canonicalize_name(node.name)을 재호출했다.
500개의 서로 다른 패키지에서 전체 canonicalize_name 호출이 253,000회였다.
정확도 개선본 프로파일의 해당 함수 누적 시간은 795.554ms였다.

버전이 있는 노드를 정규화된 이름별 목록으로 한 번 분류하고,
각 선언에서는 같은 이름의 후보만 기존 specifier.contains()로 검사하도록 변경했다.
다중 버전 후보·모호성·inactive marker·정적 선언 연결 정책을 그대로 유지한다.
일반적인 서로 다른 패키지에서는 전수 비교가 없어지며,
같은 이름에 버전 후보가 여러 개면 그 후보들의 범위 검사는 계속 수행한다.

최종 전체 canonicalize_name 호출은 3,500회, _finalize_declarations 누적 시간은 73.135ms였다.
이는 모든 그래프 상황의 선형 시간 보장이라는 뜻은 아니다.

### 2. 이미 정해진 출처 경로를 선언마다 재해석

make_declaration()이 선언마다 Path.resolve()를 호출했다.
requirements 500개에서 resolve는 503회였고 프로파일 누적 시간은 406.696ms였다.
그 아래 Windows nt._getfinalpathname 호출 비용도 확인했다.

requirements 파서는 이미 resolve한 파일 경로를 선언 생성에 전달한다.
TOML은 문서 단위로 canonical source를 한 번 확인하고 PEP 621·Poetry·오류 진단에 재사용한다.
make_declaration의 기존 외부 호출은 기본 동작대로 resolve하며,
내부 호출만 resolved_source 선택 인자를 사용한다.
분석 간에 파일 경로를 장기 캐싱하지 않는다. 상대 경로·참조 파일·출처 ID 동작을 회귀 검증했다.

requirements 500개의 resolve는 503→3회, Poetry 100개는 103→4회가 됐다.
첫 개선에서 Poetry의 별도 선언 생성 경로가 재사용을 거치지 않는 것을 후속 프로파일로 확인했다.
그 경로에도 같은 수정을 적용한 최종 자료가 final-confirmed/다. 앞선 자료도 보존했다.

### 3. 유지한 연산

요구한 범위/충돌 검증을 생략하지 않았다.
requirements 500개 프로파일에서 specifier.contains 호출은 1,000→1,000회,
_direct_pin_conflict는 500→500회다. _apply_dependency_conflicts도 계속 실행된다.
선언 수집과 Requirement 생성 정책도 유지했다.

버전 목록 캐시 초기화는 parse 시작 시 한 번이며 버전 목록을 미리 조회하지 않는다.
고정 버전 사례에서 버전 목록 조회가 전후 모두 0임을 실측했다.
추가 직접 버전 출처 수집·충돌 확인 비용은 있으나 전체 노드 검색과 경로 해석보다 작았다.
최종 후처리의 충돌 적용은 이 무충돌 사례에서 프로파일 누적 약 0.182ms였다.

## 최종 동일 실행 비교

아래는 final-confirmed/comparison.json의 워밍업 후 중앙값이다.
대괄호는 15회 측정의 최솟값~최댓값이며 단위는 ms다. IQR과 평균·CPU 시간은 원본 JSON에도 있다.
초기 진단·중간 수정본·최종 측정 모두 보존하며, 아래 표는 최종 측정만 사용한다.

| 사례 | HEAD 중앙값 | 정확도 개선본 중앙값 [범위] | 최종 중앙값 [범위] | 감소율 |
|---|---:|---:|---:|---:|
| requirements/10 | 9.305 | 9.292 [8.420~13.348] | 4.364 [3.289~5.545] | 53.0% |
| requirements/50 | 35.785 | 38.559 [35.047~65.998] | 11.163 [8.909~15.877] | 71.0% |
| requirements/100 | 109.050 | 119.057 [97.299~133.501] | 28.507 [21.200~37.983] | 76.1% |
| requirements/500 | 709.506 | 731.429 [638.216~836.770] | 119.723 [95.171~161.362] | 83.6% |
| recursive/1 | 4.299 | 4.185 [3.325~6.423] | 4.012 [2.773~6.473] | 4.1% |
| recursive/3 | 6.205 | 6.113 [5.358~6.870] | 5.459 [3.970~6.373] | 10.7% |
| recursive/5 | 6.406 | 6.122 [3.879~7.018] | 5.057 [3.144~6.488] | 17.4% |
| recursive/10 | 5.247 | 5.532 [4.096~8.289] | 5.364 [3.941~7.738] | 3.0% |
| pep621/10 | 17.034 | 17.874 [10.752~22.150] | 7.588 [5.888~11.892] | 57.5% |
| pep621/50 | 57.369 | 62.739 [44.023~70.145] | 20.254 [12.430~23.933] | 67.7% |
| pep621/100 | 114.366 | 121.786 [84.592~195.262] | 29.227 [20.773~40.714] | 76.0% |
| poetry/10 | 16.073 | 15.463 [10.768~21.562] | 7.606 [6.464~11.601] | 50.8% |
| poetry/50 | 58.031 | 63.779 [49.590~72.744] | 16.286 [14.196~21.659] | 74.5% |
| poetry/100 | 120.807 | 115.019 [92.618~147.365] | 26.784 [21.550~38.227] | 76.7% |
| shared/cpu | 96.712 | 102.657 [86.040~121.950] | 41.218 [33.865~85.707] | 59.8% |
| shared/latency | 711.740 | 176.275 [145.192~252.233] | 101.402 [91.214~123.842] | 42.5% |
| requirements/500-file-stderr | 743.284 | 799.112 [720.697~895.463] | 151.154 [123.426~205.801] | 81.1% |

최종 측정의 requirements 500개는 HEAD 자체도 최초 진단보다 느렸다.
이처럼 절대 시간은 실행 시점에 따라 크게 달라졌다. 최종과 최초 진단을 서로 섞어 개선율을 계산하지 않았다.
짧은 재귀 사례는 변동 폭이 커 작은 중앙값 차이를 확정적인 개선으로 해석하지 않는다.
주요 개선은 호출 횟수 감소와 함께 큰 입력에서 확인됐다.

원본 벤치마크 재실행 결과는 final-confirmed/original-*.txt에 있다.
원본 스크립트는 고유 반복 수(5/10회)와 출력 동작을 유지했으므로 위의 워밍업·교차 통계와 구분한다.

## Mock CPU 비용과 API 절감 효과의 분리

합성 그래프는 직접 parent 60개가 같은 shared의 세 요구 범위를 반복 참조한다.
출력은 부모 60개 + 실제 shared 두 버전 = 62개 노드다.
HEAD는 버전 목록 180회, 정확도 개선본/최종본은 1회이며 메타데이터는 모두 62회다.
각 조건은 같은 버전 목록에서 각각의 최신 적합 버전을 고른다.

지연 사례는 버전 조회에 time.sleep(0.002), 메타데이터 조회에 time.sleep(0.0005)를 넣었다.
실제 외부 HTTP 측정이 아니며 OS 스케줄링에 따라 실제 sleep은 지정 시간보다 길 수 있다.
지연이 없는 Mock의 단순 함수 호출 절감과 네트워크 대기 절감은 같은 수치로 해석하지 않는다.

캐시 효과만 분리하기 위해 최종 파서 사본 두 개를 만들고 한 사본만 _resolve_version 진입 시 캐시를 비웠다.
제품 코드는 변경하지 않았다. 모든 정확도·충돌 로직이 동일한 두 사본을 3회 워밍업·15회 교차 측정했다.
모든 샘플에서 전체 노드·선언 데이터가 같음을 확인했다.

| 캐시 대조 사례 | 캐시 없음 중앙값(ms) | 캐시 있음 중앙값(ms) | 버전 목록 없음→있음 | 메타데이터 |
|---|---:|---:|---:|---:|
| shared/cpu | 29.200 | 26.633 | 180→1 | 62→62 |
| shared/latency | 591.838 | 72.763 | 180→1 | 62→62 |

기존 benchmark_api_calls.py도 임시 사본에서 다시 실행했다.
버전 목록 1회·메타데이터 3회·노드 3개로 이전 api-calls-after.json 전체와 일치했다.
최초 캐시 도입 전 2→1회 절감 효과도 유지된다. 기존 before/after JSON은 덮어쓰지 않았다.

## 정확성 및 최종 검증

- 제어 벤치마크 17개 모든 샘플에서 HEAD/정확도 개선본/최종본의 그래프 해시가 일치했다.
- 정확도 개선본/최종본의 전체 노드·선언 데이터 해시도 17개 사례 모두 일치했다.
- 기존 88개 테스트를 모두 실행하고 신규 회귀 3개를 추가해 관련 테스트는 91개다.
- 신규 3개는 이름 정규화·버전 범위·다중 후보 모호성·비활성 marker,
  -r 참조 출처/ID, PEP 621·Poetry 상대 경로와 오류 출처 보존을 검사한다.
- 전체 CI는 main 340 + security-review 95 + legacy-parser 26 = 461 PASS다.
  실패·오류·건너뛰기 0이며 Java 임시 컴파일·Flask 정확도·CycloneDX 및 보안 정책 검증도 통과했다.
- 실제 microblog는 이전 PyPI/OSV 스냅샷으로 재분석했다. 추가 외부 조회는 하지 않았다.
  raw parser.json은 완전히 같고 통합 graph.json은 조회 시각 4개 필드만 달랐다.
  queried_at/resolution_queried_at을 제외하면 통합 JSON 전체가 같다.
- microblog의 노드 56개·관계 57개·패키지별 취약점 매칭 60개가 유지됐다.
  55개 OSV 응답을 재사용했고 오류 0건이다. 버전 미확정 1개는 기존대로 건너뛰었다.
- 실제 microblog SBOM의 공식 스키마·참조 무결성도 통과했다.
  비교 과정에서 SBOM serialNumber/생성 시각은 실행별 메타데이터로 취급한다.
- 직접 고정·충돌·extras·marker·재귀·PURL·CVE 매칭 정책과 SBOM·대시보드 전달 회귀도 모두 통과했다.
- git diff --check 통과. GitHub Actions 원격 실행은 수행하지 않았다.

## 이번 작업의 변경 파일

기존 정확도/캐시 변경을 보존한 상태에서 이번에 추가로 바꾼 제품 코드는 두 파일이다.

- python-parser/python_parser.py: 정규화 이름별 후보 목록, 확인된 출처 경로 재사용
- python-parser/toml_parser.py: 문서 단위 canonical source의 PEP 621·Poetry·오류 진단 재사용

신규 테스트·검증 및 문서:

- python-parser/test/test_declaration_linking.py: 신규 회귀 3개
- ci/benchmark_parser_comparison.py: 격리·워밍업·교차 실행·프로파일·원본 벤치마크 실행기
- ci/benchmark_cache_effect.py: 최종 코드의 캐시 단독 대조 실행기
- ci/run_checks.py: 신규 3개를 반영한 main 예상 수 340
- ci/README.md 및 .github/workflows/python-tests.yml: 전체 예상 수 461
- docs/week12-performance-analysis.md: 이 보고서
- performance-results/week12-performance/: 신규 측정·프로파일·검증 증거

cyclonedx_converter.py, dashboard_export.py, integrated_parser.py, dependency_node.py,
python_security_adapter.py 및 기존 회귀 파일의 이전 로컬 변경은 이번 성능 작업에서 추가 수정하지 않았다.

## 증거 경로 및 재실행

모든 새 출력 경로는 존재하지 않는 디렉터리여야 한다.

- diagnosis/: 제품 수정 전 HEAD/현재 코드 비교, 원시 샘플·사본·해시·cProfile
- final/: 첫 개선 측정. Poetry 잔여 경로를 발견한 중간 결과로 보존
- final-confirmed/: 최종 3개 변형 비교. 최종 보고의 시간 근거
- cache-control/: 캐시 단독 대조, 원시 샘플·사본·해시
- api-calls.json: 기존 소형 API 벤치마크 재실행 결과
- ci/: 최종 461개 CI 로그·JUnit·정확도·SBOM 증거
- microblog-final/: 실제 입력의 파서·통합 JSON·SBOM·PyPI 재현 응답
- microblog-security/: 이전 정확도 개선본과 최종본의 OSV·매칭·대시보드·SBOM 비교
- validation.json: 전체 데이터 동일성·테스트·보존 결과

```powershell
$env:PYTHONUTF8 = '1'
$env:PYTHONDONTWRITEBYTECODE = '1'
python -B ci/benchmark_parser_comparison.py --output performance-results/performance-new --reference accuracy=performance-results/week12-performance/diagnosis/variants/current
python -B ci/benchmark_cache_effect.py --output performance-results/cache-control-new
python -B ci/run_checks.py --output performance-results/performance-ci-new
python -B ci/measure_python_conflicts.py ../microblog/requirements.txt --output performance-results/microblog-performance-new --snapshot performance-results/week12-accuracy/microblog-before/pypi-snapshot.json
```

실행 환경은 Python 3.14.3, packaging 26.3, pytest 9.1.1, Windows 11이다.
CI Java는 JDK 25.0.3에서 --release 17로 임시 사본만 컴파일했다.
Windows의 process_time 해상도 때문에 짧은 사례 CPU 중앙값이 0으로 기록될 수 있어 벽시계·프로파일과 함께 해석했다.

## 보존 확인

작업 시작 시 존재한 미추적 파일 및 target/classes 파일 217개의 SHA256이 모두 유지됐다.
기존 Java target/classes 전체 70개 파일도 CI 전후 동일하다.
기존 benchmark 스크립트, before/after 결과, 로그, 테스트 산출물, 정확도·캐시 회귀와 보고서를 덮어쓰지 않았다.
HEAD 추출과 캐시 대조 변경은 새 variants 사본에만 수행했다.
이전 로컬 제품 변경을 바탕으로 위의 필요한 성능 개선을 추가했으며 되돌리기 작업은 수행하지 않았다.

측정 원본과 개인 검증 산출물은 로컬에 보존하며 이 저장소에는 포함하지 않는다. 위의 핵심 결과와 공개 검증 실행기로 검토·재현한다.
