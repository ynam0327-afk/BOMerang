# 12주차 최종 정리 및 반영 검증

검증일: 2026-11-10 (Asia/Seoul).

## 반영 범위

기준 커밋은 6d92b684571634440e42bec39bdb04768495818b이며 최종 정리 시작 시 최신 origin/main과 일치했다.
12주차 변경은 버전 목록 캐시, 직접 고정 버전·충돌 정보 전달, 선언 후처리 성능 개선의 세 커밋으로 나눈다.
각 단계의 소스는 별도 인덱스 내용으로 선별하며 현재 작업 파일을 과거 버전으로 덮어쓰지 않는다.

## 최종 로컬 검증

| 검증 | 결과 |
|---|---:|
| Python 파서·정확도 회귀 | 기존 88 + 신규 3 = 91 PASS |
| 전체 CI main | 340 PASS |
| security-review | 95 PASS |
| legacy-parser | 26 PASS |
| 전체 CI | 461 PASS, 실패·오류·건너뛰기 0 |
| Java exporter/bridge 임시 사본 컴파일 | PASS |
| Flask 선언 정확도 | TP=32, FP=0, FN=0 |
| CycloneDX 스키마·참조 및 기존 보안 정책 검증 | PASS |
| target/classes 보존 | 전체 70개 파일 SHA256 동일 |

최종 CI는 다시 실행한 로컬 결과다. GitHub Actions 원격 실행 성공을 의미하지 않는다.
수치·재현 방법·한계는 [성능 분석](week12-performance-analysis.md),
[정확도 분석](week12-python-parser-accuracy.md), [최초 캐시 검증](week12-python-parser-optimization.md)에 있다.

성능 제어 비교 17개 사례에서 노드·관계·선언 데이터가 일치했다.
실제 microblog는 노드 56개, 관계 57개, 패키지별 취약점 매칭 60개를 유지했다.
버전 목록 캐시의 기존 소형 검증은 1회 조회와 메타데이터 3회를 유지한다.
입력이 확인되지 않은 최초 urllib3==2.0.7 보고는 별도 미확인 사례로 남긴다.

## 커밋에 포함하는 전체 파일

- `.github/workflows/python-tests.yml`
- `benchmark_api_calls.py`
- `benchmark_python_parser.py`
- `benchmark_recursive_parser.py`
- `benchmark_toml_parser.py`
- `ci/README.md`
- `ci/benchmark_cache_effect.py`
- `ci/benchmark_parser_comparison.py`
- `ci/compare_python_conflicts.py`
- `ci/measure_python_conflicts.py`
- `ci/run_checks.py`
- `cyclonedx_converter.py`
- `dashboard_export.py`
- `docs/week12-performance-analysis.md`
- `docs/week12-python-parser-accuracy.md`
- `docs/week12-python-parser-optimization.md`
- `docs/week12-release-validation.md`
- `integrated_parser.py`
- `python-parser/dependency_node.py`
- `python-parser/python_parser.py`
- `python-parser/test/test_declaration_linking.py`
- `python-parser/test/test_python_parser_core.py`
- `python-parser/test/test_version_list_cache.py`
- `python-parser/toml_parser.py`
- `python-security-integration/python_security_adapter.py`
- `test_python_dependency_conflicts.py`

루트 벤치마크 4개는 검증 실행기가 사용하는 재현 코드이므로 포함한다.
신규 회귀 test_version_list_cache.py, test_python_dependency_conflicts.py,
test_declaration_linking.py와 기존 정책 회귀 수정도 모두 포함한다.

## 로컬 보존 및 제외

Java .class, .vscode, microblog 로그·JSON, parser-debug.log, accuracy-tests/pypi-extras-live/,
performance-results/ 및 개인 테스트 산출물은 보존하되 커밋하지 않는다.
기존 제외 파일 511개의 SHA256을 기록해 전후 동일성을 검사한다.
문서 정리 전 원본은 Git에서 제외되는 test-results/ 아래 별도 폴더에 백업했다.
초기 캐시 문서의 한글 인코딩만 검증된 결과로 복구하고 단계별 과거 검증과 최종 정리를 구분했다.
.gitignore는 변경하지 않았다. reset, 강제 push, 잠금 파일 삭제는 사용하지 않는다.
Git 잠금 오류가 발생하면 강제로 정리하지 않고 중단한다.

캐시·정확도 단계는 각각 커밋할 트리의 격리 사본에서 68개·88개 테스트를 통과했다. 최종 트리도 별도 사본에서 검증한다.
기존 benchmark_python_parser.py 빈 줄 한 곳의 후행 공백만 정리했으며 AST가 동일함을 확인했다. 원본 바이트는 로컬 source-backups에 보존했다.
