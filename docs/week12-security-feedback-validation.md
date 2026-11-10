# 12주차 보안 피드백 후속 검증

검증일: 2026-11-10 (Asia/Seoul). 기준 코드는 b76b3eaadb193036b1bbfb8432d45e7318904c2a이다.
이 문서는 보안 피드백의 로컬 분석·검증 기록이다. 초기 분석 단계에서는 push·merge·reset 및 기존 파일 삭제/초기화를 수행하지 않았다.

## 결과 요약

| 피드백 | 확인 결과 | 조치 |
|---|---|---|
| 두 보안 테스트가 scored 2를 기대하나 pending 1 발생 | Maven 비교 bridge 없는 사본에서 동일하게 재현 | 합성 테스트에 명시적 affected 버전 근거 추가. 실제 범위 검증 불가 시 보류 정책 유지 |
| urllib3 2.0.7/2.8.0 중복 | 최초 2.0.7 입력 미확인. 현재 실제 입력은 2.1.0이며 세 단계 모두 1개 | 최신 코드와 동일 PyPI 스냅샷으로 재검증. 원본 사례 해결 단정 안 함 |
| peppercorn unresolved | 실제 입력·과거 로그·현재 메타데이터에서 해당 사례를 찾지 못함 | 미확인으로 남김. 실제 확인된 pip 미확정 원인과 범주별 회귀를 기록 |
| CVSS 부재/버전 불확정/매칭 보류 혼동 | 점수 수식 오류가 아닌 상태·근거 전달 보완 필요 | 미확정 원인·조회 평가 상태·매칭 근거를 통합 결과와 대시보드 생성 데이터에 보존 |
| Python/Java 24건 + Maven 1건 skip | exporter .class 없는 사본에서 정확히 재현 | 원본을 지우지 않고 임시 사본으로 확인. 공식 CI는 컴파일 후 skip 0 |
| Gradle 및 모바일·반응형 화면 | Gradle 이름을 가진 11개 CI 사례 통과. 별도 화면/URL은 미확인 | 정적 분석 지원 범위와 UI 검증 범위를 구분 |

기존 전체 CI 461 PASS를 수정 전에 재확인했다. 수정 후에는 기존 461개와 신규 17개가 모두 통과해
전체 478 PASS, 실패·오류·건너뛰기 0이다. 파서/정확도/보안 관련 직접 실행은 142 PASS다.

## 1. 두 보안 통합 테스트 실패

관련 테스트:

- python-security-integration/test_integrated_security.py::Tests::test_mixed_full_pipeline
- test_security_sbom_pipeline.py::test_security_pipeline_to_cyclonedx

현재 작업 폴더에서는 두 테스트 모두 통과했다.
ci.run_checks.stage_sources()로 .class를 복사하지 않는 임시 사본을 만들자 두 테스트 모두
expected={'scored': 2}, actual={'pending': 1, 'scored': 1}로 실패했다.
원본 .class는 삭제하지 않았다.

두 테스트는 합성 Maven g:a@1.0과 Python demo@1.9를 분석하며 합성 NVD 응답에 숫자 CVSS 8.0이 있다.
Maven 쪽 OSV 데이터는 introduced=0, fixed=2.0의 범위만 가지고 있었다.
MavenComparisonServer.class가 없으면 Maven ComparableVersion을 실행하지 못하고,
범위 비교는 unknown, 우선순위는 pending으로 남는다.

호출 경로는 maven_version_compare.compare → osv_version_matcher.evaluate_range →
local_version_validation.status=unknown → risk_model.calculate이다.
보류 사유는 version_match_not_affected_or_unconfirmed이며 selected_cvss.score=8.0은 존재한다.
따라서 이 두 실패를 CVSS 누락이나 점수 계산 오류로 해석하면 안 된다.

scored 2 기대값은 두 항목의 영향 버전을 입증할 수 있는 환경/데이터에서는 타당하지만,
범위 비교기를 준비하지 않은 실행에서는 그 전제가 충족되지 않았다.
기대값을 무조건 scored 1로 바꾸거나 unknown을 affected로 바꾸지 않았다.

최소 수정은 합성 FakeSecurity의 Maven OSV 응답에 versions=[조회한 합성 버전]을 추가하는 것이다.
실제 OSV matcher가 원래 지원하는 명시적 affected 버전 근거를 사용한다.
점수는 기존 합성 NVD 8.0에서 계산하며 새로운 점수를 만들어 넣지 않는다.
Python 범위 fixture는 그대로 유지했다.

수정 후 .class 없는 사본에서도 두 테스트가 통과했다.
별도 신규 회귀는 명시적 버전 근거 없이 범위만 있고 비교기가 없으면 계속 pending임을 검사한다.
Maven 범위 비교 자체는 공식 CI에서 실제 Java bridge를 컴파일해 기존 테스트로 검증한다.
실제 운영의 Maven 범위 분석에는 Java 및 bridge/lib 준비가 여전히 필요하다.

## 2. 24개 + 1개 skip과 Gradle

서로 다른 두 Java 전제 조건을 구분해야 한다.

| 전제 조건 | 없을 때의 현상 |
|---|---|
| target/classes/com/bomerang/JsonDependencyExporter.class | Python/Java 통합 테스트 24개와 원격 Maven 테스트 1개가 명시적으로 skip |
| src/main/java/com/bomerang/bridge/MavenComparisonServer.class 및 Maven JAR | 범위-only Maven 매칭을 입증하지 못해 점수 pending |

skip을 실패로 바꾸거나 가짜 exporter로 대체하지 않았다.
공식 ci/run_checks.py는 임시 사본에서 exporter와 bridge를 --release 17로 컴파일한다.
최종 전체 CI는 478개 모두 실제 실행됐고 skip 0이다.

Gradle 관련 이름을 가진 CI 사례 11개는 전부 통과했다.
Groovy/Kotlin의 Python 혼합 분석, runtime/test/provided 범위 및 출처 매핑을 포함한다.
libs 카탈로그와 project 의존성은 기존 지원 범위 밖임을 확인하는 테스트도 포함한다.
따라서 11개 통과를 모든 동적 Gradle 빌드/플러그인 지원으로 해석하지 않는다.
팀원이 실행한 실제 Gradle 입력·명령은 제공되지 않아 별도 기본 분석 오류는 확정하지 못했다.

저장소의 대시보드는 dashboard_export.py 응답 생성 계약이며,
분석 fixture인 Flask 원본을 제외하면 별도 프런트엔드/모바일·반응형 화면 구현은 찾지 못했다.
실제 화면 URL·별도 저장소·실패 재현 경로가 없어 모바일 화면 수정/검증은 미완료다.
이번 검증은 API 응답 생성 데이터까지이며 실제 배포된 HTTP API/화면 성공을 주장하지 않는다.

## 3. urllib3 재검증

실제 입력은 ../microblog/requirements.txt이며 requests==2.31.0과 urllib3==2.1.0이 직접 선언돼 있다.
PyPI에서 저장한 requests@2.31.0의 requires_dist는 urllib3 (<3,>=1.21.1)이다.
직접 고정 2.1.0은 이 조건을 만족한다.

최신 코드로 입력을 다시 분석하고 동일 저장 PyPI 응답을 사용해 변경 전후를 비교했다.
실시간 레지스트리 시점 차이를 버전 정책 변화로 오인하지 않도록 한 재현 실험이다.

| 단계 | urllib3 결과 |
|---|---|
| PythonParser 단독 | pkg:pypi/urllib3@2.1.0 한 개 |
| 통합 JSON | 동일한 PURL 한 개 |
| CycloneDX SBOM | 동일한 컴포넌트 한 개 |

requests 연결은 계속 2.1.0을 가리킨다. raw parser.json은 수정 전후 완전히 같다.
통합 JSON의 기존 필드도 조회 시각을 제외하면 같으며 resolution_reason/reasons만 추가됐다.
실제 microblog는 노드 56개·의존 관계 57개·패키지별 취약점 매칭 60개를 유지한다.
CycloneDX 스키마와 참조 무결성도 통과했다.

기존 직접 고정 우선·호환 연결·비호환 시 직접 노드 보존 및 미해결 연결·다중 고정 충돌 정책은
기존 test_python_dependency_conflicts.py 회귀로 모두 확인했다.
이번 작업에서는 PythonParser, toml_parser, PURL/재귀/캐시 구현을 변경하지 않았다.

최초 urllib3==2.0.7과 2.8.0 보고의 입력/실행 경로는 여전히 미확인이다.
이를 해결했다고 단정하지 않는다. 합성 회귀에 쓰는 2.0.7도 그 원본 사례 재현 증거가 아니다.

## 4. 버전 미확정 원인

peppercorn은 현재 microblog 입력, 확인한 과거 microblog 결과/로그,
현재 재현용 PyPI 메타데이터에서 확인되지 않았다. 원래 입력이나 부모 메타데이터가 필요하다.
peppercorn을 버전 없는 전이 의존성으로 만든 신규 합성 테스트는 정책 검증이며 실제 사례 확인이 아니다.

실제 확인된 미확정 패키지는 pip이다.
저장된 httpie@3.2.2 requires_dist에 정확히 pip라는 조건 없는 요구가 있고,
직접 pip 고정 선언도 없다. parser는 조건이 없으면 목록 API를 호출해 최신 버전을 추정하지 않는다.
PyPI 스냅샷에서도 pip 버전 목록 조회가 없으며 오류·충돌도 없다.
이는 버전 선언 부재에 따른 정책상 unresolved다. 가용 최신 버전을 임의로 넣지 않았다.

보안 어댑터가 기존 근거에서 아래 원인을 분류하도록 했다.

| resolution_reason | 의미/확인 근거 |
|---|---|
| missing_version_specifier | 직접/전이 요구에 조건이 없고 고정 버전 재사용 근거도 없음 |
| version_lookup_failed | 미해결 노드의 버전 조회 오류. resolution_error에 예외 정보 유지 |
| no_matching_version | 선언 범위에 맞는 후보를 선택하지 못함 |
| dependency_conflict | 기존 구조화된 직접 고정/범위 충돌 기록이 존재 |
| unsupported_declaration | 이름은 추출됐지만 URL 버전 소스 해석을 지원하지 않는 경우 |

확정된 버전에서 메타데이터 탐색만 실패한 경우 resolution_reason은 null이다.
그 경우는 기존 graph_resolution_status=partial_parse_error와 parser_error로 구분한다.
같은 PURL의 여러 출처에서 식별된 원인은 resolution_reasons로 합치고 오류 정보도 보존한다.
정상 버전 선택 결과나 확정·추정·미확정 정책은 바꾸지 않았다.

미지원 Poetry table 형식은 기존 통합 declaration_errors의 메시지로 확인하며 없는 패키지 노드를 만들지 않는다.
모든 pip 옵션·선언 형식을 새로 지원하거나 정적 오류 목록을 대시보드 패키지 목록으로 변환하는 작업은 하지 않았다.

## 5. 보류·조회·매칭·검토 상태를 구분

우선순위 수식, CVSS 선택 순서 및 기본 가중치 구현은 변경하지 않았다.
앱 기본 경로는 python-security-integration/risk_model.py와 integrated_security.pipeline이다.
기본 표시 CVSS 100%, 깊이 0%이며 priority_score는 기본적으로 CVSS baseScore의 10배다.
점수가 없으면 null/pending이고, 실제 숫자 CVSS 0.0이면 정상적인 scored/0.0이다.
실제 발생 조건은 평가하지 않아 application_status=unreviewed를 유지한다.

협의된 깊이 20%는 별도 실험으로 보관한다. 팀에서 전달한 순위 역전 7쌍 확인 내용을 기본 표시로 승격하지 않는다.
본 작업은 그 순위쌍의 원본 데이터가 없어 7쌍을 다시 재현한 실험이 아니다.
기존 실험 설정·결과를 보존하고 기본 대시보드가 실험 가중치를 거부하는 회귀를 유지했다.

새 상태는 scan → normalize → match → priority → dashboard 생성 데이터에 그대로 전달한다.

- security_assessment_status: OSV 조회를 완료했으면 assessed, 버전 미확정/조회 실패 등으로 평가하지 못하면 not_assessed.
  assessed는 조회 완료라는 뜻이며 영향 버전 확정·점수 산정·실제 발생 검토 완료와 다르다.
- security_assessment_reason: package_version_unresolved, vulnerability_lookup_failed 또는 지원하지 않는 생태계/좌표 등의 사유.
- resolution_reason/reasons/error: 패키지 버전 미확정의 구체적 원인.
- findings.version_match_evidence: 범위 비교기 부재 등 unknown 매칭의 실제 근거.
- 기존 findings.priority_reason/score/status 및 application_status: 유지.

| 경우 | 조회/매칭 | 점수/화면용 상태 |
|---|---|---|
| 숫자 CVSS 없음, 버전 affected | vulnerabilities_found + affected | missing_numeric_cvss, pending, null, 미검토 |
| 패키지 버전 미확정 | skipped + not_assessed | package_version_unresolved. 취약점 조회·점수 산정 미실시, findings=[] |
| 숫자 CVSS는 있으나 범위 검증 unknown | 후보 취약점은 있으나 영향 버전 미확정 | version_match_not_affected_or_unconfirmed, pending, null |
| 실제 CVSS 0.0과 affected 근거 | affected | scored, 0.0. 데이터 누락과 다름 |
| 조회 성공·알려진 취약점 없음 | no_known_vulnerabilities + assessed | findings=[]이며 미실시와 구별 |
| 조회 실패 | lookup_failed + not_assessed | vulnerability_lookup_failed. 안전하다는 결론을 내리지 않음 |

실제 pip의 대시보드 생성 데이터는 아래와 같다.

```json
{
  "name": "pip",
  "resolved_version": null,
  "version_status": "unresolved",
  "lookup_status": "skipped",
  "security_assessment_status": "not_assessed",
  "security_assessment_reason": "package_version_unresolved",
  "resolution_reason": "missing_version_specifier",
  "findings": []
}
```

이번 실제 microblog OSV 재현은 nvd=False다. 60개 affected 매칭의 점수는 숫자 CVSS가 수집되지 않아 pending이다.
이는 실제 외부 NVD에 CVSS가 존재하지 않는다는 확인이 아니다. 신규 외부 NVD 요청/벡터의 임의 수치 변환은 하지 않았다.
실제 외부 API의 응답 전달과 화면 렌더링은 팀 서비스에서 추가 확인해야 한다.

## 6. 검증 결과와 변경 파일

| 검증 | 결과 |
|---|---:|
| 수정 전 공식 CI | 기존 461 PASS |
| 원래 두 테스트: 작업 폴더 | 2 PASS |
| 원래 두 테스트: bridge 없는 임시 사본 | 수정 전 2 FAIL, 수정 후 2 PASS |
| class 없는 사본의 통합/원격 테스트 | 24 + 1 skip 재현 |
| 최종 파서·정확도·보안 관련 직접 실행 | 142 PASS |
| 신규 회귀 | 17 PASS |
| 최종 CI main | 357 PASS |
| security-review / legacy-parser | 95 / 26 PASS |
| 전체 CI | 478 PASS, 실패·오류·건너뛰기 0 |
| Gradle 이름을 가진 CI 사례 | 11 PASS |
| 기존 소형 API 벤치마크 | 버전 목록 1회, 메타데이터 3회, 노드 3개 |
| 기존 파일 보존 | 512개 SHA256 동일, target/classes 70개 유지 |
| git diff --check | PASS |

신규 회귀는 비교기 없는 명시적 버전/범위-only, CVSS 부재·0점, 버전 미확정·조회 실패·무취약점,
기본/실험 가중치 구분, 미확정 원인 6종, 미지원 Poetry table, 병합 원인 보존, 버전 없는 전이 의존성을 검사한다.

수정 파일:

- python-security-integration/test_integrated_security.py: 합성 Maven fixture의 명시적 버전 근거
- python-security-integration/python_security_adapter.py: 미확정 원인 분류 및 병합 보존
- python-security-integration/week7_scan.py: 조회 평가 상태·사유
- python-security-integration/normalize_week7.py: 새 상태 필드 전달
- dashboard_export.py: 미확정 사유·조회 평가·매칭 근거 보존
- test_security_feedback.py: 신규 17개 회귀
- ci/run_checks.py, ci/README.md, .github/workflows/python-tests.yml: 새 회귀 목록/총 478개
- docs/week12-security-feedback-validation.md: 이 보고서

위험도 모델 두 사본, Python 파서 성능 핵심, Java 소스·클래스, 기존 벤치마크는 변경하지 않았다.
기존 .class 수정 상태는 작업 이전 상태 그대로이며 Git diff에 보이더라도 이번 수정이 아니다.
Git 커밋·push·merge·reset은 하지 않았다.

## 로컬 증거와 재실행

증거는 Git에서 제외되는 test-results/week12-security-feedback-j4msfdv9/ 아래 신규 파일로 저장했다.
기존 로그·JSON·벤치마크 결과를 덮어쓰지 않았다.

- reported-tests-workspace-before.txt / reported-tests-missing-bridge-before.txt: 실패 재현
- without-class-after.txt: 수정 후 두 테스트와 24+1 skip
- ci-before/ 및 ci-after/: 기존 461개와 최종 478개 CI 로그·JUnit·정책 검증
- related-tests-final.txt: 관련 142개 실행
- microblog-before/ 및 microblog-after/: 실제 입력의 파서·통합 JSON·SBOM·PyPI 스냅샷
- microblog-security/: 동일 OSV 응답으로 비교한 정규화·매칭·점수·대시보드·SBOM
- api-calls.json / gradle-tests.json / validation.json: 호출 수·Gradle 목록·불변성 검증
- preservation-before.json: 기존 파일 SHA256

```powershell
$env:PYTHONPATH = '.;python-parser;python-security-integration'
$env:PYTHONUTF8 = '1'
$env:PYTHONDONTWRITEBYTECODE = '1'
python -B -m pytest --import-mode=importlib -p no:cacheprovider -q python-parser/test test_python_dependency_conflicts.py python-security-integration/test_integrated_security.py python-security-integration/test_risk_model.py test_security_sbom_pipeline.py test_security_feedback.py
python -B ci/run_checks.py --output test-results/security-feedback-new
```

출력 경로는 매번 존재하지 않는 새 경로를 사용한다.
환경은 Windows 11/Python 3.14.3이며 공식 CI는 임시 사본에서 --release 17로 Java를 컴파일했다.
GitHub Actions 원격 실행은 하지 않았다.

## 남은 확인 사항

1. 최초 urllib3==2.0.7 사례의 입력과 당시 실행 명령.
2. 실제 peppercorn이 나타난 입력 또는 부모 requires_dist/lockfile 근거.
3. 팀원이 실행한 실제 Gradle 기본 분석 파일·명령.
4. 별도 대시보드/모바일·반응형 저장소 또는 화면 URL 및 재현 경로.
5. 외부 팀 서비스가 새 사유 필드를 누락 없이 전달·표시하는지 여부.

위 항목은 확인된 것으로 단정하지 않으며, 실제 버전이나 점수를 임의 확정하지 않는다.

## 최종 반영 검증

보안 피드백 관련 소스 4개, 테스트 2개, CI 3개, 이 문서 1개만 반영 대상으로 선별했다.
커밋할 Git 트리의 격리 사본에서 전체 CI 478개를 최종 재실행한다. 원시 로그·JSON·개인 산출물과 기존 Java 클래스는 제외한다.
정상적인 main push만 사용하며 reset·강제 push·잠금 파일 강제 삭제는 하지 않는다. 최종 커밋 해시는 Git 이력에서 확인할 수 있다.
