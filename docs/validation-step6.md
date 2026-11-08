# BOMerang 10~11주차 최종 검증 및 CI 통합 보고서

작성일: 2026-11-08 (Asia/Seoul)

로컬 CI 실행기로 429개 테스트가 통과했습니다. 실패·오류·건너뛰기는 0개입니다.
GitHub Actions 원격 실행은 수행하지 않았습니다. 이 보고서의 성공 결과는 Windows 로컬 실행 결과입니다.

## 1. CI 변경 전후

| 항목 | 기존 | 변경 후 |
|---|---|---|
| job | Python 단위 / 통합 2개 | offline-verification 1개 |
| Python | 3.14 | 유지 |
| Java | Temurin 17 (통합 job) | 유지 |
| Actions | checkout v7, setup-python v7, setup-java v6, upload-artifact v7 | 유지 |
| 테스트 | Python 단위 및 통합 3개 파일 | 명시적 3프로세스, 전체 429개 |
| Java 출력 | checkout의 target/classes와 src/bridge | 임시 사본에서 소스 컴파일 |
| 스키마 / Flask 소스 평가 | 없음 | 로컬 공식 스키마·참조 검사 / 고정 소스 평가 |
| 위험도 정책 | 전용 gate 없음 | 기본 CVSS100, 보류·미검토 및 실험 분리 검사 |
| 결과 | 제한된 JUnit | 전체 JUnit·로그·정책 JSON·Flask·SBOM·스키마 결과 |

트리거(main push/PR 및 workflow_dispatch), contents:read 권한은 유지했습니다.
Actions 버전은 공식 저장소에서 확인했고 업데이트하지 않았습니다.
출처: https://github.com/actions/checkout ; https://github.com/actions/setup-python ;
https://github.com/actions/setup-java ; https://github.com/actions/upload-artifact

## 2. 파일 변경 범위

수정: `.github/workflows/python-tests.yml`

추가: `ci/run_checks.py`, `ci/verify_artifacts.py`, `ci/requirements.txt`, `ci/README.md`,
이 보고서와 `test-reports/step6/`의 원본 백업·해시·실행 결과.

제품 코드, 기존 테스트 및 gold는 수정하지 않았습니다.
STEP 6 시작 시점 파일 332개의 해시를 baseline.json으로 기록했습니다.
실행 종료 후 원래 파일 중 변경된 것은 의도한 workflow 하나뿐입니다.
원본 target/classes 70개 파일의 해시가 동일하며 기존 복구 상태도 유지됩니다.
commit/push/merge, git restore/clean/reset을 실행하지 않았습니다.

## 3. 환경과 재현 명령

실측: Windows 11, CPython 3.14.3, Zulu OpenJDK/Javac 25.0.3.
Java는 --release 17로 새로 컴파일했습니다. 로컬 Java 17 런타임 검증은 수행하지 않았습니다.
pytest 9.1.1, packaging 26.3, requests 2.34.2, jsonschema 4.26.0, referencing 0.37.0.
ci/requirements.txt는 직접 의존성을 해당 버전으로 고정합니다. 전이 의존성 전체 lock은 아닙니다.

```text
python -m pip install -r ci/requirements.txt
python -B ci/run_checks.py --output test-results/verification
```

실제로 실행한 최종 명령:

```text
python -B ci/run_checks.py --output test-reports/step6/local-run-2
```

run_checks.py의 MAIN/SUITES에 정확한 pytest 대상과 PYTHONPATH가 정의되어 있고,
local-run-2/summary.json에 실제 명령이 저장되어 있습니다.
각 pytest 프로세스는 `--import-mode=importlib -p no:cacheprovider -q`를 사용합니다.
출력 폴더 재사용은 거부되므로 재실행 시 새 이름을 사용하세요.

## 4. 전체 테스트 실측

| 구분 | 통과 | 실패 | 오류 | 건너뛰기 |
|---|---:|---:|---:|---:|
| main | 308 | 0 | 0 | 0 |
| security-review | 95 | 0 | 0 | 0 |
| legacy-parser | 26 | 0 | 0 | 0 |
| 합계 | 429 | 0 | 0 | 0 |

main의 세부 구성: Python 파서 59, 통합 24, CycloneDX 8, 보안 SBOM 3,
로컬 Maven 전이 1, 보안 통합 13, 기본 위험도 18, STEP 2 평가 34,
STEP 3 선언 보존 45, STEP 4 혼합 통합 39, STEP 5 보안 64.
95개는 기존 OSV·버전·Maven 비교·위험도·리뷰 등 회귀이며 레거시 파서는 26개입니다.
기존 365개 + STEP 5 신규 64개이며 STEP 6에서 테스트 개수를 새로 늘리지 않았습니다.
JUnit: local-run-2/main.xml, security-review.xml, legacy-parser.xml.

첫 실행(local-run-1)은 428 통과 / 1 실패였습니다.
임시 사본에 STEP 2 원본 결과 JSON을 복사하지 않아 fallback 회귀가 실패했습니다.
기존 테스트 기대값이나 정답을 바꾸지 않고 실행기의 복사 목록만 보완했습니다.
첫 실패 결과도 보존했습니다. 최종 실행은 모든 테스트를 다시 실행했습니다.

Java JUnit은 미실행입니다. Java exporter/bridge의 새 소스 컴파일,
로컬 Maven HTTP 전이 파싱 및 임시 소스 컴파일 동등성 테스트는 실행했습니다.

## 5. Flask 정확도

pallets/flask 3.1.2, commit `2c1b30d0503cfb064f1cb252e6614a06915a362a`.
기존 pyproject.toml 스냅샷과 gold/flask.json을 변경하지 않았습니다.
기존 평가기의 --declarations 모드 및 오프라인 PyPI 클라이언트를 재사용했습니다.

| 정적 직접 선언 지표 | STEP 2 보존 결과 | STEP 6 재측정 |
|---|---:|---:|
| TP | 6 | 32 |
| FP | 0 | 0 |
| FN | 26 | 0 |
| Precision | 100% | 100% |
| Recall | 18.75% | 100% |
| F1 | 31.58% | 100% |

현재 환경 marker 활성 선언은 30/30 탐지(기존 활성 Recall 20% → 100%)입니다.
전체 선언 32개, 원문 보존 32개, 선언 패키지 27개, 런타임 그래프 노드 6개입니다.
정적 선언 32개를 실제 설치된 패키지 32개로 해석하지 않습니다.
버전 해석은 외부 조회 없이 수행하며 설치 버전 검증이 아닙니다.
실측: local-run-2/flask.json 및 flask-integrated.json.
과거 결과 출처: accuracy-tests/step3/comparison.json, 기존 STEP 2 결과.
OS가 다른 CI에서는 marker 활성 수가 달라질 수 있으므로 정적 32개 탐지를 gate로 사용합니다.

## 6. Python·Maven·Gradle 통합

혼합 fixture 회귀 39개를 새 Java 소스 컴파일 결과로 모두 통과했습니다.
Python runtime·optional·PEP735·marker 선언과 Maven scope·optional·dependencyManagement,
Gradle configuration, PURL별 병합, 선언 메타데이터, depth 및 관계를 검증합니다.
정적 통합 20개, 로컬 Maven 전이 포함 22개 노드 기대값을 재검증했습니다.
정적 optional·개발 선언은 실제 의존성 그래프와 분리됩니다.
Maven과 Gradle 패키지의 ecosystem은 모두 maven이며 출처로 구분합니다.
잘못된 TOML/POM의 전체 실패 및 일부 복구 가능한 오류의 결과 유지도 기존 테스트로 확인했습니다.

## 7. CycloneDX 공식 검증

STEP 4 원본 mixed.cdx.json과 새로 생성한 합성 취약점 SBOM 모두 통과했습니다.
검증 항목은 공식 스키마 적합성과 별도 참조 무결성 검사입니다.
중복 bom-ref, dependency와 affects의 존재하지 않는 참조, 중복 취약점 ID를 검사합니다.
부정 fixture로 잘못된 구조 및 참조를 거부하는 테스트도 실행했습니다.

공식 CycloneDX 1.6 Draft-07 스키마의 보존 사본과 SHA256 manifest를 사용했습니다.
출처는 https://cyclonedx.org/schema/bom-1.6.schema.json 및 함께 참조되는
https://cyclonedx.org/schema/spdx.schema.json 과 https://cyclonedx.org/schema/jsf-0.82.schema.json 입니다.
원본 확보일과 전체 해시는 security-fixtures/step5/schema/manifest.json에 있습니다.
이번 실행에서 스키마를 재다운로드하지 않았고 원격 $ref 해석도 하지 않았습니다.
검증기는 jsonschema 4.26.0 / referencing 0.37.0, format checker 적용입니다.

실측: local-run-2/schema-step4-original.json, schema-enriched.json,
enriched-synthetic.cdx.json. 합성 SBOM에는 SYNTHETIC TEST DATA를 표시했습니다.

## 8. OSV/NVD 고정 fixture 검증

security-fixtures/step5/synthetic-osv-nvd.json을 기존 transport 교체 방식으로 재사용했습니다.
실제 API 검증이 아니며 새로운 실제 취약점 발견으로 보고하지 않습니다.
취약·패치·introduced/fixed/last_affected 경계, alias 중복, PURL 및 ecosystem 구분,
확정/추정/미확정 버전, 잘못된 응답과 조회 실패, NVD 메타데이터 보강을 검증했습니다.

합성 혼합 그래프 패키지 22개: 취약점 없음 응답 12, 레코드 있음 8, OSV 조회 실패 2.
로컬 버전 판정은 affected 5, not affected 2, not applicable 1입니다.
고유 합성 취약점 4개가 affected package PURL 5개와 연결됩니다.
NVD는 메타데이터 보강으로 사용하며 OSV 발견과 구분합니다.
실제 OSV/NVD 호출은 0회입니다. 조회 실패나 버전 미확정을 안전 판정으로 처리하지 않습니다.

## 9. 팀 합의 정책 준수

기본은 canonical python-security-integration/risk_model.py의 team-priority-v2입니다.
CVSS 가중치 1.0, depth 0.0, reference 0이며 제품 위험도 계산식을 변경하지 않았습니다.
대시보드 priority_score는 선택 CVSS base * 10인 0~100 스케일입니다.
예: CVSS 7.5 → 75, 8.1 → 81. CVSS 원점수와 프로젝트 우선순위 스케일을 구분합니다.

| 합의 | 결과 |
|---|---|
| CVSS 100% 기본 | 통과, dashboard 점수와 정책 gate 적용 |
| 깊이 20% 실험 | 별도 JSON, team_approved=false |
| CVSS 누락 | missing_numeric_cvss 2개, pending 및 null 유지 |
| 실제 조건 미확인 | 리뷰 항목 8개 모두 unreviewed 유지 |
| 보류/미검토 독립 | 검증 통과, SBOM 선언·상태 보존 테스트 포함 |
| 과거 7쌍/3쌍 | 원본 미확보, 미검증 |

기본 결과는 priority-default.json / dashboard-default.json,
실험은 priority-depth20-experiment.json에 따로 기록했습니다.
이번 합성 fixture 결과를 과거 순위 역전 결과로 간주하지 않습니다.
src/main/java/com/bomerang/risk_model.py의 레거시 실험용 기본값은 보존했고
별도 95개 회귀에서 검증합니다. 제품 기본 import 경로와 혼동하지 않습니다.

## 10. GitHub Actions 재현 범위와 남은 일

구현한 workflow는 모든 429개와 공식 스키마·참조 검사·Flask·정책 gate를 대상으로 합니다.
원격 실행 및 Ubuntu/Temurin 17 런타임 결과는 미측정입니다.
Windows의 Java 25에서 --release 17로 컴파일한 결과만 성공으로 확인했습니다.
actionlint 및 별도 YAML 파서 검증은 실행하지 않았습니다.

현재 미추적 STEP 2~5 테스트/fixture도 담당자가 검토하여 GitHub checkout에 포함해야 합니다.
필수 파일 상세는 ci/README.md에 있습니다. 기존 class 파일에 의존하지 않습니다.
담당자가 변경을 저장소에 반영한 후 Actions의 workflow_dispatch를 실행하고,
bomerang-offline-verification artifact의 summary.json, JUnit, artifact-checks.json을 확인하세요.
이 작업에서는 commit/push 및 원격 workflow_dispatch를 수행하지 않았습니다.

설치 및 Actions 자체 다운로드는 네트워크가 필요하며 검증 단계의 오프라인 성격과 구분합니다.
Python 3.14의 패치 버전, ubuntu-latest와 Actions major tag는 향후 변경될 수 있습니다.
더 엄격한 공급망 재현성이 필요하면 runner/patch/Action SHA와 전이 의존성 lock을 별도 검토하세요.

남은 기능 한계: 실제 설치 환경 및 악용 조건 미검토, 라이브 OSV/NVD API 미검증,
일부 Gradle 확장/Java 원문 선언 목록 미지원, 비표준 last_inclusive 자동 해석 미지원.
원본 7쌍과 3쌍 집계 자료를 확보하기 전에는 과거 순위 역전 재현을 주장할 수 없습니다.
STEP 5 복구의 최종 근거는 test-reports/step5/recovery/completion.json이며
그 이전 보존 예외 보고서를 이번 작업에서 덮어쓰지 않았습니다.


## STEP 7 공개본 안내

위 내용은 STEP 6 시점의 실측 보고서입니다. 원본 로컬 결과·복구 자료는 보존하지만
저장소에는 업로드하지 않습니다. 현재 CI는 ci/fixtures의 경로 정리 사본을 사용하며,
현재 재현 절차와 필수 파일 목록은 ci/README.md가 기준입니다.
이 문서의 로컬 성공 기록은 GitHub Actions 원격 성공을 의미하지 않습니다.
