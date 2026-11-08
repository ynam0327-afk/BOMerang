# BOMerang 오프라인 CI 재현

Python 3.14, JDK 17 이상과 저장소에 포함된 Maven artifact 3.9.9 JAR가 필요합니다.
GitHub Actions는 Ubuntu + Python 3.14 + Temurin 17을 사용합니다.

```text
python -m pip install -r ci/requirements.txt
python -B ci/run_checks.py --output test-results/verification
```

출력 경로는 존재하지 않는 새 디렉터리여야 합니다. 반복 실행 시 다른 이름을 사용하세요.
설치 단계에는 PyPI 연결이 필요하며, Actions 다운로드도 네트워크를 사용합니다.
검증 단계는 공개 저장소 clone, PyPI 버전 조회, OSV/NVD API 호출을 사용하지 않습니다.
Maven 전이 의존성 테스트는 127.0.0.1의 fixture HTTP 서버만 사용합니다.

## 테스트 프로세스와 실패 기준

`run_checks.py`의 SUITES가 실행 대상의 단일 목록입니다.

| 프로세스 | PYTHONPATH | 예상 통과 |
|---|---|---:|
| main | python-parser + python-security-integration | 308 |
| security-review | src/main/java/com/bomerang | 95 |
| legacy-parser | python-security-integration/python-parser | 26 |
| 합계 | 별도 프로세스, importlib 수집 | 429 |

각 프로세스에 `--import-mode=importlib -p no:cacheprovider -q`를 적용합니다.
PYTEST_ADDOPTS를 제거하고 PYTHONDONTWRITEBYTECODE=1을 적용합니다.
기대 개수 불일치, 실패, 오류, 건너뛰기, 같은 프로세스의 중복 테스트 식별자는 실패입니다.
의도적으로 다른 경로에 있는 레거시 파서 26개는 별도 회귀 대상입니다.
새 테스트가 추가되면 실행 목록과 기대 수를 검토하여 함께 갱신하세요.

## 원본 보존

검증에 필요한 Python/Java 소스, 테스트, 라이브러리와 fixture만 임시 사본으로 복사합니다.
기존 .class, 캐시, 로그는 복사하지 않습니다. Java exporter와 comparator bridge는
임시 사본에서 `javac --release 17`로 새로 컴파일합니다.
기존 테스트가 요구하는 target/classes 상대 경로는 임시 사본 안에서 충족합니다.
호출 저장소의 target/classes는 실행 전후 전체 파일 SHA256으로 비교합니다.
제품 소스 및 기존 테스트를 변경하는 전처리는 하지 않습니다.

## 후속 검증과 산출물

- Flask 고정 원본 SHA256 및 gold를 이용해 `--declarations` 소스 평가를 실행합니다.
- 정적 선언 TP=32, FP=0, FN=0을 회귀 기준으로 검사합니다.
- OS에 따른 marker 활성 수는 별도 결과로 기록합니다. 설치된 패키지 수로 해석하지 않습니다.
- 합성 OSV/NVD transport를 기존 파이프라인에 전달하여 SBOM을 새로 생성합니다.
- STEP 4 원본 SBOM과 새 합성 SBOM 모두 공식 CycloneDX 1.6 스키마 및 참조 무결성을 검사합니다.
- 스키마는 security-fixtures/step5/schema의 공식 원본과 manifest 해시를 사용합니다.
  Draft-07, jsonschema 4.26.0, referencing 0.37.0이며 원격 $ref 해석은 금지됩니다.
- CVSS 100% 기본 점수, 점수 보류(null), 독립적인 미검토 상태, 조회 상태 구분을 검사합니다.
- priority-default.json / dashboard-default.json과 priority-depth20-experiment.json을 분리합니다.
- 과거 순위 역전 7쌍/3쌍은 원본 미확보로 미검증입니다. 이 실행은 과거 실험 재현이 아닙니다.

JUnit 3개, 실행 로그, summary.json, flask.json, 정책별 JSON,
새 SBOM, schema-*.json 및 artifact-checks.json이 출력됩니다.
Actions는 실패한 경우에도 해당 디렉터리를 artifact로 업로드합니다.

## 새 checkout에서 필요한 파일

STEP 2~5의 소스·테스트·fixture를 함께 추적합니다. 실행기는 추적된 ci/fixtures 사본을
기존 테스트가 요구하는 상대 경로에 배치합니다. 개인 절대 경로가 들어 있는 원본 결과와
복구 백업·캐시·로그는 배포하지 않습니다.

- accuracy-tests/repository_cases.json, gold/flask.json, sources/flask/ 및 Flask LICENSE
- ci/fixtures/flask-step2-integrated.json, mixed-resolved.json, mixed.cdx.json
- integration-fixtures/step4/의 선언 파일 및 로컬 POM(.gradle 캐시 제외)
- security-fixtures/step5/의 합성 응답, 공식 스키마, manifest 및 라이선스
- 루트 신규 테스트 4개, evaluate_repository_parsing.py, validate_cyclonedx.py
- 기존 Python 파서 두 경로, 보안 모듈, src/main/java의 Python/Java 소스 및 Maven JAR

manifest에 기록된 Windows 실행 환경은 기존 측정의 메타데이터입니다.
그 경로를 실행하지 않으며 CI는 현재 Python 및 OS 환경을 별도로 기록합니다.
제품 기본 정책은 python-security-integration/risk_model.py를 사용합니다.
STEP 6 보고서의 공개 사본은 docs/validation-step6.md에 있습니다.
원본 결과와 복구 증거는 로컬에 보존합니다.

기존 target/classes나 Python bridge .class를 commit할 필요가 없습니다.
GitHub Actions 실행 성공 여부는 실제 원격 run에서 별도로 확인해야 합니다.
