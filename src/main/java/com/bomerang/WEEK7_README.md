# 7주차 1차 구현

## 추가 파일
- week7_scan.py: Java JsonDependencyExporter JSON 배열을 입력으로 OSV 조회, 선택적 NVD 상세 정보 보강.
- test_week7.py: 자동 테스트 10개.

기존 Java 파일은 변경하지 않았습니다. Python 3.10 이상, 추가 패키지 설치 없이 실행합니다.

## Windows 실행
기존 Java 프로젝트에서 JsonDependencyExporter를 실행해 packages.json을 만든 뒤:

```powershell
python week7_scan.py packages.json --output vulnerability-results.json
python week7_scan.py packages.json --output vulnerability-results.json --nvd
python -m unittest -v test_week7
```

NVD_API_KEY 환경변수는 선택입니다. 키가 없으면 요청 간격을 길게 둡니다. HTTP 오류는 실패 상태로 기록하며 자동 재시도는 아직 없습니다. 캐시는 한 번 실행하는 동안만 유지됩니다.

## 버전 계약
- confirmed: 정확한 명세 버전은 version_evidence.kind=declared_exact로 기록합니다. 실제 설치 버전 확인을 뜻하지 않습니다.
- estimated: selection_policy=latest_in_range, version_evidence와 resolved_version을 상위 파서가 전달해야 합니다.
- unresolved: 범위만 있거나 선택 근거가 없으면 OSV 조회를 건너뜁니다.

추정 입력 예시(버전 값은 설명용):
```json
[{"ecosystem":"maven","group":"org.example","name":"demo","declared_version":"[1,2)","resolved_version":"1.9","version_status":"estimated","selection_policy":"latest_in_range","version_evidence":{"kind":"registry_latest_in_range","source":"상위 파서"},"resolution_queried_at":"2026-10-13T00:00:00Z"}]
```

최신 선택을 이 모듈에서 수행하거나 검증하지 않습니다. 업로드된 프로젝트에는 해당 구현과 Python 통합 파서가 없으므로, 후속 연동 때 원본 범위/선택 버전/조회 시각/근거를 보존해야 합니다. Python 로컬 버전 표기 등 복잡한 버전은 현재 보수적으로 미확정 처리될 수 있습니다.

## 상태
lookup_status: skipped / lookup_failed / no_known_vulnerabilities / vulnerabilities_found.
추정 조회 결과는 provisional=true. 취약점 없음은 해당 조회 버전에서 알려진 취약점이 조회되지 않았다는 뜻입니다.
OSV 페이지를 모두 조회하며 원본 affected/aliases/severity/references를 보존합니다.
NVD는 OSV의 CVE ID/별칭으로 조회하는 보강 단계이며 독립 탐지나 CPE 정밀 매칭이 아닙니다. NVD 실패는 OSV 결과를 제거하지 않습니다.

## 확인 결과와 남은 작업
자동 테스트 10개 통과. 실제 OSV log4j-core 2.14.1 조회 응답 확인. 실제 프로젝트 Java 컴파일은 이 환경에 JDK가 없어 수행하지 못했습니다.
아직 완료하지 않은 항목: 최신 버전 선택 구현 연동, 로컬 버전 범위 경계값 검증, NVD 독립 매칭, CVE 별칭 기반 전체 중복 정규화, 위험도 모델, 실제 저장소 매칭 정밀도 평가.

공식 규격: https://google.github.io/osv.dev/post-v1-query/ 및 https://nvd.nist.gov/developers/vulnerabilities
