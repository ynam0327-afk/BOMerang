package com.bomerang;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class OsvApiClient {
    private static final String OSV_QUERY_URL = "https://api.osv.dev/v1/query";
    private final HttpClient httpClient;

    public OsvApiClient() {
        // API 요청 시 10초 이상 응답이 없으면 끊어주는 타임아웃 설정 (서버 멈춤 방지)
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public void checkVulnerability(DependencyNode node) {
        String ecosystem = "Maven"; // 추후 Python 구현 시 "PyPI"로 변경하면 됩니다.
        
        // OSV API가 Maven 생태계에서 요구하는 패키지 이름 형태 (groupId:artifactId)
        String packageName = node.getGroupId() + ":" + node.getName();
        String version = node.getVersion();

        System.out.println("\n[-] OSV API 취약점 검사 요청: " + packageName + " (" + version + ")");

        // OSV API 규격에 맞는 JSON 페이로드 생성
        String jsonPayload = String.format(
            "{\"version\": \"%s\", \"package\": {\"name\": \"%s\", \"ecosystem\": \"%s\"}}",
            version, packageName, ecosystem
        );

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(OSV_QUERY_URL))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .build();

            // 구글 서버로 요청 전송 후 응답 받기
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                // OSV는 취약점이 없으면 빈 JSON({})을 반환합니다.
                if (response.body().trim().equals("{}")) {
                    System.out.println("  -> 안전한 라이브러리입니다. (알려진 취약점 없음)");
                } else {
                    System.out.println("  -> [!] 취약점 발견! 상세 데이터:\n" + response.body());
                }
            } else {
                System.out.println("  -> [X] API 호출 실패. 상태 코드: " + response.statusCode());
            }
        } catch (Exception e) {
            System.err.println("  -> [X] API 통신 중 에러: " + e.getMessage());
        }
    }
}