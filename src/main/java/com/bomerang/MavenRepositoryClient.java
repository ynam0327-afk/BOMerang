package com.bomerang;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;

public class MavenRepositoryClient {

    private static final String MAVEN_CENTRAL_URL =
            "https://repo.maven.apache.org/maven2";

    private final String repositoryUrl;

    private final HttpClient httpClient;

    public MavenRepositoryClient() {
        String configured = System.getenv("BOMERANG_MAVEN_REPO_URL");
        this.repositoryUrl = configured == null || configured.isBlank()
                ? MAVEN_CENTRAL_URL : configured.replaceAll("/+$", "");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public Optional<Path> downloadPom(
            DependencyNode dependency
    ) throws IOException, InterruptedException {

        validateDependency(dependency);

        String groupPath = dependency
                .getGroupId()
                .replace(".", "/");

        String artifactId =
                dependency.getArtifactId();

        String version =
                dependency.getVersion();

        /*
         * Maven Central POM 경로:
         *
         * groupId 경로/artifactId/version/
         * artifactId-version.pom
         */
        String pomUrl =
                repositoryUrl
                + "/" + groupPath
                + "/" + artifactId
                + "/" + version
                + "/" + artifactId
                + "-" + version
                + ".pom";

        System.out.println(
                "[-] 하위 의존성 POM 요청: "
                + pomUrl
        );

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(pomUrl))
                .timeout(Duration.ofSeconds(15))
                .GET()
                .build();

        HttpResponse<String> response =
                httpClient.send(
                        request,
                        HttpResponse.BodyHandlers.ofString(
                                StandardCharsets.UTF_8
                        )
                );

        if (response.statusCode() != 200) {
            System.out.println(
                    "[!] POM 다운로드 실패: HTTP "
                    + response.statusCode()
            );

            return Optional.empty();
        }

        Path temporaryPom =
                Files.createTempFile(
                        "bomerang-dependency-",
                        ".pom"
                );

        Files.writeString(
                temporaryPom,
                response.body(),
                StandardCharsets.UTF_8
        );

        return Optional.of(temporaryPom);
    }

    private void validateDependency(
            DependencyNode dependency
    ) {
        if (dependency == null) {
            throw new IllegalArgumentException(
                    "의존성 노드가 null입니다."
            );
        }

        if (dependency.getGroupId() == null
                || dependency.getGroupId().isBlank()) {
            throw new IllegalArgumentException(
                    "groupId가 없습니다."
            );
        }

        if (dependency.getArtifactId() == null
                || dependency.getArtifactId().isBlank()) {
            throw new IllegalArgumentException(
                    "artifactId가 없습니다."
            );
        }

        if (dependency.getVersion() == null
                || dependency.getVersion().isBlank()
                || dependency.getVersion().contains("unknown")) {
            throw new IllegalArgumentException(
                    "유효한 버전이 없습니다: "
                    + dependency.getVersion()
            );
        }
    }
}
