package com.bomerang;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class GradleParserTest {

    @TempDir
    Path tempDir;

    /*
     * 테스트 9:
     * build.gradle의 implementation 의존성을
     * 정상적으로 파싱하는지 확인한다.
     */
    @Test
    void shouldParseGradleDependency() throws Exception {
        String gradle = """
                dependencies {
                    implementation 'org.springframework:spring-core:6.1.5'
                }
                """;

        Path gradlePath = tempDir.resolve("build.gradle");
        Files.writeString(gradlePath, gradle);

        GradleParser parser = new GradleParser();

        List<DependencyNode> results =
                parser.parse(gradlePath.toFile());

        assertEquals(1, results.size());
        assertEquals(
                "org.springframework:spring-core:6.1.5",
                results.get(0).getUniqueId()
        );
        assertEquals("compile", results.get(0).getScope());
    }

    /*
     * 테스트 10:
     * Gradle configuration이 각각 올바른 scope로
     * 변환되는지 확인한다.
     */
    @Test
    void shouldConvertGradleConfigurationsToScopes()
            throws Exception {

        String gradle = """
                dependencies {
                    compileOnly 'org.projectlombok:lombok:1.18.32'
                    runtimeOnly 'com.h2database:h2:2.2.224'
                    testImplementation 'org.junit.jupiter:junit-jupiter:5.10.2'
                }
                """;

        Path gradlePath =
                tempDir.resolve("scope-build.gradle");

        Files.writeString(gradlePath, gradle);

        GradleParser parser = new GradleParser();

        List<DependencyNode> results =
                parser.parse(gradlePath.toFile());

        assertEquals(3, results.size());

        assertEquals(
                "provided",
                results.get(0).getScope()
        );

        assertEquals(
                "runtime",
                results.get(1).getScope()
        );

        assertEquals(
                "test",
                results.get(2).getScope()
        );

        assertTrue(
                parser.supports("build.gradle")
        );

        assertTrue(
                parser.supports("build.gradle.kts")
        );
    }
}