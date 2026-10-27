package com.bomerang;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class MavenParserTest {

    @TempDir
    Path tempDir;

    /*
     * 테스트 3:
     * MavenParser가 pom.xml만 지원하는지 확인한다.
     */
    @Test
    void shouldSupportPomXmlOnly() {
        MavenParser parser = new MavenParser();

        assertTrue(parser.supports("pom.xml"));
        assertTrue(parser.supports("POM.XML"));
        assertFalse(parser.supports("build.gradle"));
    }

    /*
     * 테스트 4:
     * scope가 생략된 Maven 의존성의 기본 scope가
     * compile로 설정되는지 확인한다.
     */
    @Test
    void shouldUseCompileAsDefaultScope() throws Exception {
        String xml = """
                <project>
                    <dependencies>
                        <dependency>
                            <groupId>org.example</groupId>
                            <artifactId>sample-library</artifactId>
                            <version>1.0.0</version>
                        </dependency>
                    </dependencies>
                </project>
                """;

        Path pomPath = tempDir.resolve("pom.xml");
        Files.writeString(pomPath, xml);

        MavenParser parser = new MavenParser();

        List<DependencyNode> results =
                parser.parse(pomPath.toFile());

        assertEquals(1, results.size());
        assertEquals("compile", results.get(0).getScope());
    }
        /*
    * 테스트 5:
    * optional 값이 true인 Maven 의존성을
    * 올바르게 인식하는지 확인한다.
    */
    @Test
    void shouldParseOptionalDependency() throws Exception {
        String xml = """
                <project>
                    <dependencies>
                        <dependency>
                            <groupId>org.example</groupId>
                            <artifactId>optional-library</artifactId>
                            <version>1.0.0</version>
                            <optional>true</optional>
                        </dependency>
                    </dependencies>
                </project>
                """;

        Path pomPath = tempDir.resolve("optional-pom.xml");
        Files.writeString(pomPath, xml);

        MavenParser parser = new MavenParser();

        List<DependencyNode> results =
                parser.parse(pomPath.toFile());

        assertEquals(1, results.size());
        assertTrue(results.get(0).isOptional());
    }
    /*
    * 테스트 6:
    * Maven properties에 정의된 버전이
    * 의존성 버전에 정상적으로 적용되는지 확인한다.
    */
    @Test
    void shouldResolveVersionFromProperties() throws Exception {
        String xml = """
                <project>
                    <properties>
                        <library.version>2.3.4</library.version>
                    </properties>

                    <dependencies>
                        <dependency>
                            <groupId>org.example</groupId>
                            <artifactId>property-library</artifactId>
                            <version>${library.version}</version>
                        </dependency>
                    </dependencies>
                </project>
                """;

        Path pomPath = tempDir.resolve("property-pom.xml");
        Files.writeString(pomPath, xml);

        MavenParser parser = new MavenParser();

        List<DependencyNode> results =
                parser.parse(pomPath.toFile());

        assertEquals(1, results.size());
        assertEquals(
                "2.3.4",
                results.get(0).getVersion()
        );
    }
    /*
 * 테스트 7:
    * dependencyManagement에 정의된 버전이
    * 버전이 생략된 실제 의존성에 적용되는지 확인한다.
    */
    @Test
    void shouldUseVersionFromDependencyManagement() throws Exception {
        String xml = """
                <project>
                    <dependencyManagement>
                        <dependencies>
                            <dependency>
                                <groupId>org.example</groupId>
                                <artifactId>managed-library</artifactId>
                                <version>3.1.0</version>
                            </dependency>
                        </dependencies>
                    </dependencyManagement>

                    <dependencies>
                        <dependency>
                            <groupId>org.example</groupId>
                            <artifactId>managed-library</artifactId>
                        </dependency>
                    </dependencies>
                </project>
                """;

        Path pomPath =
                tempDir.resolve("dependency-management-pom.xml");

        Files.writeString(pomPath, xml);

        MavenParser parser = new MavenParser();

        List<DependencyNode> results =
                parser.parse(pomPath.toFile());

        assertEquals(1, results.size());
        assertEquals(
                "org.example:managed-library:3.1.0",
                results.get(0).getUniqueId()
        );
    }
    /*
    * 테스트 8:
    * Maven 의존성에 명시된 test scope가
    * 올바르게 파싱되는지 확인한다.
    */
    @Test
    void shouldParseTestScope() throws Exception {
        String xml = """
                <project>
                    <dependencies>
                        <dependency>
                            <groupId>org.junit.jupiter</groupId>
                            <artifactId>junit-jupiter</artifactId>
                            <version>5.10.2</version>
                            <scope>test</scope>
                        </dependency>
                    </dependencies>
                </project>
                """;

        Path pomPath = tempDir.resolve("test-scope-pom.xml");
        Files.writeString(pomPath, xml);

        MavenParser parser = new MavenParser();

        List<DependencyNode> results =
                parser.parse(pomPath.toFile());

        assertEquals(1, results.size());
        assertEquals("test", results.get(0).getScope());
        assertEquals(
                "org.junit.jupiter:junit-jupiter:5.10.2",
                results.get(0).getUniqueId()
        );
    }
}