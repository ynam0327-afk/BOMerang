package com.bomerang;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GradleParser implements DependencyParser {

    /*
     * 지원 형식:
     *
     * implementation 'group:artifact:version'
     * implementation("group:artifact:version")
     * testImplementation "group:artifact:version"
     */
    private static final Pattern DEPENDENCY_PATTERN =
        Pattern.compile(
                "^[\\t ]*"
                + "(implementation|api|compileOnly|runtimeOnly"
                + "|testImplementation|testRuntimeOnly)"
                + "[\\t ]*\\(?\\s*"
                + "[\"']([^:\"']+):([^:\"']+):([^\"']+)[\"']"
                + "(?:\\s*\\))?",
                Pattern.MULTILINE
        );

    @Override
    public boolean supports(String fileName) {
        return fileName.equalsIgnoreCase("build.gradle")
                || fileName.equalsIgnoreCase("build.gradle.kts");
    }

    @Override
    public List<DependencyNode> parse(File file) throws Exception {
        List<DependencyNode> dependencies =
                new ArrayList<>();

        // 줄 단위가 아니라 파일 전체를 읽는다.
        String content = Files.readString(
                file.toPath(),
                StandardCharsets.UTF_8
        );

        Matcher matcher =
                DEPENDENCY_PATTERN.matcher(content);

        while (matcher.find()) {
            String configuration = matcher.group(1);
            String groupId = matcher.group(2);
            String artifactId = matcher.group(3);
            String version = matcher.group(4);

            String scope =
                    convertConfigurationToScope(configuration);

            DependencyNode dependency =
                    new DependencyNode(
                            groupId,
                            artifactId,
                            version,
                            scope,
                            false,
                            0
                    );

            dependencies.add(dependency);
        }

        return dependencies;
    }

    private String convertConfigurationToScope(
            String configuration
    ) {
        switch (configuration) {
            case "compileOnly":
                return "provided";

            case "runtimeOnly":
                return "runtime";

            case "testImplementation":
            case "testRuntimeOnly":
                return "test";

            case "implementation":
            case "api":
                return "compile";

            default:
                return "compile";
        }
    }
}