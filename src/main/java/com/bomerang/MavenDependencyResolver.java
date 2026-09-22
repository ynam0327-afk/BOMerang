package com.bomerang;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;

public class MavenDependencyResolver {

    private final MavenRepositoryClient repositoryClient;
    private final MavenParser mavenParser;
    private final int maxDepth;

    public MavenDependencyResolver(int maxDepth) {
        this.repositoryClient =
                new MavenRepositoryClient();

        this.mavenParser =
                new MavenParser();

        this.maxDepth = maxDepth;
    }

    public List<DependencyNode> parseRootPom(
            File pomFile
    ) throws Exception {
        Map<String, String> bomManagedVersions =
                new HashMap<>();

        List<DependencyNode> importedBoms =
                mavenParser.parseImportedBoms(pomFile);

        for (DependencyNode importedBom : importedBoms) {
            System.out.println(
                    "[-] 루트 BOM 발견: "
                    + importedBom.getUniqueId()
            );

            Optional<Path> bomPomResult =
                    repositoryClient.downloadPom(importedBom);

            if (bomPomResult.isEmpty()) {
                continue;
            }

            Path bomPomPath = bomPomResult.get();

            try {
                Map<String, String> bomProperties =
                        mavenParser.parseProperties(
                                bomPomPath.toFile()
                        );

                // BOM의 속성이 부모 POM에 선언된 경우도 처리한다.
                Optional<DependencyNode> bomParentResult =
                        mavenParser.parseParent(
                                bomPomPath.toFile()
                        );

                if (bomParentResult.isPresent()) {
                    DependencyNode bomParent =
                            bomParentResult.get();

                    Optional<Path> bomParentPomResult =
                            repositoryClient.downloadPom(
                                    bomParent
                            );

                    if (bomParentPomResult.isPresent()) {
                        Path bomParentPomPath =
                                bomParentPomResult.get();

                        try {
                            Map<String, String> bomParentProperties =
                                    loadPropertiesWithParents(
                                            bomParentPomPath.toFile(),
                                            5
                                    );

                            bomProperties =
                                    mavenParser.mergeProperties(
                                            bomParentProperties,
                                            bomProperties
                                    );

                            System.out.println(
                                    "[-] BOM 부모 속성 수: "
                                    + bomParentProperties.size()
                            );
                        } finally {
                            Files.deleteIfExists(
                                    bomParentPomPath
                            );
                        }
                    }
                }

                Map<String, String> managedVersions =
                        mavenParser.parseManagedVersions(
                                bomPomPath.toFile(),
                                bomProperties
                        );

                bomManagedVersions.putAll(
                        managedVersions
                );

                System.out.println(
                        "[-] 루트 BOM 관리 버전 수: "
                        + managedVersions.size()
                );
            } finally {
                Files.deleteIfExists(bomPomPath);
            }
        }

        return mavenParser.parse(
                pomFile,
                Map.of(),
                bomManagedVersions
        );
    }
    public void resolve(
            List<DependencyNode> rootDependencies
    ) {
        for (DependencyNode root : rootDependencies) {
            Set<String> currentPath =
                    new HashSet<>();

            resolveNode(
                    root,
                    0,
                    currentPath
            );
        }
    }

    private void resolveNode(
            DependencyNode node,
            int depth,
            Set<String> currentPath
    ) {
        String nodeId = node.getUniqueId();

        // 최대 탐색 깊이 제한
        if (depth >= maxDepth) {
            System.out.println(
                    "[!] 최대 깊이 도달: " + nodeId
            );
            return;
        }

        // 현재 재귀 경로에 같은 노드가 있으면 순환 참조
        if (currentPath.contains(nodeId)) {
            System.out.println(
                    "[!] 순환 참조 감지: " + nodeId
            );
            return;
        }

        // 하위 의존성을 가져올 필요가 없는 scope 처리
        if (!shouldResolve(node)) {
            return;
        }

        currentPath.add(nodeId);

        Path downloadedPom = null;

        try {
            Optional<Path> pomResult =
                    repositoryClient.downloadPom(node);

            if (pomResult.isEmpty()) {
                return;
            }

            downloadedPom = pomResult.get();

            // 현재 POM의 dependencyManagement에서 import BOM 탐색
            List<DependencyNode> importedBoms =
                    mavenParser.parseImportedBoms(
                            downloadedPom.toFile()
                    );

            Map<String, String> importedBomManagedVersions =
                    new HashMap<>();

            for (DependencyNode importedBom : importedBoms) {
                System.out.println(
                        "    [BOM 발견] "
                        + node.getUniqueId()
                        + " -> "
                        + importedBom.getUniqueId()
                );

                Optional<Path> bomPomResult =
                        repositoryClient.downloadPom(importedBom);

                if (bomPomResult.isEmpty()) {
                    continue;
                }

                Path bomPomPath = bomPomResult.get();

                try {
                    Map<String, String> bomProperties =
                            mavenParser.parseProperties(
                                    bomPomPath.toFile()
                            );

                    Map<String, String> bomManagedVersions =
                            mavenParser.parseManagedVersions(
                                    bomPomPath.toFile(),
                                    bomProperties
                            );

                    importedBomManagedVersions.putAll(
                            bomManagedVersions
                    );

                    System.out.println(
                            "    [BOM 관리 버전 수] "
                            + bomManagedVersions.size()
                    );
                } finally {
                    Files.deleteIfExists(bomPomPath);
                }
            }

            Map<String, String> parentProperties =
                    Map.of();

            Map<String, String> parentManagedVersions =
                    Map.of();

            Optional<DependencyNode> parentResult =
                    mavenParser.parseParent(downloadedPom.toFile());

            if (parentResult.isPresent()) {
                DependencyNode parent = parentResult.get();

                System.out.println(
                        "    [부모 POM] "
                        + node.getUniqueId()
                        + " -> "
                        + parent.getUniqueId()
                );

                Optional<Path> parentPomResult =
                        repositoryClient.downloadPom(parent);

                if (parentPomResult.isPresent()) {
                    Path parentPomPath = parentPomResult.get();

                    try {
                       parentProperties =
                                mavenParser.parseProperties(
                                        parentPomPath.toFile()
                                );

                        parentManagedVersions =
                                mavenParser.parseManagedVersions(
                                        parentPomPath.toFile(),
                                        parentProperties
                                );

                        System.out.println(
                                "    [부모 속성 수] "
                                + parentProperties.size()
                        );

                        System.out.println(
                                "    [부모 관리 버전 수] "
                                + parentManagedVersions.size()
                        );
                    } finally {
                        Files.deleteIfExists(parentPomPath);
                    }
                }
            }

            Map<String, String> effectiveManagedVersions =
                    new HashMap<>(parentManagedVersions);

            // 현재 POM에서 import한 BOM이 부모 설정보다 우선한다.
            effectiveManagedVersions.putAll(
                    importedBomManagedVersions
            );

            List<DependencyNode> parsedChildren =
                    mavenParser.parse(
                            downloadedPom.toFile(),
                            parentProperties,
                            effectiveManagedVersions
                    );

            for (DependencyNode parsedChild
                    : parsedChildren) {

                /*
                 * test, provided, optional 의존성은
                 * 현재 실행 프로젝트로 전파되지 않으므로 제외한다.
                 */
                if (!shouldInclude(parsedChild)) {
                    continue;
                }

                DependencyNode child =
                        new DependencyNode(
                                parsedChild.getGroupId(),
                                parsedChild.getArtifactId(),
                                parsedChild.getVersion(),
                                parsedChild.getScope(),
                                parsedChild.isOptional(),
                                depth + 1
                        );

                node.addChild(child);

                resolveNode(
                        child,
                        depth + 1,
                        currentPath
                );
            }

        } catch (Exception e) {
            System.err.println(
                    "[X] 하위 의존성 분석 실패: "
                    + nodeId
                    + " - "
                    + e.getMessage()
            );

        } finally {
            currentPath.remove(nodeId);

            if (downloadedPom != null) {
                try {
                    Files.deleteIfExists(downloadedPom);
                } catch (Exception ignored) {
                    // 임시 파일 삭제 실패는 분석 중단 사유가 아니다.
                }
            }
        }
    }

    private Map<String, String> loadPropertiesWithParents(
            File pomFile,
            int remainingDepth
    ) throws Exception {
        Map<String, String> currentProperties =
                mavenParser.parseProperties(pomFile);

        if (remainingDepth <= 0) {
            return currentProperties;
        }

        Optional<DependencyNode> parentResult =
                mavenParser.parseParent(pomFile);

        if (parentResult.isEmpty()) {
            return currentProperties;
        }

        Optional<Path> parentPomResult =
                repositoryClient.downloadPom(
                        parentResult.get()
                );

        if (parentPomResult.isEmpty()) {
            return currentProperties;
        }

        Path parentPomPath =
                parentPomResult.get();

        try {
            Map<String, String> parentProperties =
                    loadPropertiesWithParents(
                            parentPomPath.toFile(),
                            remainingDepth - 1
                    );

            return mavenParser.mergeProperties(
                    parentProperties,
                    currentProperties
            );
        } finally {
            Files.deleteIfExists(parentPomPath);
        }
    }
    private boolean shouldResolve(
            DependencyNode node
    ) {
        if (node.isOptional()) {
            return false;
        }

        String scope = node.getScope();

        if ("test".equals(scope)
                || "provided".equals(scope)
                || "system".equals(scope)) {
            return false;
        }

        String version = node.getVersion();

        return version != null
                && !version.isBlank()
                && !version.contains("unknown")
                && !version.contains("${");
    }

    private boolean shouldInclude(
            DependencyNode node
    ) {
        return shouldResolve(node);
    }
}