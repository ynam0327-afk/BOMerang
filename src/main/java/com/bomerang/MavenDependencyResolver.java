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
    private final boolean includeTest;
    private final MavenVersionSelector versionSelector = new MavenVersionSelector();

    public MavenDependencyResolver(int maxDepth) {
        this(maxDepth, false);
    }

    public MavenDependencyResolver(int maxDepth, boolean includeTest) {
        this.includeTest = includeTest;
        this.repositoryClient =
                new MavenRepositoryClient();

        this.mavenParser =
                new MavenParser();

        this.maxDepth = maxDepth;
    }

    public List<DependencyNode> parseRootPom(
            File pomFile
    ) throws Exception {
        Model model = loadModel(pomFile, 0, new HashSet<>());
        rootManagedVersions = new HashMap<>(model.versions);
        return mavenParser.parse(pomFile, model.properties, model.versions);
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
                    currentPath,
                    Set.of()
            );
        }
    }

    private void resolveNode(
            DependencyNode node,
            int depth,
            Set<String> currentPath,
            Set<String> inheritedExclusions
    ) {
        if (!versionSelector.resolve(node)) {
            System.err.println("[!] Version unresolved: " + node.getUniqueId() + " - " + node.getResolutionError());
            return;
        }
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
        Set<String> childExclusions = new HashSet<>(inheritedExclusions);
        childExclusions.addAll(node.getExclusions());

        Path downloadedPom = null;

        try {
            Optional<Path> pomResult =
                    repositoryClient.downloadPom(node);

            if (pomResult.isEmpty()) {
                return;
            }

            downloadedPom = pomResult.get();

            Model model = loadModel(downloadedPom.toFile(), 0, new HashSet<>());
            List<DependencyNode> parsedChildren = mavenParser.parse(
                    downloadedPom.toFile(), model.properties, model.versions);

            for (DependencyNode parsedChild
                    : parsedChildren) {

                if (isExcluded(parsedChild, childExclusions)) continue;

                /*
                 * 라이브러리 내부 test, provided, optional 의존성은
                 * 현재 실행 프로젝트로 전파되지 않으므로 제외한다.
                 */
                String managedVersion = rootManagedVersions.getOrDefault(
                        parsedChild.getGroupId() + ":" + parsedChild.getArtifactId(),
                        parsedChild.getVersion());
                DependencyNode effectiveChild = new DependencyNode(
                        parsedChild.getGroupId(), parsedChild.getArtifactId(), managedVersion,
                        parsedChild.getScope(), parsedChild.isOptional(), depth + 1);
                if (!shouldInclude(effectiveChild)) {
                    continue;
                }

                DependencyNode child =
                        new DependencyNode(
                                parsedChild.getGroupId(),
                                parsedChild.getArtifactId(),
                                rootManagedVersions.getOrDefault(
                                        parsedChild.getGroupId() + ":" + parsedChild.getArtifactId(),
                                        parsedChild.getVersion()),
                                "test".equals(node.getScope()) ? "test"
                                        : "runtime".equals(node.getScope()) ? "runtime"
                                        : parsedChild.getScope(),
                                parsedChild.isOptional(),
                                depth + 1
                        );

                child.copyExclusionsFrom(parsedChild);

                node.addChild(child);

                resolveNode(
                        child,
                        depth + 1,
                        currentPath,
                        childExclusions
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

    private Map<String, String> rootManagedVersions = Map.of();

    private boolean isExcluded(DependencyNode node, Set<String> exclusions) {
        String group = node.getGroupId();
        String artifact = node.getArtifactId();
        return exclusions.contains(group + ":" + artifact)
                || exclusions.contains(group + ":*")
                || exclusions.contains("*:" + artifact)
                || exclusions.contains("*:*");
    }
    private final Map<String, Model> modelCache = new HashMap<>();

    private static final class Model {
        final Map<String, String> properties;
        final Map<String, String> versions;
        Model(Map<String, String> properties, Map<String, String> versions) {
            this.properties = properties;
            this.versions = versions;
        }
    }

    /** Resolve remote parent chains and nested BOM imports, with cycle guards. */
    private Model loadModel(File pom, int level, Set<String> path) throws Exception {
        if (level >= 30) throw new IllegalStateException("POM inheritance/BOM depth exceeded");
        Map<String, String> properties = new HashMap<>();
        Map<String, String> versions = new HashMap<>();
        Optional<DependencyNode> parent = mavenParser.parseParent(pom);
        if (parent.isPresent()) {
            Model inherited = loadRemoteModel(parent.get(), level + 1, path);
            properties.putAll(inherited.properties);
            versions.putAll(inherited.versions);
        }
        properties.putAll(mavenParser.parseProperties(pom));
        Map<String, String> imports = new HashMap<>();
        for (DependencyNode bom : mavenParser.parseImportedBoms(pom, properties)) {
            Model imported = loadRemoteModel(bom, level + 1, path);
            // Earlier imports win; local declarations override imports below.
            imported.versions.forEach(imports::putIfAbsent);
        }
        versions.putAll(imports);
        versions.putAll(mavenParser.parseManagedVersions(pom, properties));
        return new Model(properties, versions);
    }

    private Model loadRemoteModel(DependencyNode node, int level, Set<String> path)
            throws Exception {
        if (!versionSelector.resolve(node)) throw new IllegalStateException("Parent/BOM version unresolved: " + node.getResolutionError());
        String id = node.getUniqueId();
        Model cached = modelCache.get(id);
        if (cached != null) return cached;
        if (!path.add(id)) throw new IllegalStateException("POM inheritance/BOM cycle: " + id);
        Path temporary = null;
        try {
            Optional<Path> result = repositoryClient.downloadPom(node);
            if (result.isEmpty()) throw new IllegalStateException("Parent/BOM unavailable: " + id);
            temporary = result.get();
            Model model = loadModel(temporary.toFile(), level, path);
            modelCache.put(id, model);
            return model;
        } finally {
            path.remove(id);
            if (temporary != null) Files.deleteIfExists(temporary);
        }
    }

    private boolean shouldResolve(
            DependencyNode node
    ) {
        if (node.isOptional()) {
            return false;
        }

        String scope = node.getScope();

        if (("test".equals(scope) && !includeTest)
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
        // Dependencies declared test/provided/system in a library never propagate.
        String scope = node.getScope();
        return !"test".equals(scope)
                && !"provided".equals(scope)
                && !"system".equals(scope)
                && !node.isOptional()
                && shouldResolve(node);
    }
}
