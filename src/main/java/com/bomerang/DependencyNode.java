package com.bomerang;

import java.util.ArrayList;
import java.util.List;

public class DependencyNode {

    private String groupId;
    private String artifactId;
    private String version;
    private String scope;
    private boolean optional;
    private int depth;

    // 현재 의존성의 하위 의존성 목록
    private List<DependencyNode> children;

    // 기존 코드와 호환되는 기본 생성자
    public DependencyNode(
            String groupId,
            String artifactId,
            String version
    ) {
        this(
                groupId,
                artifactId,
                version,
                "compile",
                false,
                0
        );
    }

    // 모든 정보를 입력받는 생성자
    public DependencyNode(
            String groupId,
            String artifactId,
            String version,
            String scope,
            boolean optional,
            int depth
    ) {
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.version = version;

        // scope가 생략되면 Maven 기본값인 compile 사용
        if (scope == null || scope.isBlank()) {
            this.scope = "compile";
        } else {
            this.scope = scope;
        }

        this.optional = optional;
        this.depth = depth;
        this.children = new ArrayList<>();
    }

    public void addChild(DependencyNode child) {
        this.children.add(child);
    }

    // Maven 좌표를 이용한 노드 고유 ID
    public String getUniqueId() {
        return groupId + ":" + artifactId + ":" + version;
    }

    public String getGroupId() {
        return groupId;
    }

    public String getArtifactId() {
        return artifactId;
    }

    /*
     * 기존 OsvApiClient에서 getName()을 사용하고 있으므로
     * 당장은 호환성을 위해 남겨둔다.
     */
    public String getName() {
        return artifactId;
    }

    public String getVersion() {
        return version;
    }

    public String getScope() {
        return scope;
    }

    public boolean isOptional() {
        return optional;
    }

    public int getDepth() {
        return depth;
    }

    public List<DependencyNode> getChildren() {
        return children;
    }
}