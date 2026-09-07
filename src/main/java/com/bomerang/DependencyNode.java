package com.bomerang; 

import java.util.ArrayList;
import java.util.List;

public class DependencyNode {
    private String groupId;
    private String name;       // 라이브러리명
    private String version;    // 버전
    
    // 하위 의존성을 담는 리스트 
    private List<DependencyNode> children; 

    public DependencyNode(String groupId, String name, String version) {
        this.groupId = groupId;
        this.name = name;
        this.version = version;
        this.children = new ArrayList<>();
    }

    // 자식 노드 추가 메서드
    public void addChild(DependencyNode child) {
        this.children.add(child);
    }

    // 순환 참조 방지용 고유 ID 생성
    public String getUniqueId() {
        if (groupId != null && !groupId.isEmpty()) {
            return groupId + ":" + name + ":" + version;
        }
        return name + ":" + version;
    }

    // Getters
    public String getGroupId() { return groupId; }
    public String getName() { return name; }
    public String getVersion() { return version; }
    public List<DependencyNode> getChildren() { return children; }
}