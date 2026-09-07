package com.bomerang;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class DependencyAnalyzer {
    // 논문 핵심 포인트: 이미 방문한 노드의 ID를 기억하여 무한 루프 방지
    private Set<String> visited = new HashSet<>();

    public void analyze(List<DependencyNode> nodes) {
        System.out.println("\n🔍 [DFS 탐색 시작] 순환 참조 방지 알고리즘 작동 중...");
        for (DependencyNode node : nodes) {
            traverse(node, 0); // 깊이(depth) 0부터 탐색 시작
        }
    }

    private void traverse(DependencyNode node, int depth) {
        String nodeId = node.getUniqueId();
        
        // 트리 구조를 보기 쉽게 출력하기 위한 들여쓰기
        String indent = "";
        for (int i = 0; i < depth; i++) indent += "    ";

        // 1. 탈출 조건: 이미 방문한 라이브러리면 탐색을 즉시 중단 (순환 참조 방지)
        if (visited.contains(nodeId)) {
            System.out.println(indent + "⚠️ [순환 참조 감지! 탐색 건너뜀] " + nodeId);
            return;
        }

        // 2. 방문 처리 (도장 찍기)
        visited.add(nodeId);
        System.out.println(indent + "-> 정상 탐색 완료: " + nodeId);

        // 3. 재귀 호출: 내 자식 노드들을 향해 한 단계 더 깊이(depth + 1) 파고들기
        for (DependencyNode child : node.getChildren()) {
            traverse(child, depth + 1);
        }
    }
}