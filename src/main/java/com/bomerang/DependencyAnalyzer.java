package com.bomerang;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class DependencyAnalyzer {

    // 탐색을 완전히 마친 의존성
    private final Set<String> resolved = new HashSet<>();

    public void analyze(List<DependencyNode> nodes) {
        System.out.println("\n===== DFS 재귀 의존성 탐색 시작 =====");

        // analyze()를 다시 호출할 때 이전 결과가 남지 않도록 초기화
        resolved.clear();

        for (DependencyNode node : nodes) {
            Set<String> currentPath = new HashSet<>();
            traverse(node, 0, currentPath);
        }
    }

    private void traverse(
            DependencyNode node,
            int depth,
            Set<String> currentPath
    ) {
        String nodeId = node.getUniqueId();
        String indent = "    ".repeat(depth);

        /*
         * 현재 탐색 중인 경로에 같은 노드가 존재하면
         * 실제 순환 참조이다.
         *
         * 예: A -> B -> C -> A
         */
        if (currentPath.contains(nodeId)) {
            System.out.println(
 
                    indent + "⚠ 순환 참조 감지: " + nodeId
            );
            return;
        }

        /*
         * 이전 경로에서 이미 탐색을 완료한 노드이다.
         * 순환 참조가 아니라 공유 의존성이다.
         *
         * 예:
         * A -> C
         * B -> C
         */
        if (resolved.contains(nodeId)) {
            System.out.println(
                    indent + "↳ 이미 분석된 의존성 재사용: " + nodeId
            );
            return;
        }

        // 현재 재귀 경로에 노드 추가
        currentPath.add(nodeId);

        System.out.println(
                indent
                + "-> 탐색: "
                + nodeId
                + " (depth="
                + depth
                + ")"
        );

        // 자식 의존성 재귀 탐색
        for (DependencyNode child : node.getChildren()) {
            traverse(child, depth + 1, currentPath);
        }

        /*
         * 현재 노드의 자식 탐색이 끝났으므로
         * 현재 경로에서 제거하고 완료 목록에 추가한다.
         */
        currentPath.remove(nodeId);
        resolved.add(nodeId);
    }
}