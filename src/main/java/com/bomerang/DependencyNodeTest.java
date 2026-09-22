package com.bomerang;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class DependencyNodeTest {

    /*
     * 테스트 1:
     * groupId, artifactId, version을 조합해
     * 고유 ID가 올바르게 만들어지는지 확인한다.
     */
    @Test
    void shouldCreateUniqueId() {
        DependencyNode node =
                new DependencyNode(
                        "org.example",
                        "sample-library",
                        "1.0.0",
                        "compile",
                        false,
                        0
                );

        assertEquals(
                "org.example:sample-library:1.0.0",
                node.getUniqueId()
        );
    }
    /*
    * 테스트 2:
    * addChild()로 추가한 의존성이
    * children 목록에 정상 저장되는지 확인한다.
    */
    @Test
    void shouldAddChildDependency() {
        DependencyNode parent =
                new DependencyNode(
                        "org.example",
                        "parent",
                        "1.0.0",
                        "compile",
                        false,
                        0
                );

        DependencyNode child =
                new DependencyNode(
                        "org.example",
                        "child",
                        "2.0.0",
                        "compile",
                        false,
                        1
                );

        parent.addChild(child);

        assertEquals(
                1,
                parent.getChildren().size()
        );

        assertEquals(
                "org.example:child:2.0.0",
                parent.getChildren()
                        .get(0)
                        .getUniqueId()
        );
    }
}