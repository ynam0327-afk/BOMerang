package com.bomerang;

import java.io.File;
import java.util.List;

public class Main {

    public static void main(String[] args) {
        System.out.println(
                "[-] SBOM 통합 파서 시스템 시작..."
        );

        /*
         * 실행 인자가 있으면 해당 파일을 사용한다.
         * 실행 인자가 없으면 기본값으로 pom.xml을 사용한다.
         */
        String targetPath;

        if (args.length > 0) {
            targetPath = args[0];
        } else {
            targetPath = "pom.xml";
        }

        File targetFile = new File(targetPath);

        System.out.println(
                "[-] 분석 대상: "
                + targetFile.getPath()
        );

        ParserFactory factory =
                new ParserFactory();

        try {
            DependencyParser parser =
                    factory.getParser(targetFile);

            List<DependencyNode> results;

                if (targetFile.getName().equalsIgnoreCase("pom.xml")) {
                MavenDependencyResolver rootResolver =
                        new MavenDependencyResolver(3);

                results =
                        rootResolver.parseRootPom(targetFile);
                } else {
                results =
                        parser.parse(targetFile);
                }

            System.out.println(
                    "\n===== 의존성 파싱 결과 ====="
            );

            for (DependencyNode node : results) {
                System.out.println(
                        "ID: " + node.getUniqueId()
                        + ", scope: " + node.getScope()
                        + ", optional: " + node.isOptional()
                        + ", depth: " + node.getDepth()
                );
            }

            System.out.println(
                    "\n총 의존성 수: "
                    + results.size()
            );
           /*
                * Maven 프로젝트일 때 실제 하위 의존성 트리를 구성한다.
                */
                if (targetFile.getName().equalsIgnoreCase("pom.xml")) {
                System.out.println(
                        "\n===== 재귀 하위 의존성 분석 시작 ====="
                );

                // 루트 의존성 기준 최대 3단계까지 탐색
                MavenDependencyResolver resolver =
                        new MavenDependencyResolver(3);

                resolver.resolve(results);

                System.out.println(
                        "\n===== 최종 의존성 트리 ====="
                );

                DependencyAnalyzer analyzer =
                        new DependencyAnalyzer();

                analyzer.analyze(results);
                }

        } catch (Exception e) {
            System.err.println(
                    "[X] 의존성 파싱 중 오류 발생: "
                    + e.getMessage()
            );

            e.printStackTrace();
        }
    }
}