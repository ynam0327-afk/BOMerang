package com.bomerang;

import java.io.File;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        System.out.println("[-] SBOM 통합 파서 시스템 시작...");

        ParserFactory factory = new ParserFactory();
        File targetFile = new File("sample.xml");

        try {
            DependencyParser parser = factory.getParser(targetFile);
            List<DependencyNode> results = parser.parse(targetFile);
            
            System.out.println("[-] 파싱 성공! 취약점 검사를 시작합니다.");

            // 방금 만든 OSV API 클라이언트 생성
            OsvApiClient osvClient = new OsvApiClient();

            // 파싱된 라이브러리를 하나씩 꺼내어 API로 검사
            for (DependencyNode node : results) {
                osvClient.checkVulnerability(node);
            }

        } catch (Exception e) {
            System.err.println("[X] 시스템 에러 발생: " + e.getMessage());
        }
    }
}