package com.bomerang; // 본인이 생성한 패키지명으로 변경하세요.

import java.io.File;
import java.util.List;

public interface DependencyParser {
    
    // 이 파서가 해당 파일을 분석할 수 있는지 확인 (예: pom.xml)
    boolean supports(String fileName);

    // 파일을 분석하여 최상위 의존성 목록을 반환
    List<DependencyNode> parse(File file) throws Exception;
}