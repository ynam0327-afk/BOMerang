package com.bomerang;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class ParserFactory {
    // 시스템이 지원하는 모든 파서들의 목록을 가지고 있습니다.
    private final List<DependencyParser> parsers;

    public ParserFactory() {
        parsers = new ArrayList<>();
        // 1. Maven 파서 등록 (현재 완성됨)
        parsers.add(new MavenParser());
        
        parsers.add(new GradleParser());
    }

    // 파일 이름에 맞는 파서를 찾아 반환하는 핵심 메서드
    public DependencyParser getParser(File file) {
        for (DependencyParser parser : parsers) {
            if (parser.supports(file.getName())) {
                return parser;
            }
        }
        throw new IllegalArgumentException("지원하지 않는 파일 형식입니다: " + file.getName());
    }
}