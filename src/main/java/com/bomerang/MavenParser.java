package com.bomerang; 

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class MavenParser implements DependencyParser {

    @Override
    public boolean supports(String fileName) {
        // 파일 이름이 pom.xml일 때만 작동하도록 설정
        return fileName.endsWith(".xml");
    }

    @Override
    public List<DependencyNode> parse(File file) throws Exception {
        List<DependencyNode> dependencies = new ArrayList<>();

        // 1. XML 파싱을 위한 공장(Factory) 설정 (DOM 방식)
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(file);

        // XML 문서 구조를 안정화 (불필요한 공백 제어 등)
        document.getDocumentElement().normalize();

        // 2. 문서 내의 모든 <dependency> 태그 찾기
        NodeList nList = document.getElementsByTagName("dependency");

        for (int i = 0; i < nList.getLength(); i++) {
            Node node = nList.item(i);

            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) node;

                // 헬퍼 메서드를 이용해 값 추출
                String groupId = getTagValue("groupId", element);
                String artifactId = getTagValue("artifactId", element); // 이름
                String version = getTagValue("version", element);

                // Spring Boot처럼 부모(Parent) pom에서 버전을 관리하여 생략된 경우를 대비한 방어 코드
                if (version == null || version.isEmpty()) {
                    version = "unknown (managed)"; 
                }

                // 3. 추출한 정보로 노드를 만들고 리스트에 담기
                DependencyNode depNode = new DependencyNode(groupId, artifactId, version);
                dependencies.add(depNode);
            }
        }

        return dependencies;
    }

    // XML 태그 내부의 텍스트 값을 안전하게 꺼내주는 헬퍼 메서드
    private String getTagValue(String tag, Element element) {
        NodeList nodeList = element.getElementsByTagName(tag);
        if (nodeList != null && nodeList.getLength() > 0) {
            NodeList childNodes = nodeList.item(0).getChildNodes();
            if (childNodes != null && childNodes.getLength() > 0) {
                return childNodes.item(0).getNodeValue().trim();
            }
        }
        return null;
    }
}