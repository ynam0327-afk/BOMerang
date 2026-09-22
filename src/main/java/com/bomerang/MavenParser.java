package com.bomerang;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class MavenParser implements DependencyParser {

    @Override
    public boolean supports(String fileName) {
        return fileName.equalsIgnoreCase("pom.xml");
    }

    /*
     * 부모 속성과 부모 dependencyManagement가 없는
     * 일반적인 POM 파싱 방식
     */
    @Override
    public List<DependencyNode> parse(
            File file
    ) throws Exception {
        return parse(
                file,
                Map.of(),
                Map.of()
        );
    }

    /*
     * 부모 속성만 전달받는 파싱 방식
     */
    public List<DependencyNode> parse(
            File file,
            Map<String, String> parentProperties
    ) throws Exception {
        return parse(
                file,
                parentProperties,
                Map.of()
        );
    }

    /*
     * 부모 속성과 부모 dependencyManagement를
     * 모두 전달받는 파싱 방식
     */
    public List<DependencyNode> parse(
            File file,
            Map<String, String> parentProperties,
            Map<String, String> parentManagedVersions
    ) throws Exception {
        List<DependencyNode> dependencies =
                new ArrayList<>();

        Document document =
                parseDocument(file);

        Map<String, String> childProperties =
                readProperties(document);

        Map<String, String> properties =
                mergeProperties(
                        parentProperties,
                        childProperties
                );

        Map<String, String> childManagedVersions =
                readManagedVersions(
                        document,
                        properties
                );

        Map<String, String> managedVersions =
                new HashMap<>(
                        parentManagedVersions
                );

        /*
         * 부모의 관리 버전보다 현재 POM의
         * dependencyManagement 설정이 우선한다.
         */
        managedVersions.putAll(
                childManagedVersions
        );

        NodeList dependencyList =
                document.getElementsByTagName(
                        "dependency"
                );

        for (int i = 0;
                i < dependencyList.getLength();
                i++) {

            Node node =
                    dependencyList.item(i);

            if (node.getNodeType()
                    != Node.ELEMENT_NODE) {
                continue;
            }

            Element element =
                    (Element) node;

            /*
             * project 바로 아래 dependencies에 선언된
             * 실제 프로젝트 의존성만 처리한다.
             *
             * dependencyManagement, plugin, profile 등의
             * dependency는 제외한다.
             */
            if (!isDirectProjectDependency(element)) {
                continue;
            }

            String groupId =
                    resolveProperty(
                            getTagValue(
                                    "groupId",
                                    element
                            ),
                            properties
                    );

            String artifactId =
                    resolveProperty(
                            getTagValue(
                                    "artifactId",
                                    element
                            ),
                            properties
                    );

            String version =
                    resolveProperty(
                            getTagValue(
                                    "version",
                                    element
                            ),
                            properties
                    );

            String scope =
                    getTagValue(
                            "scope",
                            element
                    );

            String optionalText =
                    getTagValue(
                            "optional",
                            element
                    );

            /*
             * dependency에 버전이 없다면
             * dependencyManagement에서 찾는다.
             */
            if (version == null
                    || version.isBlank()) {

                String dependencyKey =
                        groupId
                        + ":"
                        + artifactId;

                version =
                        managedVersions.getOrDefault(
                                dependencyKey,
                                "unknown (managed)"
                        );

                version =
                        resolveProperty(
                                version,
                                properties
                        );
            }

            if (scope == null
                    || scope.isBlank()) {
                scope = "compile";
            }

            boolean optional =
                    Boolean.parseBoolean(
                            optionalText
                    );

            DependencyNode dependency =
                    new DependencyNode(
                            groupId,
                            artifactId,
                            version,
                            scope,
                            optional,
                            0
                    );

            dependencies.add(dependency);
        }

        return dependencies;
    }

    /*
     * XML 파일을 DOM Document로 변환한다.
     */
    private Document parseDocument(
            File file
    ) throws Exception {
        DocumentBuilderFactory factory =
                DocumentBuilderFactory
                        .newInstance();

        DocumentBuilder builder =
                factory.newDocumentBuilder();

        Document document =
                builder.parse(file);

        document
                .getDocumentElement()
                .normalize();

        return document;
    }

    /*
     * 특정 요소 안에 있는 태그 값을 읽는다.
     */
    private String getTagValue(
            String tagName,
            Element element
    ) {
        NodeList nodeList =
                element.getElementsByTagName(
                        tagName
                );

        if (nodeList.getLength() == 0) {
            return null;
        }

        Node node =
                nodeList.item(0);

        if (node == null) {
            return null;
        }

        String value =
                node.getTextContent();

        if (value == null) {
            return null;
        }

        return value.trim();
    }

    /*
     * 해당 노드가 특정 태그 내부에 있는지 확인한다.
     */
    private boolean isInsideTag(
            Node node,
            String tagName
    ) {
        Node parent =
                node.getParentNode();

        while (parent != null) {
            if (parent.getNodeType()
                    == Node.ELEMENT_NODE
                    && tagName.equals(
                            parent.getNodeName()
                    )) {
                return true;
            }

            parent =
                    parent.getParentNode();
        }

        return false;
    }

    /*
     * project 바로 아래의 properties만 읽는다.
     *
     * profile, plugin 등의 properties를
     * 잘못 읽는 문제를 방지한다.
     */
    private Map<String, String> readProperties(
            Document document
    ) {
        Map<String, String> properties =
                new HashMap<>();

        Element projectElement =
                document.getDocumentElement();

        Element propertiesElement =
                getDirectChildElement(
                        projectElement,
                        "properties"
                );

        if (propertiesElement == null) {
            return properties;
        }

        NodeList children =
                propertiesElement
                        .getChildNodes();

        for (int i = 0;
                i < children.getLength();
                i++) {

            Node child =
                    children.item(i);

            if (child.getNodeType()
                    != Node.ELEMENT_NODE) {
                continue;
            }

            String propertyName =
                    child.getNodeName();

            String propertyValue =
                    child
                            .getTextContent()
                            .trim();

            properties.put(
                    propertyName,
                    propertyValue
            );
        }

        return properties;
    }

    /*
     * ${property.name} 형태의 값을 실제 값으로 바꾼다.
     *
     * 속성이 다른 속성을 참조하는 경우를 위해
     * 최대 10단계까지 반복해서 해석한다.
     */
    private String resolveProperty(
            String value,
            Map<String, String> properties
    ) {
        if (value == null) {
            return null;
        }

        String resolvedValue =
                value.trim();

        for (int i = 0; i < 10; i++) {
            if (!resolvedValue.startsWith("${")
                    || !resolvedValue.endsWith("}")) {
                break;
            }

            String propertyName =
                    resolvedValue.substring(
                            2,
                            resolvedValue.length() - 1
                    );

            String propertyValue =
                    properties.get(
                            propertyName
                    );

            if (propertyValue == null
                    || propertyValue.equals(
                            resolvedValue
                    )) {
                break;
            }

            resolvedValue =
                    propertyValue.trim();
        }

        return resolvedValue;
    }

    /*
     * dependencyManagement에 선언된
     * groupId:artifactId와 버전을 읽는다.
     */
    private Map<String, String> readManagedVersions(
            Document document,
            Map<String, String> properties
    ) {
        Map<String, String> managedVersions =
                new HashMap<>();

        NodeList dependencyList =
                document.getElementsByTagName(
                        "dependency"
                );

        for (int i = 0;
                i < dependencyList.getLength();
                i++) {

            Node node =
                    dependencyList.item(i);

            if (node.getNodeType()
                    != Node.ELEMENT_NODE) {
                continue;
            }

            Element element =
                    (Element) node;

            if (!isInsideTag(
                    element,
                    "dependencyManagement"
            )) {
                continue;
            }

            String groupId =
                    resolveProperty(
                            getTagValue(
                                    "groupId",
                                    element
                            ),
                            properties
                    );

            String artifactId =
                    resolveProperty(
                            getTagValue(
                                    "artifactId",
                                    element
                            ),
                            properties
                    );

            String version =
                    resolveProperty(
                            getTagValue(
                                    "version",
                                    element
                            ),
                            properties
                    );

            if (groupId == null
                    || artifactId == null
                    || version == null
                    || version.isBlank()) {
                continue;
            }

            String dependencyKey =
                    groupId
                    + ":"
                    + artifactId;

            managedVersions.put(
                    dependencyKey,
                    version
            );
        }

        return managedVersions;
    }

    /*
     * project 바로 아래 dependencies의
     * 직접 의존성인지 확인한다.
     */
    private boolean isDirectProjectDependency(
            Element dependencyElement
    ) {
        Node dependenciesNode =
                dependencyElement
                        .getParentNode();

        if (dependenciesNode == null
                || dependenciesNode.getNodeType()
                != Node.ELEMENT_NODE
                || !"dependencies".equals(
                        dependenciesNode
                                .getNodeName()
                )) {
            return false;
        }

        Node projectNode =
                dependenciesNode
                        .getParentNode();

        return projectNode != null
                && projectNode.getNodeType()
                == Node.ELEMENT_NODE
                && "project".equals(
                        projectNode.getNodeName()
                );
    }

    /*
     * POM의 parent 정보를 읽는다.
     */
    public Optional<DependencyNode> parseParent(
            File file
    ) throws Exception {
        Document document =
                parseDocument(file);

        Element projectElement =
                document.getDocumentElement();

        Element parentElement =
                getDirectChildElement(
                        projectElement,
                        "parent"
                );

        if (parentElement == null) {
            return Optional.empty();
        }

        String groupId =
                getTagValue(
                        "groupId",
                        parentElement
                );

        String artifactId =
                getTagValue(
                        "artifactId",
                        parentElement
                );

        String version =
                getTagValue(
                        "version",
                        parentElement
                );

        if (groupId == null
                || artifactId == null
                || version == null) {
            return Optional.empty();
        }

        DependencyNode parent =
                new DependencyNode(
                        groupId,
                        artifactId,
                        version,
                        "import",
                        false,
                        0
                );

        return Optional.of(parent);
    }

    /*
     * 특정 요소 바로 아래의 자식 요소만 찾는다.
     */
    private Element getDirectChildElement(
            Element parent,
            String tagName
    ) {
        NodeList children =
                parent.getChildNodes();

        for (int i = 0;
                i < children.getLength();
                i++) {

            Node child =
                    children.item(i);

            if (child.getNodeType()
                    == Node.ELEMENT_NODE
                    && tagName.equals(
                            child.getNodeName()
                    )) {
                return (Element) child;
            }
        }

        return null;
    }

    /*
     * 외부에서 POM의 properties를 읽을 때 사용한다.
     */
    public Map<String, String> parseProperties(
            File file
    ) throws Exception {
        Document document =
                parseDocument(file);

        return readProperties(document);
    }

    /*
     * 외부에서 POM의 dependencyManagement를
     * 읽을 때 사용한다.
     */
    public Map<String, String> parseManagedVersions(
            File file,
            Map<String, String> properties
    ) throws Exception {
        Document document =
                parseDocument(file);

        return readManagedVersions(
                document,
                properties
        );
    }

    /*
     * 부모와 자식의 properties를 합친다.
     * 동일한 속성은 자식 값이 우선한다.
     */
    public Map<String, String> mergeProperties(
            Map<String, String> parentProperties,
            Map<String, String> childProperties
    ) {
        Map<String, String> mergedProperties =
                new HashMap<>(
                        parentProperties
                );

        mergedProperties.putAll(
                childProperties
        );

        return mergedProperties;
    }

    /*
     * dependencyManagement 안의
     * type=pom, scope=import인 BOM을 찾는다.
     */
    public List<DependencyNode> parseImportedBoms(
            File file
    ) throws Exception {
        List<DependencyNode> importedBoms =
                new ArrayList<>();

        Document document =
                parseDocument(file);

        Map<String, String> properties =
                readProperties(document);

        NodeList dependencyList =
                document.getElementsByTagName(
                        "dependency"
                );

        for (int i = 0;
                i < dependencyList.getLength();
                i++) {

            Node node =
                    dependencyList.item(i);

            if (node.getNodeType()
                    != Node.ELEMENT_NODE) {
                continue;
            }

            Element element =
                    (Element) node;

            if (!isInsideTag(
                    element,
                    "dependencyManagement"
            )) {
                continue;
            }

            String type =
                    getTagValue(
                            "type",
                            element
                    );

            String scope =
                    getTagValue(
                            "scope",
                            element
                    );

            if (!"pom".equals(type)
                    || !"import".equals(scope)) {
                continue;
            }

            String groupId =
                    resolveProperty(
                            getTagValue(
                                    "groupId",
                                    element
                            ),
                            properties
                    );

            String artifactId =
                    resolveProperty(
                            getTagValue(
                                    "artifactId",
                                    element
                            ),
                            properties
                    );

            String version =
                    resolveProperty(
                            getTagValue(
                                    "version",
                                    element
                            ),
                            properties
                    );

            if (groupId == null
                    || artifactId == null
                    || version == null
                    || version.isBlank()
                    || version.contains("${")) {
                continue;
            }

            importedBoms.add(
                    new DependencyNode(
                            groupId,
                            artifactId,
                            version,
                            "import",
                            false,
                            0
                    )
            );
        }

        return importedBoms;
    }
}