package com.bomerang;

import java.io.File;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

/** Emits one JSON document for a pom.xml or build.gradle file. */
public class JsonDependencyExporter {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: JsonDependencyExporter <pom.xml|build.gradle|build.gradle.kts>");
            System.exit(2);
        }
        File file = new File(args[0]);
        if (!file.isFile()) throw new IllegalArgumentException("File not found: " + file);
        List<DependencyNode> roots = new ParserFactory().getParser(file).parse(file);
        // Existing Maven resolver prints progress to stdout and fetches remote POMs.
        // Export declared dependencies and any children already supplied by the parser.
        List<String> entries = new ArrayList<>();
        Set<DependencyNode> seen = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        for (DependencyNode root : roots) visit(root, file.getName(), 1, seen, entries);
        System.out.println("[" + String.join(",", entries) + "]");
    }

    private static void visit(DependencyNode node, String source, int depth,
                              Set<DependencyNode> seen, List<String> entries) {
        if (!seen.add(node)) return;
        StringBuilder json = new StringBuilder("{");
        json.append("\"ecosystem\":\"maven\",");
        json.append("\"group\":").append(quote(node.getGroupId())).append(',');
        json.append("\"name\":").append(quote(node.getArtifactId())).append(',');
        json.append("\"declared_version\":").append(quote(node.getVersion())).append(',');
        json.append("\"resolved_version\":").append(quote(node.getVersion())).append(',');
        String purl = "pkg:maven/" + node.getGroupId() + "/" + node.getArtifactId()
                + "@" + node.getVersion();
        json.append("\"purl\":").append(quote(purl)).append(',');
        json.append("\"depth\":").append(depth).append(',');
        json.append("\"scope\":").append(quote(node.getScope())).append(',');
        json.append("\"source_file\":").append(quote(source)).append(',');
        json.append("\"dependencies\":[");
        List<String> children = new ArrayList<>();
        for (DependencyNode child : node.getChildren()) {
            children.add(quote("pkg:maven/" + child.getGroupId() + "/"
                    + child.getArtifactId() + "@" + child.getVersion()));
        }
        json.append(String.join(",", children)).append("]}");
        entries.add(json.toString());
        for (DependencyNode child : node.getChildren()) visit(child, source, depth + 1, seen, entries);
    }

    private static String quote(String value) {
        if (value == null) return "null";
        StringBuilder out = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        return out.append('"').toString();
    }
}
