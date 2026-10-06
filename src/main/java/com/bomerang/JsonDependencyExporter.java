package com.bomerang;

import java.io.File;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Emits one JSON document for a pom.xml or build.gradle file. */
public class JsonDependencyExporter {
    public static void main(String[] args) throws Exception {
        boolean remote = false;
        boolean includeTest = false;
        String target = null;
        for (String arg : args) {
            if ("--resolve-maven".equals(arg)) remote = true;
            else if ("--include-test".equals(arg)) includeTest = true;
            else if (arg.startsWith("--") || target != null) {
                usage();
                return;
            } else target = arg;
        }
        if (target == null || (includeTest && !remote)) {
            usage();
            return;
        }
        File file = new File(target);
        if (!file.isFile()) throw new IllegalArgumentException("File not found: " + file);
        if (includeTest && !file.getName().equalsIgnoreCase("pom.xml")) {
            usage();
            return;
        }
        List<DependencyNode> roots;
        if (remote && file.getName().equalsIgnoreCase("pom.xml")) {
            // Resolver writes progress to stdout; keep stdout strictly machine-readable JSON.
            java.io.PrintStream original = System.out;
            try {
                System.setOut(System.err);
                MavenDependencyResolver resolver = new MavenDependencyResolver(3, includeTest);
                roots = resolver.parseRootPom(file);
                resolver.resolve(roots);
            } finally {
                System.setOut(original);
            }
        } else {
            roots = new ParserFactory().getParser(file).parse(file);
        }
        System.out.println(export(roots, file.getName()));
    }

    private static void usage() {
        System.err.println("Usage: JsonDependencyExporter <pom.xml|build.gradle|build.gradle.kts> [--resolve-maven] [--include-test]");
        System.err.println("--include-test requires --resolve-maven and pom.xml");
        System.exit(2);
    }

    /** Merge output by purl while still traversing every distinct node object. */
    static String export(List<DependencyNode> roots, String source) {
        Map<String, Entry> packages = new LinkedHashMap<>();
        Set<DependencyNode> seen = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<Visit> queue = new ArrayDeque<>();
        for (DependencyNode root : roots) queue.addLast(new Visit(root, 1));
        while (!queue.isEmpty()) {
            Visit visit = queue.removeFirst();
            DependencyNode node = visit.node;
            // Breadth-first traversal reaches shared objects at their shortest depth.
            // Identity tracking stops cycles without dropping other objects with the same purl.
            if (!seen.add(node)) continue;
            Entry entry = packages.computeIfAbsent(purl(node), key -> new Entry(node));
            entry.depth = Math.min(entry.depth, visit.depth);
            entry.scopes.add(node.getScope() == null ? "compile" : node.getScope());
            entry.optionalValues.add(node.isOptional());
            for (DependencyNode child : node.getChildren()) {
                entry.dependencies.add(purl(child));
                queue.addLast(new Visit(child, visit.depth + 1));
            }
        }
        List<String> entries = new ArrayList<>();
        for (Entry entry : packages.values()) entries.add(entry.json(source));
        return "[" + String.join(",", entries) + "]";
    }

    private static String purl(DependencyNode node) {
        return "pkg:maven/" + node.getGroupId() + "/" + node.getArtifactId()
                + "@" + node.getVersion();
    }

    private static final class Visit {
        final DependencyNode node;
        final int depth;
        Visit(DependencyNode node, int depth) { this.node = node; this.depth = depth; }
    }

    private static final class Entry {
        final DependencyNode node;
        int depth = Integer.MAX_VALUE;
        final Set<String> scopes = new TreeSet<>();
        final Set<Boolean> optionalValues = new TreeSet<>();
        final Set<String> dependencies = new LinkedHashSet<>();
        Entry(DependencyNode node) { this.node = node; }

        String scope() {
            // Preserve the scalar field for existing consumers; scopes is authoritative.
            for (String scope : List.of("compile", "runtime", "provided", "system", "test")) {
                if (scopes.contains(scope)) return scope;
            }
            return scopes.iterator().next();
        }

        String json(String source) {
            StringBuilder json = new StringBuilder("{");
            json.append("\"ecosystem\":\"maven\",");
            json.append("\"group\":").append(quote(node.getGroupId())).append(',');
            json.append("\"name\":").append(quote(node.getArtifactId())).append(',');
            json.append("\"declared_version\":").append(quote(node.getVersion())).append(',');
            json.append("\"resolved_version\":").append(quote(node.getVersion())).append(',');
            json.append("\"purl\":").append(quote(purl(node))).append(',');
            json.append("\"depth\":").append(depth).append(',');
            json.append("\"scope\":").append(quote(scope())).append(',');
            List<String> scopeItems = new ArrayList<>();
            for (String scope : scopes) scopeItems.add(quote(scope));
            json.append("\"scopes\":[").append(String.join(",", scopeItems)).append("],");
            // Required on any observed path means the merged package is not optional.
            json.append("\"optional\":").append(!optionalValues.contains(false)).append(',');
            List<String> optionalItems = new ArrayList<>();
            for (Boolean value : optionalValues) optionalItems.add(value.toString());
            json.append("\"optional_values\":[").append(String.join(",", optionalItems)).append("],");
            json.append("\"source_file\":").append(quote(source)).append(',');
            json.append("\"dependencies\":[");
            List<String> children = new ArrayList<>();
            for (String child : dependencies) children.add(quote(child));
            json.append(String.join(",", children)).append("]}");
            return json.toString();
        }
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
