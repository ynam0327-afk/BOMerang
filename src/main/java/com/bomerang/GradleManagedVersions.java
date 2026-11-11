package com.bomerang;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.*;

/** Bounded static support; never executes Gradle or project build scripts. */
public final class GradleManagedVersions {
    private static final Pattern BOOT = Pattern.compile("id\\s*(?:\\(\\s*)?[\"']org\\.springframework\\.boot[\"']\\s*\\)?\\s*version\\s*[\"']([0-9][0-9A-Za-z.\\-]*)[\"']");
    private static final Pattern DM = Pattern.compile("id\\s*(?:\\(\\s*)?[\"']io\\.spring\\.dependency-management[\"']");
    private static final Pattern BOM = Pattern.compile("mavenBom\\s*(?:\\(\\s*)?[\"']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([0-9][0-9A-Za-z.\\-]*)[\"']");
    private GradleManagedVersions() {}

    public static void resolve(File file, List<DependencyNode> nodes) throws Exception {
        if (nodes.stream().noneMatch(n -> n.getVersion() == null || n.getVersion().isBlank())) return;
        String code = withoutComments(Files.readString(file.toPath(), StandardCharsets.UTF_8));
        String structuralCode = withoutStrings(code);
        // These constructs can change selected versions. Refuse rather than guess.
        if (Pattern.compile("\\b(ext|extra|properties|constraints|resolutionStrategy|platform|enforcedPlatform|apply|allprojects|subprojects|versionCatalogs)\\b|\\$").matcher(structuralCode).find() || code.contains("$")) {
            pending(nodes, "gradle_management_unsupported_override_or_dynamic_expression"); return;
        }
        List<String> coordinates = new ArrayList<>();
        Matcher boot = BOOT.matcher(code);
        while (boot.find()) coordinates.add("org.springframework.boot:spring-boot-dependencies:" + boot.group(1));
        if (!DM.matcher(code).find()) {
            pending(nodes, "gradle_dependency_management_plugin_not_detected"); return;
        }
        Matcher bom = BOM.matcher(code);
        while (bom.find()) coordinates.add(bom.group(1) + ":" + bom.group(2) + ":" + bom.group(3));
        // Multiple BOM order/override semantics are deliberately not approximated.
        if (coordinates.size() != 1) {
            pending(nodes, "gradle_management_requires_one_literal_bom"); return;
        }
        String coordinate = coordinates.get(0);
        String[] parts = coordinate.split(":");
        Map<String, String> versions;
        try {
            versions = new MavenDependencyResolver(20).managedVersionsFor(
                new DependencyNode(parts[0], parts[1], parts[2]));
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt(); throw ex;
        } catch (Exception ex) {
            System.err.println("Gradle BOM lookup failed: " + coordinate + " (" + ex.getClass().getSimpleName() + ")");
            pending(nodes, "gradle_bom_lookup_failed:" + coordinate); return;
        }
        for (DependencyNode node : nodes) {
            if (node.getVersion() != null && !node.getVersion().isBlank()) continue;
            String version = versions.get(node.getGroupId() + ":" + node.getArtifactId());
            DependencyNode candidate = new DependencyNode(node.getGroupId(), node.getArtifactId(), version);
            if ("confirmed".equals(candidate.getVersionStatus())) node.applyGradleManagedVersion(version, coordinate);
            else node.failVersionResolution("gradle_bom_has_no_exact_version:" + coordinate);
        }
    }

    private static void pending(List<DependencyNode> nodes, String reason) {
        for (DependencyNode n : nodes)
            if (n.getVersion() == null || n.getVersion().isBlank()) n.failVersionResolution(reason);
    }

    private static String withoutStrings(String source) {
        StringBuilder out = new StringBuilder();
        char quote = 0;
        for (int i = 0; i < source.length(); i++) {
            char c = source.charAt(i);
            if (quote != 0) {
                if (c == '\\' && i + 1 < source.length()) {
                    out.append("  "); i++;
                } else {
                    if (c == quote) quote = 0;
                    out.append(c == '\n' ? '\n' : ' ');
                }
            } else if (c == '\'' || c == '"') {
                quote = c; out.append(' ');
            } else out.append(c);
        }
        return out.toString();
    }

    private static String withoutComments(String source) {
        StringBuilder out = new StringBuilder();
        char quote = 0; boolean line = false, block = false;
        for (int i = 0; i < source.length(); i++) {
            char c = source.charAt(i), next = i + 1 < source.length() ? source.charAt(i + 1) : 0;
            if (line) { if (c == '\n') { line = false; out.append(c); } else out.append(' '); continue; }
            if (block) { if (c == '*' && next == '/') { block = false; out.append("  "); i++; } else out.append(c == '\n' ? '\n' : ' '); continue; }
            if (quote != 0) {
                out.append(c);
                if (c == '\\' && i + 1 < source.length()) out.append(source.charAt(++i));
                else if (c == quote) quote = 0;
                continue;
            }
            if (c == '\'' || c == '"') { quote = c; out.append(c); }
            else if (c == '/' && next == '/') { line = true; out.append("  "); i++; }
            else if (c == '/' && next == '*') { block = true; out.append("  "); i++; }
            else out.append(c);
        }
        return out.toString();
    }
}
