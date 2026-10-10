"""Convert BOMerang's integrated dependency JSON into CycloneDX 1.6 JSON.

Input format:
    {"files": [...], "dependencies": [DependencyNode-as-dict, ...]}

This module deliberately does not perform dependency resolution or vulnerability
matching; it only converts the existing parser result.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import re
import uuid
from pathlib import Path
from typing import Any


SPEC_VERSION = "1.6"


def _purl_parts(purl: str) -> dict[str, str]:
    """Extract a best-effort name/version/group from a package URL."""
    match = re.match(r"^pkg:([^/]+)/(.+?)(?:@([^?#]+))?(?:[?#].*)?$", purl)
    if not match:
        return {}
    ecosystem, package_path, version = match.groups()
    package_path = package_path.split("?", 1)[0].split("#", 1)[0]
    parts = package_path.split("/")
    name = parts[-1]
    result = {"name": name, "ecosystem": ecosystem}
    if len(parts) > 1:
        result["group"] = "/".join(parts[:-1])
    if version:
        result["version"] = version
    return result


def _component(node: dict[str, Any]) -> dict[str, Any]:
    purl = node.get("purl")
    parts = _purl_parts(purl) if isinstance(purl, str) else {}
    name = node.get("name") or parts.get("name")
    if not name:
        raise ValueError(f"Dependency node has neither a name nor a usable PURL: {node!r}")

    component: dict[str, Any] = {
        "type": "library",
        "name": str(name),
    }
    # Use the package URL as a stable reference throughout components,
    # dependency edges, and vulnerability affects entries.
    if isinstance(purl, str) and purl:
        component["bom-ref"] = purl
    version = node.get("resolved_version") or parts.get("version")
    if version:
        component["version"] = str(version)
    group = node.get("group") or parts.get("group")
    if group:
        component["group"] = str(group)
    if purl:
        component["purl"] = purl

    # CycloneDX component scope is limited to required, optional, or excluded.
    source_scope = (node.get("scope") or "").lower()
    if source_scope in {"test", "dev", "development", "provided", "optional"}:
        component["scope"] = "optional"
    elif source_scope in {"excluded"}:
        component["scope"] = "excluded"
    elif source_scope:
        component["scope"] = "required"

    properties = []
    for key in ("ecosystem", "declared_version", "source_file", "depth",
                "parse_status", "error_message", "is_circular"):
        value = node.get(key)
        if value is not None and value != "":
            properties.append({"name": f"bomerang:{key}", "value": str(value).lower()
                               if isinstance(value, bool) else str(value)})
    if properties:
        component["properties"] = properties
    return component


def _load_nodes(dependency_result: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """Accept integrated-parser output or the team's flat dependency JSON list."""
    if isinstance(dependency_result, list):
        return dependency_result, []
    if not isinstance(dependency_result, dict):
        raise TypeError("dependency_result must be a dictionary or a list")
    nodes = dependency_result.get("dependencies", [])
    files = dependency_result.get("files", [])
    if not isinstance(nodes, list):
        raise ValueError("'dependencies' must be a list")
    if not isinstance(files, list):
        raise ValueError("'files' must be a list")
    return nodes, [str(path) for path in files]


def _property(name: str, value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    elif isinstance(value, bool):
        value = str(value).lower()
    else:
        value = str(value)
    return {"name": f"bomerang:{name}", "value": value}


def _severity(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if normalized in {"critical", "high", "medium", "low", "info", "none"} else None


def _vulnerability_method(version: Any) -> str | None:
    return {"4.0": "CVSSv4", "3.1": "CVSSv31", "3.0": "CVSSv3", "2.0": "CVSSv2"}.get(str(version))


def _convert_vulnerabilities(risk_result: dict[str, Any] | None,
                             component_refs: set[str]) -> list[dict[str, Any]]:
    """Convert risk JSON findings and preserve BOMerang-specific risk metadata."""
    if risk_result is None:
        return []
    if not isinstance(risk_result, dict):
        raise TypeError("risk_result must be a dictionary")
    packages = risk_result.get("packages", [])
    if not isinstance(packages, list):
        raise ValueError("risk JSON 'packages' must be a list")

    vulnerabilities: dict[str, dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            continue
        purl = package.get("purl")
        if not isinstance(purl, str) or not purl:
            continue
        for finding in package.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            vuln_id = finding.get("vulnerability_id")
            if not isinstance(vuln_id, str) or not vuln_id.strip():
                continue
            vuln = vulnerabilities.setdefault(vuln_id, {
                "id": vuln_id,
                "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vuln_id}"},
                "affects": [],
                "properties": [],
            })
            if purl in component_refs and not any(a.get("ref") == purl for a in vuln["affects"]):
                vuln["affects"].append({"ref": purl})

            score = finding.get("cvss_score")
            vector = finding.get("cvss_vector")
            version = finding.get("cvss_version")
            severity = _severity(finding.get("severity"))
            if score is not None or vector or severity:
                rating: dict[str, Any] = {"source": {"name": "CVSS"}}
                if isinstance(score, (int, float)):
                    rating["score"] = score
                if isinstance(vector, str) and vector:
                    rating["vector"] = vector
                method = _vulnerability_method(version)
                if method:
                    rating["method"] = method
                if severity:
                    rating["severity"] = severity
                # Keep distinct CVSS ratings if multiple records for one CVE differ.
                if rating not in vuln.setdefault("ratings", []):
                    vuln["ratings"].append(rating)

            aliases = finding.get("aliases") or []
            for alias in aliases:
                if isinstance(alias, str) and alias.startswith("GHSA-"):
                    advisory = {"url": f"https://github.com/advisories/{alias}"}
                    if advisory not in vuln.setdefault("advisories", []):
                        vuln["advisories"].append(advisory)

            # CycloneDX has no standard field for BOMerang's custom priority score
            # or review workflow, so preserve them explicitly as properties.
            for key in ("priority_score", "score_breakdown", "review_required",
                        "review_reasons", "exploit_conditions_status", "vendor_assessment",
                        "match_source", "match_status", "status", "cvss_assessment_type",
                        "cvss_source", "scope_unknown", "depth_unknown"):
                prop = _property(key, finding.get(key))
                if prop and prop not in vuln["properties"]:
                    vuln["properties"].append(prop)
            if finding.get("review_required") is True:
                vuln["properties"].append({"name": "bomerang:review_status", "value": "required"}) if not any(
                    p["name"] == "bomerang:review_status" for p in vuln["properties"]
                ) else None

    return sorted(vulnerabilities.values(), key=lambda item: item["id"])


def convert_to_cyclonedx(
    integrated_result: Any,
    *,
    risk_result: dict[str, Any] | None = None,
    bom_name: str = "BOMerang SBOM",
    bom_version: int = 1,
    serial_number: str | None = None,
) -> dict[str, Any]:
    """Convert dependency JSON plus optional risk JSON into a CycloneDX 1.6 BOM.

    Dependency input can be integrated_parser output (dict) or the team's flat
    spring-exclusions.json list. Risk input is the team's spring-risk.json format.
    """
    nodes, source_files = _load_nodes(integrated_result)

    nodes_by_ref: dict[str, dict[str, Any]] = {}
    for node in nodes:
        if not isinstance(node, dict):
            raise ValueError("Each dependency must be a dictionary")
        purl = node.get("purl")
        if not isinstance(purl, str) or not purl:
            raise ValueError(f"Dependency node is missing a usable PURL: {node!r}")
        # Match integrated_parser's PURL-based deduplication behavior.
        nodes_by_ref.setdefault(purl, node)

    components = [_component(node) for node in nodes_by_ref.values()]
    dependencies = []
    for purl, node in nodes_by_ref.items():
        refs = node.get("dependencies") or []
        if not isinstance(refs, list):
            raise ValueError(f"'dependencies' for {purl} must be a list")
        # CycloneDX references must resolve to components in this BOM. Do not
        # emit dangling references; parser output remains available as properties.
        depends_on = sorted({ref for ref in refs if isinstance(ref, str) and ref in nodes_by_ref})
        dependencies.append({"ref": purl, "dependsOn": depends_on})

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial_number or f"urn:uuid:{uuid.uuid4()}",
        "version": bom_version,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).replace(
                microsecond=0
            ).isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{
                "type": "application",
                "name": "BOMerang",
                "version": "0.1.0",
            }]},
            "component": {
                "type": "application",
                "name": bom_name,
                "bom-ref": "urn:bomerang:project",
            },
            "properties": [
                {"name": "bomerang:source_file", "value": path}
                for path in source_files
            ] + ([
                {"name": "bomerang:risk_model_version", "value": str(risk_result["model_version"])}
            ] if risk_result and risk_result.get("model_version") is not None else []) + ([
                {"name": "bomerang:risk_generated_at", "value": str(risk_result["generated_at"])}
            ] if risk_result and risk_result.get("generated_at") is not None else []) + ([
                {"name": "bomerang:risk_coverage_note", "value": str(risk_result["coverage_note"])}
            ] if risk_result and risk_result.get("coverage_note") else []),
        },
        "components": components,
        "dependencies": dependencies,
    }
    vulnerabilities = _convert_vulnerabilities(risk_result, set(nodes_by_ref))
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert BOMerang integrated parser JSON to CycloneDX 1.6 JSON"
    )
    parser.add_argument("input", type=Path, help="integrated_parser JSON input")
    parser.add_argument("-o", "--output", type=Path, default=Path("bom.cdx.json"))
    parser.add_argument("--risk", type=Path, help="optional risk-analysis JSON (spring-risk.json format)")
    parser.add_argument("--name", default="BOMerang SBOM", help="project name in SBOM metadata")
    args = parser.parse_args()

    def load_json(path: Path) -> Any:
        # Teammate's dependency export is UTF-16; risk and integrated JSON are UTF-8.
        raw = path.read_bytes()
        for encoding in ("utf-8-sig", "utf-16"):
            try:
                return json.loads(raw.decode(encoding))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
        raise ValueError(f"Could not decode valid JSON from {path}")

    source = load_json(args.input)
    risk = load_json(args.risk) if args.risk else None
    bom = convert_to_cyclonedx(source, risk_result=risk, bom_name=args.name)
    with args.output.open("w", encoding="utf-8", newline="\n") as file:
        json.dump(bom, file, ensure_ascii=False, indent=2)
        file.write("\n")
    print(f"CycloneDX SBOM written to: {args.output}")


if __name__ == "__main__":
    main()
