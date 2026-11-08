"""Regenerate synthetic SBOM, validate local official schemas and policy gates."""
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "python-parser"), str(ROOT / "python-security-integration")]
from test_security_step5 import FrozenClient
from integrated_security import pipeline
from risk_model import DEFAULT, score_document
from dashboard_export import export
from security_sbom_adapter import to_cyclonedx_risk
from cyclonedx_converter import convert_to_cyclonedx
from validate_cyclonedx import validate_document


def write(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def main():
    output = Path(sys.argv[1])
    graph = json.loads((ROOT / "test-reports/step4/mixed-resolved.json").read_text(encoding="utf-8"))
    client = FrozenClient()
    scanned, normalized, matched, priority = pipeline(graph["dependencies"], client, nvd=True)
    dashboard = export(priority)
    experiment = score_document(matched, {"cvss_weight": 0.8, "depth_weight": 0.2})
    bom = convert_to_cyclonedx(graph, risk_result=to_cyclonedx_risk(priority))
    bom.setdefault("metadata", {}).setdefault("properties", []).append(
        {"name": "bomerang:data_kind", "value": "SYNTHETIC TEST DATA; not real vulnerability findings"})
    for name, data in [("scan", scanned), ("matched", matched), ("priority-default", priority),
                       ("dashboard-default", dashboard), ("priority-depth20-experiment", experiment),
                       ("enriched-synthetic.cdx", bom)]:
        write(output / (name + ".json"), data)
    checks = {}
    original = json.loads((ROOT / "test-reports/step4/mixed.cdx.json").read_text(encoding="utf-8"))
    for name, document in [("step4-original", original), ("enriched", bom)]:
        result = validate_document(document)
        write(output / ("schema-" + name + ".json"), result)
        checks["schema_" + name] = result["schema_valid"] and result["local_integrity_valid"]
    findings = [f for p in dashboard["packages"] for f in p["findings"]]
    pending = [f for f in findings if f["priority_reason"] == "missing_numeric_cvss"]
    checks["default_cvss100"] = DEFAULT["cvss_weight"] == 1 and DEFAULT["depth_weight"] == 0 and DEFAULT["team_approved"]
    checks["dashboard_cvss100"] = all(f["priority_score"] == round(f["selected_cvss"]["score"] * 10, 2)
                                           for f in findings if f["priority_status"] == "scored")
    checks["pending_not_zero"] = len(pending) == 2 and all(f["priority_status"] == "pending" and
                                                          f["priority_score"] is None for f in pending)
    checks["independent_unreviewed"] = len(findings) == 8 and all(f["application_status"] == "unreviewed" for f in findings)
    checks["experiment_separate"] = experiment["priority_model"]["depth_weight"] == 0.2 and not experiment["priority_model"]["team_approved"]
    statuses = Counter(p["lookup_status"] for p in dashboard["packages"])
    checks["lookup_states_distinct"] = statuses == {"no_known_vulnerabilities": 12, "vulnerabilities_found": 8, "lookup_failed": 2}
    flask = json.loads((output / "flask.json").read_text(encoding="utf-8"))
    checks["flask_all_declarations"] = flask["all_declared"]["detection"] == {
        "TP": 32, "FP": 0, "FN": 0, "precision": 1.0, "recall": 1.0, "f1_score": 1.0}
    # Environment-active counts may vary across OS; all-static is the cross-platform gate.
    result = {"checks": checks, "success": all(checks.values()), "fixture_kind": "synthetic",
              "live_osv_nvd_calls": 0, "historical_7_vs_3_pairs": "unverified; original unavailable",
              "lookup_states": dict(statuses), "default_policy": priority["priority_model"],
              "flask_all_declared": flask["all_declared"]["detection"],
              "flask_environment_applicable": flask["environment_applicable"]["detection"],
              "flask_counts": flask["observed_declaration_counts"]}
    write(output / "artifact-checks.json", result)
    print(json.dumps(result))
    raise SystemExit(0 if result["success"] else 1)


if __name__ == "__main__":
    main()
