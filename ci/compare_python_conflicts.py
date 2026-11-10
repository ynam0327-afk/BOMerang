"""Compare graph identity/edges and vulnerability matches using one OSV snapshot."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "python-parser"), str(ROOT / "python-security-integration")]
from integrated_security import pipeline
from week7_scan import Client
from dashboard_export import export
from cyclonedx_converter import convert_to_cyclonedx
from security_sbom_adapter import to_cyclonedx_risk
from validate_cyclonedx import validate_document


def write(path, data):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


class CapturingSecurity:
    def __init__(self, snapshot=None):
        self.frozen = snapshot is not None
        self.snapshot = snapshot or {}
        self.client = Client()

    def osv(self, ecosystem, name, version):
        key = json.dumps([ecosystem, name, version])
        if key not in self.snapshot:
            if self.frozen:
                raise AssertionError("Missing frozen OSV response: " + key)
            try:
                self.snapshot[key] = {"records": self.client.osv(ecosystem, name, version)}
            except Exception as exc:
                self.snapshot[key] = {"error": type(exc).__name__ + ": " + str(exc)}
        result = self.snapshot[key]
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["records"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--snapshot", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    client = CapturingSecurity(json.loads(args.snapshot.read_text(encoding="utf-8")) if args.snapshot else None)
    compared = {}
    for label, directory in [("before", args.before), ("after", args.after)]:
        graph = json.loads((directory / "graph.json").read_text(encoding="utf-8"))
        scan, normalized, matched, priority = pipeline(graph["dependencies"], client, nvd=False)
        dashboard = export(priority)
        bom = convert_to_cyclonedx(graph, risk_result=to_cyclonedx_risk(priority))
        for name, document in [("scan", scan), ("normalized", normalized), ("matched", matched), ("priority", priority),
                               ("dashboard", dashboard), ("bom.cdx", bom), ("schema", validate_document(bom))]:
            write(args.output / (label + "-" + name + ".json"), document)
        compared[label] = {
            "purls": sorted(row["purl"] for row in graph["dependencies"]),
            "edges": {row["purl"]: sorted(row["dependencies"]) for row in graph["dependencies"]},
            "lookup_states": dict(Counter(row["lookup_status"] for row in scan["results"])),
            "findings": sorted((p["purl"], f["id"], f["version_match"], f["priority_score"])
                               for p in dashboard["packages"] for f in p["findings"]),
            "dependency_conflicts": {row["purl"]: row.get("dependency_conflicts", []) for row in graph["dependencies"]},
        }
    before, after = compared["before"], compared["after"]
    result = {"same_purls": before["purls"] == after["purls"], "same_edges": before["edges"] == after["edges"],
              "same_vulnerability_findings": before["findings"] == after["findings"],
              "nvd_enrichment": False, "osv_snapshot_queries": len(client.snapshot),
              "osv_snapshot_errors": sum("error" in row for row in client.snapshot.values()),
              "before": before, "after": after}
    write(args.output / "osv-snapshot.json", client.snapshot)
    write(args.output / "comparison.json", result)
    print(json.dumps({key: value for key, value in result.items() if key not in ["before", "after"]}), flush=True)


if __name__ == "__main__":
    main()
