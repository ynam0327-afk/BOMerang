"""Synthetic OSV/NVD fixtures, team policy and official-schema offline checks."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from integrated_security import pipeline
from week7_scan import Client, scan
from osv_version_matcher import evaluate_range, match_record
from risk_model import DEFAULT, score_document
from security_sbom_adapter import to_cyclonedx_risk
from cyclonedx_converter import convert_to_cyclonedx
from dashboard_export import export
from validate_cyclonedx import validate_document

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "security-fixtures/step5/synthetic-osv-nvd.json"
MIXED = ROOT / "test-reports/step4/mixed-resolved.json"


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def load_review():
    spec = importlib.util.spec_from_file_location(
        "step5_review", ROOT / "src/main/java/com/bomerang/review_priorities.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FrozenClient(Client):
    """Uses real OSV pagination/NVD parsing with a synthetic in-memory transport."""
    def __init__(self, data=None):
        super().__init__()
        self.data = deepcopy(data if data is not None else read(DATA))
        self.calls = []

    def request(self, url, payload=None, headers=None):
        if payload is not None:
            coordinate = payload["package"]["ecosystem"] + "|" + payload["package"]["name"]
            self.calls.append(("osv", coordinate, payload["version"]))
            if coordinate in self.data["osv_failures"]:
                raise RuntimeError(self.data["osv_failures"][coordinate])
            return deepcopy(self.data["osv_malformed"].get(
                coordinate, self.data["osv"].get(coordinate, {})))
        cve = parse_qs(urlparse(url).query)["cveId"][0]
        self.calls.append(("nvd", cve))
        if cve in self.data["nvd_failures"]:
            raise RuntimeError(self.data["nvd_failures"][cve])
        return deepcopy(self.data["nvd"].get(cve, {"vulnerabilities": []}))

    def nvd(self, cve):
        # No real transport: avoid production rate-limit sleeps in synthetic tests.
        self.last_nvd = None
        return super().nvd(cve)


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    import week7_scan
    def forbidden(*args, **kwargs):
        raise AssertionError("External API calls are forbidden in STEP 5")
    monkeypatch.setattr(week7_scan, "urlopen", forbidden)


@pytest.fixture(scope="module")
def graph():
    return read(MIXED)


@pytest.fixture(scope="module")
def outputs(graph):
    return pipeline(graph["dependencies"], FrozenClient(), nvd=True)


@pytest.fixture(scope="module")
def bom(graph, outputs):
    return convert_to_cyclonedx(graph, risk_result=to_cyclonedx_risk(outputs[-1]))


def row(document, purl):
    return next(r for r in document["results"] if r["package"]["purl"] == purl)


def finding(document, purl):
    return row(document, purl)["vulnerabilities"][0]


def props(obj):
    return {p["name"]: p["value"] for p in obj.get("properties", [])}


def package(name="shared", version="1.0"):
    return {"name": name, "ecosystem": "pypi", "purl": "pkg:pypi/" + name + ("@" + version if version else ""),
            "declared_version": "==" + version if version else None,
            "resolved_version": version, "version_status": "confirmed" if version else "unresolved",
            "version_evidence": {"kind": "declared_exact"} if version else None,
            "depth": 1, "dependencies": []}


@pytest.mark.parametrize("ecosystem", ["PyPI", "Maven"])
@pytest.mark.parametrize("version,expected", [
    ("0.9", "not_affected"), ("1.0", "affected"), ("1.9", "affected"),
    ("2.0", "not_affected"), ("2.1", "not_affected"),
])
def test_introduced_and_fixed_boundaries(ecosystem, version, expected):
    result = evaluate_range(version, ecosystem, {"type": "ECOSYSTEM",
        "events": [{"introduced": "1.0"}, {"fixed": "2.0"}]})
    assert result["status"] == expected


@pytest.mark.parametrize("ecosystem", ["PyPI", "Maven"])
@pytest.mark.parametrize("version,expected", [("1.0", "affected"), ("1.5", "affected"), ("1.6", "not_affected")])
def test_last_affected_is_inclusive(ecosystem, version, expected):
    assert evaluate_range(version, ecosystem, {"type": "ECOSYSTEM",
        "events": [{"introduced": "1.0"}, {"last_affected": "1.5"}]})["status"] == expected


def test_unsupported_last_inclusive_is_unknown_not_safe():
    assert evaluate_range("1", "PyPI", {"type": "ECOSYSTEM",
        "events": [{"introduced": "0"}, {"last_inclusive": "1"}]})["status"] == "unknown"


def test_aliases_deduplicate_per_purl_and_keep_original_records(outputs):
    normalized = finding(outputs[1], "pkg:pypi/shared@1.0")
    assert len(row(outputs[1], "pkg:pypi/shared@1.0")["vulnerabilities"]) == 1
    assert normalized["canonical_id"] == "CVE-2099-50001"
    assert len(normalized["osv_source_records"]) == 2
    assert set(normalized["all_ids"]) == {"CVE-2099-50001", "OSV-STEP5-SHARED", "GHSA-step-five-test"}


def test_same_name_other_ecosystem_and_group_do_not_leak(outputs):
    matched = outputs[2]
    assert finding(matched, "pkg:pypi/shared@1.0")["local_version_validation"]["status"] == "affected"
    assert finding(matched, "pkg:maven/org.example/shared@1.0")["local_version_validation"]["status"] == "affected"
    assert finding(matched, "pkg:maven/org.other/shared@1.0")["local_version_validation"]["status"] == "not_applicable"


def test_fixed_versions_are_not_affected(outputs):
    for purl in ("pkg:pypi/py-parent@1.0", "pkg:maven/org.example/managed-lib@2.0"):
        assert finding(outputs[2], purl)["local_version_validation"]["status"] == "not_affected"


def test_estimated_version_stays_provisional(outputs):
    risk = finding(outputs[-1], "pkg:pypi/py-runtime@1.5")["project_priority"]
    assert risk["provisional"] is True
    assert row(outputs[0], "pkg:pypi/py-runtime@1.5")["version_status"] == "estimated"


def test_unresolved_skips_lookup_and_never_claims_safe_or_affected():
    client = FrozenClient()
    scanned, normalized, matched, priority = pipeline([package("unresolved-fixture", None)], client, True)
    assert client.calls == []
    result = scanned["results"][0]
    assert result["version_status"] == "unresolved" and result["lookup_status"] == "skipped"
    assert result["reason"] == "missing_or_non_exact_version"
    assert result["vulnerabilities"] == []
    assert priority["priority_ranking"] == []


def test_lookup_failure_and_no_vulnerabilities_are_distinct(outputs):
    scanned = outputs[0]
    assert row(scanned, "pkg:maven/org.example/java-parent@1.0")["lookup_status"] == "lookup_failed"
    assert "synthetic" in row(scanned, "pkg:maven/org.example/java-parent@1.0")["reason"]
    assert row(scanned, "pkg:pypi/py-active@1.0")["lookup_status"] == "no_known_vulnerabilities"


def test_malformed_api_envelope_records_failure(outputs):
    result = row(outputs[0], "pkg:maven/org.example/gradle-provided@1.0")
    assert result["lookup_status"] == "lookup_failed"
    assert "Malformed OSV response" in result["reason"]


@pytest.mark.parametrize("record", [
    {"id": "BROKEN", "aliases": "not-an-array"},
    {"id": "BROKEN", "affected": "not-an-array"},
    {"id": ["not-a-string"]},
])
def test_malformed_osv_record_is_lookup_failure(record):
    data = read(DATA)
    data["osv"]["PyPI|shared"] = {"vulns": [record]}
    result = scan([package()], FrozenClient(data), False)["results"][0]
    assert result["lookup_status"] == "lookup_failed"
    assert result["vulnerabilities"] == []


def test_nvd_is_enrichment_not_discovery(graph):
    client = FrozenClient()
    scanned, normalized, matched, priority = pipeline(graph["dependencies"], client, nvd=False)
    assert not any(c[0] == "nvd" for c in client.calls)
    assert finding(matched, "pkg:pypi/shared@1.0")["local_version_validation"]["status"] == "affected"
    risk = finding(priority, "pkg:pypi/shared@1.0")["project_priority"]
    assert risk["priority_score"] is None and risk["status"] == "pending"


def test_nvd_cvss_metadata_and_source_are_preserved(outputs):
    vuln = finding(outputs[-1], "pkg:pypi/shared@1.0")
    assert vuln["descriptions"][0]["cve_id"] == "CVE-2099-50001"
    assert vuln["project_priority"]["selected_cvss"]["source"] == "nvd@nist.gov"
    assert vuln["project_priority"]["priority_score"] == 75.0
    assert vuln["nvd_enrichment"][0]["status"] == "found"


def test_mismatched_nvd_identity_is_enrichment_failure():
    data = read(DATA)
    data["nvd"]["CVE-2099-50001"]["vulnerabilities"][0]["cve"]["id"] = "CVE-2099-99999"
    result = scan([package()], FrozenClient(data), True)["results"][0]
    assert result["lookup_status"] == "vulnerabilities_found"
    assert result["nvd_enrichment"][0]["status"] == "lookup_failed"


def test_malformed_nvd_metrics_are_enrichment_failure():
    data = read(DATA)
    data["nvd"]["CVE-2099-50001"]["vulnerabilities"][0]["cve"]["metrics"] = {"cvssMetricV31": "invalid"}
    result = scan([package()], FrozenClient(data), True)["results"][0]
    assert result["nvd_enrichment"][0]["status"] == "lookup_failed"


def test_missing_cvss_and_nvd_failure_are_independent_from_osv_discovery(outputs):
    priority = outputs[-1]
    missing = finding(priority, "pkg:pypi/py-child@1.0")
    failed = finding(priority, "pkg:pypi/py-leaf@1.0")
    assert missing["nvd_enrichment"][0]["status"] == "found"
    assert failed["nvd_enrichment"][0]["status"] == "lookup_failed"
    for item in (missing, failed):
        assert item["project_priority"]["status"] == "pending"
        assert item["project_priority"]["reason"] == "missing_numeric_cvss"
        assert item["project_priority"]["priority_score"] is None
        assert item["project_priority"]["runtime_applicability"] == "not_evaluated"


def test_team_default_is_cvss_only_and_depth_independent(outputs):
    assert DEFAULT["cvss_weight"] == 1 and DEFAULT["depth_weight"] == 0 and DEFAULT["team_approved"]
    priority = outputs[-1]
    assert priority["priority_model"]["cvss_weight"] == 1
    assert priority["priority_model"]["depth_weight"] == 0
    for item in priority["priority_ranking"]:
        if item["status"] == "scored":
            assert item["priority_score"] == round(item["selected_cvss"]["score"] * 10, 2)
            assert item["contributions"]["depth_points"] == 0


def test_dashboard_baseline_scores_pending_and_unreviewed_are_independent(outputs):
    result = export(outputs[-1])
    items = {p["purl"]: p for p in result["packages"]}
    scored = items["pkg:pypi/shared@1.0"]["findings"][0]
    pending = items["pkg:pypi/py-child@1.0"]["findings"][0]
    assert scored["priority_score"] == 75.0 and scored["priority_status"] == "scored"
    assert pending["priority_score"] is None and pending["priority_status"] == "pending"
    assert scored["application_status"] == pending["application_status"] == "unreviewed"
    assert items["pkg:maven/org.example/java-parent@1.0"]["lookup_status"] == "lookup_failed"
    assert items["pkg:pypi/py-active@1.0"]["lookup_status"] == "no_known_vulnerabilities"


def test_dashboard_rejects_experiment_as_default_priority(outputs):
    experiment = score_document(outputs[2], {"cvss_weight": .8, "depth_weight": .2})
    assert experiment["priority_model"]["team_approved"] is False
    with pytest.raises(ValueError, match="CVSS"):
        export(experiment)


def test_review_baseline_is_approved_and_experiments_remain_separate(outputs):
    review = load_review()
    report, baseline = review.build(outputs[2])
    assert baseline["priority_model"]["team_approved"] is True
    assert baseline["priority_model"]["depth_weight"] == 0
    assert baseline["priority_model"]["cvss_weight"] == 1
    assert review.score_document.__globals__["DEFAULT"]["cvss_weight"] == 1
    assert set(report["sensitivity"]) == {"depth10_experiment", "depth20_experiment"}
    assert all(item["application_review"]["status"] == "unreviewed" for item in report["review_checklist"])


def test_depth20_experiment_has_own_model_and_preserves_baseline(outputs):
    original = deepcopy(outputs[-1])
    experimental = score_document(outputs[2], {"cvss_weight": .8, "depth_weight": .2})
    assert experimental["priority_model"]["model_id"] == "experimental-priority-v2"
    assert experimental["priority_model"]["team_approved"] is False
    assert experimental["priority_model"]["depth_weight"] == .2
    assert outputs[-1] == original


def test_existing_experiment_configs_preserved_and_comparator_excludes_pending():
    config = read(ROOT / "src/main/java/com/bomerang/risk-depth20.json")
    assert config == {"cvss_weight": .8, "depth_weight": .2}
    review = load_review()
    def rankings(scores):
        return [{"package_purl": str(i), "vulnerability_id": "SYNTHETIC", "priority_score": score}
                for i, score in enumerate(scores)]
    result = review.compare_rankings(rankings([90, 80, None]), rankings([70, 80, None]))
    assert result["strict_pair_reversals"] == 1 and result["comparable_items"] == 2


def test_sbom_affects_exact_purls_and_no_cross_package_leak(bom):
    vuln = next(v for v in bom["vulnerabilities"] if v["id"] == "CVE-2099-50001")
    assert {a["ref"] for a in vuln["affects"]} == {
        "pkg:pypi/shared@1.0", "pkg:maven/org.example/shared@1.0"}
    assert len([v for v in bom["vulnerabilities"] if v["id"] == "CVE-2099-50001"]) == 1


def test_sbom_no_unaffected_or_unknown_findings(bom):
    assert not {"CVE-2099-50005", "CVE-2099-50006"} & {v["id"] for v in bom["vulnerabilities"]}


def test_sbom_policy_and_independent_statuses_survive(graph, outputs, bom):
    metadata = props(bom["metadata"])
    model = json.loads(metadata["bomerang:priority_model"])
    assert model["cvss_weight"] == 1 and model["depth_weight"] == 0
    by_id = {v["id"]: v for v in bom["vulnerabilities"]}
    for identifier, expected_status in [("CVE-2099-50001", "scored"), ("CVE-2099-50003", "pending")]:
        assessments = json.loads(props(by_id[identifier])["bomerang:package_assessments"])
        assert assessments
        assert all(a["application_status"] == "unreviewed" for a in assessments)
        assert all(a["priority_status"] == expected_status for a in assessments)
        assert all(a["weights"]["cvss"] == 1 and a["weights"]["depth"] == 0 for a in assessments)
        if expected_status == "pending":
            assert all(a["priority_score"] is None for a in assessments)
    transformed = to_cyclonedx_risk(outputs[-1])
    scored = next(p for p in transformed["packages"] if p["purl"] == "pkg:pypi/shared@1.0")
    assert scored["findings"][0]["review_required"] is True


def test_sbom_cvss_source_ratings_and_original_graph_fields(graph, bom):
    components = {c["bom-ref"]: c for c in bom["components"]}
    assert set(components) == {p["purl"] for p in graph["dependencies"]}
    for package_row in graph["dependencies"]:
        c = components[package_row["purl"]]
        assert c["name"] == package_row["name"] and c["version"] == package_row["resolved_version"]
        if "optional" in package_row:
            assert props(c)["bomerang:optional"] == str(package_row["optional"]).lower()
    assert not {p["purl"] for p in graph["declaration_packages"] if p["name"] in {"web-only", "doc-only"}} & set(components)
    vuln = next(v for v in bom["vulnerabilities"] if v["id"] == "CVE-2099-50001")
    assert vuln["ratings"][0]["score"] == 7.5
    assert props(vuln)["bomerang:cvss_source"] == "nvd@nist.gov"


def test_duplicate_components_keep_all_dependency_edges():
    graph = [
        {"name": "a", "purl": "pkg:pypi/a", "dependencies": ["pkg:pypi/b"]},
        {"name": "a", "purl": "pkg:pypi/a", "dependencies": ["pkg:pypi/c"]},
        {"name": "b", "purl": "pkg:pypi/b", "dependencies": []},
        {"name": "c", "purl": "pkg:pypi/c", "dependencies": []},
    ]
    original = deepcopy(graph)
    bom = convert_to_cyclonedx(graph)
    assert len(bom["components"]) == 3
    assert next(d for d in bom["dependencies"] if d["ref"] == "pkg:pypi/a")["dependsOn"] == ["pkg:pypi/b", "pkg:pypi/c"]
    assert graph == original


def test_official_schema_original_step4_and_enriched_bom(bom):
    for document in (read(ROOT / "test-reports/step4/mixed.cdx.json"), bom):
        result = validate_document(document)
        assert result["schema_valid"], result["schema_errors"]
        assert result["local_integrity_valid"], result["local_integrity_errors"]


@pytest.mark.parametrize("mutation", ["format", "version", "serial", "rating"])
def test_official_schema_rejects_real_shape_errors(bom, mutation):
    changed = deepcopy(bom)
    if mutation == "format": changed["bomFormat"] = "wrong"
    elif mutation == "version": changed["version"] = 0
    elif mutation == "serial": changed["serialNumber"] = "invalid"
    else: changed["vulnerabilities"][0]["ratings"][0]["method"] = "NOT-CVSS"
    assert validate_document(changed)["schema_valid"] is False


@pytest.mark.parametrize("mutation", ["duplicate_ref", "dangling_dependency", "dangling_affects"])
def test_local_integrity_catches_reference_errors_beyond_schema(bom, mutation):
    changed = deepcopy(bom)
    if mutation == "duplicate_ref":
        changed["components"][1]["bom-ref"] = changed["components"][0]["bom-ref"]
    elif mutation == "dangling_dependency":
        changed["dependencies"][0]["dependsOn"].append("pkg:pypi/not-in-graph")
    else:
        changed["vulnerabilities"][0]["affects"].append({"ref": "pkg:pypi/not-in-graph"})
    assert validate_document(changed)["local_integrity_valid"] is False


def test_malformed_osv_package_coordinates_are_query_failure():
    data = read(DATA)
    data["osv"]["PyPI|shared"]["vulns"][0]["affected"][0]["package"]["name"] = ["invalid"]
    result = scan([package()], FrozenClient(data), False)["results"][0]
    assert result["lookup_status"] == "lookup_failed"


def test_malformed_nvd_description_is_enrichment_failure():
    data = read(DATA)
    data["nvd"]["CVE-2099-50001"]["vulnerabilities"][0]["cve"]["descriptions"] = [None]
    result = scan([package()], FrozenClient(data), True)["results"][0]
    assert result["nvd_enrichment"][0]["status"] == "lookup_failed"


def test_real_zero_cvss_stays_scored_and_distinct_from_missing_score():
    data = read(DATA)
    metric = data["nvd"]["CVE-2099-50001"]["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    metric["cvssData"]["baseScore"] = 0.0
    priority = pipeline([package()], FrozenClient(data), True)[-1]
    view = export(priority)["packages"][0]["findings"][0]
    assert view["priority_status"] == "scored" and view["priority_score"] == 0.0
    assert view["application_status"] == "unreviewed"
    converted = convert_to_cyclonedx([package()], risk_result=to_cyclonedx_risk(priority))
    assert converted["vulnerabilities"][0]["ratings"][0]["score"] == 0.0


def test_dashboard_rejects_score_inconsistent_with_approved_weights(outputs):
    modified = deepcopy(outputs[-1])
    finding(modified, "pkg:pypi/shared@1.0")["project_priority"]["priority_score"] = 60
    with pytest.raises(ValueError, match="CVSS"):
        export(modified)


@pytest.mark.parametrize("ecosystem", ["PyPI", "Maven"])
@pytest.mark.parametrize("version,expected", [("0.9", "not_affected"), ("1.0", "affected"), ("1.1", "not_affected")])
def test_single_version_inclusive_range(ecosystem, version, expected):
    result = evaluate_range(version, ecosystem, {"type": "ECOSYSTEM",
        "events": [{"introduced": "1.0"}, {"last_affected": "1.0"}]})
    assert result["status"] == expected


def test_estimated_single_version_fixture_is_locally_affected(outputs):
    value = finding(outputs[2], "pkg:pypi/py-runtime@1.5")
    assert value["local_version_validation"]["status"] == "affected"
    assert finding(outputs[-1], "pkg:pypi/py-runtime@1.5")["project_priority"]["priority_score"] == 81.0


def test_sbom_preserves_estimated_version_evidence_without_claiming_installation(graph, bom):
    components = {c["bom-ref"]: c for c in bom["components"]}
    source = next(p for p in graph["dependencies"] if p["purl"] == "pkg:pypi/py-runtime@1.5")
    properties = props(components[source["purl"]])
    assert properties["bomerang:version_status"] == "estimated"
    assert properties["bomerang:selection_policy"] == "latest_in_range"
    assert json.loads(properties["bomerang:version_evidence"]) == source["version_evidence"]
    vuln = next(v for v in bom["vulnerabilities"] if v["id"] == "CVE-2099-50002")
    assessment = json.loads(props(vuln)["bomerang:package_assessments"])[0]
    assert assessment["version_status"] == "estimated" and assessment["provisional"] is True


def test_unresolved_component_keeps_unknown_version_state_without_vulnerability_claim():
    value = package("unresolved-fixture", None)
    priority = pipeline([value], FrozenClient(), True)[-1]
    bom = convert_to_cyclonedx([value], risk_result=to_cyclonedx_risk(priority))
    component = bom["components"][0]
    assert "version" not in component
    assert props(component)["bomerang:version_status"] == "unresolved"
    assert bom.get("vulnerabilities", []) == []
