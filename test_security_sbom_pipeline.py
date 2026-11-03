
"""Regression test: security pipeline to CycloneDX SBOM."""

import runpy
from pathlib import Path

from integrated_security import pipeline
from cyclonedx_converter import convert_to_cyclonedx
from security_sbom_adapter import to_cyclonedx_risk


def test_security_pipeline_to_cyclonedx():
    root = Path(__file__).resolve().parent

    fixtures = runpy.run_path(
        str(
            root
            / "python-security-integration"
            / "test_integrated_security.py"
        )
    )

    helper = fixtures["Tests"]()
    fake_security = fixtures["FakeSecurity"]()

    python_packages = helper.parse("demo>=1,<2")

    java_package = {
        "ecosystem": "maven",
        "group": "g",
        "name": "a",
        "declared_version": "1.0",
        "resolved_version": "1.0",
        "purl": "pkg:maven/g/a@1.0",
        "depth": 1,
        "dependencies": [],
    }

    packages = [java_package, *python_packages]

    scanned, normalized, matched, priority = pipeline(
        packages,
        fake_security,
        nvd=True,
    )

    assert len(scanned["results"]) == 2
    assert priority["priority_summary"] == {"scored": 2}

    risk_data = to_cyclonedx_risk(priority)

    bom = convert_to_cyclonedx(
        {"files": [], "dependencies": packages},
        risk_result=risk_data,
        serial_number="urn:uuid:00000000-0000-4000-8000-000000000001",
    )

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"

    component_refs = {
        component["bom-ref"]
        for component in bom["components"]
    }

    assert component_refs == {
        "pkg:maven/g/a@1.0",
        "pkg:pypi/demo@1.9",
    }

    vulnerabilities = bom["vulnerabilities"]
    assert len(vulnerabilities) == 1

    vuln = vulnerabilities[0]
    assert vuln["id"] == "CVE-2099-12345"

    affected_refs = {
        item["ref"] for item in vuln["affects"]
    }

    assert affected_refs == component_refs

    assert any(
        rating.get("score") == 8.0
        and rating.get("method") == "CVSSv31"
        for rating in vuln.get("ratings", [])
    )

    properties = {
        item["name"]: item["value"]
        for item in vuln["properties"]
    }

    assert properties["bomerang:review_required"] == "true"
    assert properties["bomerang:review_status"] == "required"

    print("PASS: Security pipeline -> CycloneDX SBOM")


def test_pending_cvss_is_marked_for_review():
    priority = {
        "results": [
            {
                "package": {
                    "purl": "pkg:pypi/requests@2.32.5"
                },
                "version_status": "confirmed",
                "vulnerabilities": [
                    {
                        "canonical_id": "CVE-2026-25645",
                        "all_ids": ["CVE-2026-25645"],
                        "local_version_validation": {
                            "status": "affected"
                        },
                        "project_priority": {
                            "status": "pending",
                            "priority_score": None,
                            "selected_cvss": None,
                            "provisional": False,
                            "reason": "missing_numeric_cvss",
                        },
                    }
                ],
            }
        ]
    }

    risk_data = to_cyclonedx_risk(priority)

    bom = convert_to_cyclonedx(
        [{
            "name": "requests",
            "ecosystem": "pypi",
            "resolved_version": "2.32.5",
            "purl": "pkg:pypi/requests@2.32.5",
            "dependencies": [],
        }],
        risk_result=risk_data,
    )

    vulnerabilities = bom["vulnerabilities"]

    assert len(vulnerabilities) == 1

    vulnerability = vulnerabilities[0]

    assert vulnerability["id"] == "CVE-2026-25645"
    assert vulnerability.get("ratings", []) == []

    properties = {
        item["name"]: item["value"]
        for item in vulnerability["properties"]
    }

    assert properties["bomerang:status"] == "pending"
    assert properties["bomerang:review_required"] == "true"
    assert properties["bomerang:review_status"] == "required"
    assert "missing_numeric_cvss" in properties["bomerang:review_reasons"]


def test_vulnerability_does_not_leak_to_other_packages():
    priority = {
        "results": [
            {
                "package": {
                    "purl": "pkg:pypi/requests@2.32.5"
                },
                "version_status": "confirmed",
                "vulnerabilities": [
                    {
                        "canonical_id": "CVE-2099-0001",
                        "local_version_validation": {
                            "status": "affected"
                        },
                        "project_priority": {
                            "status": "pending",
                            "reason": "missing_numeric_cvss",
                            "selected_cvss": None,
                        },
                    }
                ],
            },
            {
                "package": {
                    "purl": "pkg:pypi/pysocks@1.7.1"
                },
                "version_status": "estimated",
                "vulnerabilities": [],
            },
        ]
    }

    risk_data = to_cyclonedx_risk(priority)

    findings_by_purl = {
        package["purl"]: package["findings"]
        for package in risk_data["packages"]
    }

    assert len(
        findings_by_purl["pkg:pypi/requests@2.32.5"]
    ) == 1

    assert findings_by_purl["pkg:pypi/pysocks@1.7.1"] == []

    bom = convert_to_cyclonedx(
        [
            {
                "name": "requests",
                "ecosystem": "pypi",
                "resolved_version": "2.32.5",
                "purl": "pkg:pypi/requests@2.32.5",
                "dependencies": ["pkg:pypi/pysocks@1.7.1"],
            },
            {
                "name": "pysocks",
                "ecosystem": "pypi",
                "resolved_version": "1.7.1",
                "purl": "pkg:pypi/pysocks@1.7.1",
                "dependencies": [],
            },
        ],
        risk_result=risk_data,
    )

    assert len(bom["vulnerabilities"]) == 1
    assert bom["vulnerabilities"][0]["affects"] == [
        {"ref": "pkg:pypi/requests@2.32.5"}
    ]
