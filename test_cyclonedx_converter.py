import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from cyclonedx_converter import convert_to_cyclonedx


class CycloneDXConverterTests(unittest.TestCase):
    def test_empty_result_creates_valid_basic_bom(self):
        bom = convert_to_cyclonedx({"files": [], "dependencies": []}, serial_number="urn:uuid:test")
        self.assertEqual("CycloneDX", bom["bomFormat"])
        self.assertEqual("1.6", bom["specVersion"])
        self.assertEqual([], bom["components"])
        self.assertEqual([], bom["dependencies"])

    def test_component_and_dependency_relationships(self):
        result = {
            "files": ["requirements.txt"],
            "dependencies": [
                {
                    "name": "requests", "ecosystem": "pypi",
                    "resolved_version": "2.32.5", "declared_version": "==2.32.5",
                    "purl": "pkg:pypi/requests@2.32.5",
                    "dependencies": ["pkg:pypi/urllib3@2.2.0"],
                    "scope": None, "depth": 1, "source_file": "requirements.txt",
                    "parse_status": "success", "error_message": None, "is_circular": False,
                },
                {
                    "name": "urllib3", "ecosystem": "pypi",
                    "resolved_version": "2.2.0", "declared_version": ">=2.0",
                    "purl": "pkg:pypi/urllib3@2.2.0", "dependencies": [],
                    "scope": None, "depth": 2,
                },
            ],
        }
        bom = convert_to_cyclonedx(result, serial_number="urn:uuid:test")
        self.assertEqual(2, len(bom["components"]))
        self.assertEqual(
            {"ref": "pkg:pypi/requests@2.32.5", "dependsOn": ["pkg:pypi/urllib3@2.2.0"]},
            bom["dependencies"][0],
        )
        requests = next(c for c in bom["components"] if c["name"] == "requests")
        self.assertEqual("2.32.5", requests["version"])
        self.assertEqual("pkg:pypi/requests@2.32.5", requests["purl"])
        self.assertEqual(requests["purl"], requests["bom-ref"])
        self.assertIn({"name": "bomerang:declared_version", "value": "==2.32.5"}, requests["properties"])
        self.assertEqual("requirements.txt", bom["metadata"]["properties"][0]["value"])

    def test_java_group_and_test_scope(self):
        result = {"files": ["pom.xml"], "dependencies": [{
            "name": "spring-core", "group": "org.springframework", "ecosystem": "maven",
            "resolved_version": "6.1.0", "purl": "pkg:maven/org.springframework/spring-core@6.1.0",
            "scope": "test", "dependencies": [],
        }]}
        bom = convert_to_cyclonedx(result, serial_number="urn:uuid:test")
        component = bom["components"][0]
        self.assertEqual("org.springframework", component["group"])
        self.assertEqual("optional", component["scope"])

    def test_dangling_dependency_is_not_emitted(self):
        result = {"files": [], "dependencies": [{
            "name": "a", "ecosystem": "pypi", "purl": "pkg:pypi/a",
            "dependencies": ["pkg:pypi/not-present"],
        }]}
        bom = convert_to_cyclonedx(result, serial_number="urn:uuid:test")
        self.assertEqual([{"ref": "pkg:pypi/a", "dependsOn": []}], bom["dependencies"])

    def test_missing_purl_is_rejected(self):
        with self.assertRaises(ValueError):
            convert_to_cyclonedx({"files": [], "dependencies": [{"name": "no-purl"}]})


    def test_risk_findings_are_attached_to_components(self):
        dependency_result = [{
            "name": "jackson-databind", "ecosystem": "maven",
            "group": "tools.jackson.core", "resolved_version": "3.1.5",
            "purl": "pkg:maven/tools.jackson.core/jackson-databind@3.1.5",
            "dependencies": [], "scope": "compile", "depth": 4,
        }]
        risk_result = {
            "model_version": "0.1",
            "generated_at": "2026-10-06T06:37:31Z",
            "coverage_note": "OSV package/version matching",
            "packages": [{
                "purl": "pkg:maven/tools.jackson.core/jackson-databind@3.1.5",
                "findings": [{
                    "vulnerability_id": "CVE-2026-68497",
                    "aliases": ["CVE-2026-68497", "GHSA-q4xh-88c3-wmh7"],
                    "cvss_score": 7.5, "cvss_version": "3.1",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    "priority_score": 79.0, "severity": "HIGH",
                    "review_required": True,
                    "review_reasons": ["exploit_conditions_not_verified"],
                    "exploit_conditions_status": "not_verified",
                    "score_breakdown": {"cvss": 60.0, "scope": 15.0, "depth": 4.0},
                }],
            }],
        }
        bom = convert_to_cyclonedx(dependency_result, risk_result=risk_result,
                                   serial_number="urn:uuid:test")
        self.assertEqual(1, len(bom["vulnerabilities"]))
        vuln = bom["vulnerabilities"][0]
        self.assertEqual("CVE-2026-68497", vuln["id"])
        self.assertEqual([{"ref": dependency_result[0]["purl"]}], vuln["affects"])
        self.assertEqual(7.5, vuln["ratings"][0]["score"])
        self.assertEqual("CVSSv31", vuln["ratings"][0]["method"])
        props = {p["name"]: p["value"] for p in vuln["properties"]}
        self.assertEqual("79.0", props["bomerang:priority_score"])
        self.assertEqual("true", props["bomerang:review_required"])
        self.assertEqual("required", props["bomerang:review_status"])
        self.assertEqual("2026-10-06T06:37:31Z", next(
            p["value"] for p in bom["metadata"]["properties"]
            if p["name"] == "bomerang:risk_generated_at"
        ))

    def test_risk_for_unknown_component_does_not_create_dangling_affects(self):
        bom = convert_to_cyclonedx(
            [{"name": "a", "purl": "pkg:pypi/a", "dependencies": []}],
            risk_result={"packages": [{"purl": "pkg:pypi/missing", "findings": [{
                "vulnerability_id": "CVE-2099-0001", "cvss_score": 5.0
            }]}]},
            serial_number="urn:uuid:test",
        )
        self.assertEqual([], bom["vulnerabilities"][0]["affects"])


if __name__ == "__main__":
    unittest.main()
