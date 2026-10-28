
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

REPORT_DIR = Path(__file__).resolve().parent / "test-reports"
XML_PATH = REPORT_DIR / "pytest-results.xml"
JSON_PATH = REPORT_DIR / "test-summary.json"


def summarize():
    root = ET.parse(XML_PATH).getroot()
    cases = root.findall(".//testcase")

    results = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(cases),
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "failures": [],
    }

    for case in cases:
        failure = case.find("failure")
        error = case.find("error")
        skipped = case.find("skipped")

        if failure is not None or error is not None:
            kind = "failure" if failure is not None else "error"
            node = failure if failure is not None else error
            results["failed" if kind == "failure" else "errors"] += 1

            results["failures"].append({
                "test": case.get("name"),
                "module": case.get("classname"),
                "category": kind,
                "exception_type": (node.get("type")
                    or (node.get("message")
                    or "").split(":")[0]
                    or "UnknownError"),
                "message": node.get("message"),
                "traceback": node.text or "",
            })

        elif skipped is not None:
            results["skipped"] += 1
        else:
            results["passed"] += 1

    JSON_PATH.write_text(
        json.dumps(results, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"Total: {results['total']}")
    print(f"Passed: {results['passed']}")
    print(f"Failed: {results['failed']}")
    print(f"Errors: {results['errors']}")
    print(f"Skipped: {results['skipped']}")
    print(f"Saved: {JSON_PATH}")


if __name__ == "__main__":
    summarize()
