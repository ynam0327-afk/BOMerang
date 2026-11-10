import sys
import json
import tempfile
from pathlib import Path
from collections import Counter

from packaging.requirements import Requirement

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / "python-parser"))

from python_parser import PythonParser


class CountingPyPIClient:
    def __init__(self):
        self.dependency_calls = Counter()
        self.version_calls = Counter()

    def get_available_versions(self, package_name):
        self.version_calls[package_name.lower()] += 1
        return ["1.0.0", "1.5.0", "2.0.0"]

    def get_dependencies(self, package_name, version, extras=None):
        extras_key = tuple(sorted(extras or []))
        key = (package_name.lower(), version, extras_key)
        self.dependency_calls[key] += 1

        if package_name.lower() in ("parent-a", "parent-b"):
            return [Requirement("shared>=1.0")]

        return []


def main():
    with tempfile.TemporaryDirectory() as tmp:
        requirements = Path(tmp) / "requirements.txt"
        requirements.write_text(
            "parent-a==1.0.0\n"
            "parent-b==1.0.0\n",
            encoding="utf-8"
        )

        client = CountingPyPIClient()
        parser = PythonParser(pypi_client=client)
        nodes = parser.parse(str(requirements))

        report = {
            "node_count": len(nodes),
            "dependency_calls": [
                {
                    "package": key[0],
                    "version": key[1],
                    "extras": list(key[2]),
                    "count": count
                }
                for key, count in client.dependency_calls.items()
            ],
            "version_calls": dict(client.version_calls),
            "total_dependency_calls": sum(
                client.dependency_calls.values()
            ),
            "total_version_calls": sum(
                client.version_calls.values()
            )
        }

        output = ROOT / "performance-results" / "api-calls-before.json"
        output.parent.mkdir(exist_ok=True)
        output.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

        print(json.dumps(report, indent=2, ensure_ascii=False))
        print(f"\nSaved: {output}")


if __name__ == "__main__":
    main()
