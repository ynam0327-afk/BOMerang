import json
import subprocess
import tempfile
import unittest
from pathlib import Path

CORE = Path(__file__).resolve().parent

class MissingGradleVersionTests(unittest.TestCase):
    def check_case(self, filename, content, expected):
        for classes in (CORE / "target/classes",):
            with self.subTest(classes=str(classes)):
                with tempfile.TemporaryDirectory() as temp:
                    source = Path(temp) / filename
                    source.write_text(content, encoding="utf-8")
                    completed = subprocess.run(
                        ["java", "-Dfile.encoding=UTF-8", "-cp", str(classes),
                         "com.bomerang.JsonDependencyExporter", str(source)],
                        capture_output=True, text=True, encoding="utf-8",
                        check=True, timeout=30,
                    )
                    rows = json.loads(completed.stdout)
                    actual = [
                        (r["purl"], r["resolved_version"],
                         r["version_status"], r["scope"])
                        for r in rows
                    ]
                    self.assertCountEqual(expected, actual)

    def test_groovy_versionless(self):
        self.check_case(
            "build.gradle",
            "dependencies { implementation 'org.example:library' }\n",
            [("pkg:maven/org.example/library", None, "unresolved", "compile")],
        )

    def test_kotlin_versionless(self):
        self.check_case(
            "build.gradle.kts",
            'dependencies { testImplementation("org.example:tests") }\n',
            [("pkg:maven/org.example/tests", None, "unresolved", "test")],
        )

    def test_mixed_versions(self):
        self.check_case(
            "build.gradle",
            "dependencies {\n"
            " implementation 'org.example:library'\n"
            " runtimeOnly 'org.example:driver:2.0'\n"
            "}\n",
            [
                ("pkg:maven/org.example/library", None, "unresolved", "compile"),
                ("pkg:maven/org.example/driver@2.0", "2.0", "confirmed", "runtime"),
            ],
        )
