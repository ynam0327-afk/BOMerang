import tempfile
import unittest
from pathlib import Path

from integrated_parser import analyze

ROOT = Path(__file__).resolve().parent
CLASSES = ROOT / "target" / "classes"


class GradleDeclarationTests(unittest.TestCase):
    def check_gradle(self, content, expected, kotlin=False):
        self.assertTrue(
            (CLASSES / "com/bomerang/JsonDependencyExporter.class").is_file(),
            "Java compilation is required",
        )
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            filename = "build.gradle.kts" if kotlin else "build.gradle"
            (project / filename).write_text(content, encoding="utf-8")
            result = analyze(project, CLASSES)
            actual = [
                (node["purl"], node["scope"])
                for node in result["dependencies"]
            ]
            self.assertCountEqual(expected, actual)
            self.assertIn(filename, result["files"])

    def test_inline_groovy(self):
        self.check_gradle(
            "plugins { id 'java' }\n"
            "repositories { mavenCentral() }\n"
            "dependencies { implementation "
            "'org.apache.commons:commons-lang3:3.12.0' }\n",
            [("pkg:maven/org.apache.commons/commons-lang3@3.12.0", "compile")],
        )

    def test_multiline_groovy(self):
        self.check_gradle(
            "dependencies {\n"
            "    implementation 'org.example:library:1.0'\n"
            "    runtimeOnly 'org.example:driver:2.0'\n"
            "}\n",
            [
                ("pkg:maven/org.example/library@1.0", "compile"),
                ("pkg:maven/org.example/driver@2.0", "runtime"),
            ],
        )

    def test_inline_kotlin(self):
        self.check_gradle(
            'dependencies { implementation("org.example:library:1.0") }\n',
            [("pkg:maven/org.example/library@1.0", "compile")],
            kotlin=True,
        )

    def test_semicolon_separated(self):
        self.check_gradle(
            "dependencies { implementation 'org.example:library:1.0'; "
            "testImplementation 'org.example:tests:2.0' }\n",
            [
                ("pkg:maven/org.example/library@1.0", "compile"),
                ("pkg:maven/org.example/tests@2.0", "test"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
