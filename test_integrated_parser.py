"""20 offline integration cases for the Python/Java dependency pipeline.

Compile src/main/java into target/classes, then run:
    python -m unittest -v test_integrated_parser
"""
import json
from pathlib import Path
import tempfile
import unittest

from integrated_parser import analyze

ROOT = Path(__file__).resolve().parent
CLASSES = ROOT / "target" / "classes"


class NoNetworkPyPI:
    def __init__(self, dependencies=()):
        self.dependencies = dependencies
        self.calls = []

    def get_dependencies(self, name, version):
        self.calls.append((name, version))
        return self.dependencies


@unittest.skipUnless(
    (CLASSES / "com" / "bomerang" / "JsonDependencyExporter.class").is_file(),
    "Compile Java sources into target/classes before running integration tests",
)
class IntegratedParserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name)
        self.client = NoNetworkPyPI()

    def requirements(self, content, folder=None):
        path = folder or self.project
        path.mkdir(parents=True, exist_ok=True)
        (path / "requirements.txt").write_text(content, encoding="utf-8")

    def pom(self, dependencies, folder=None):
        path = folder or self.project
        path.mkdir(parents=True, exist_ok=True)
        rows = []
        for group, artifact, version, scope in dependencies:
            scope_xml = f"<scope>{scope}</scope>" if scope else ""
            rows.append(f"<dependency><groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
                        f"<version>{version}</version>{scope_xml}</dependency>")
        (path / "pom.xml").write_text(
            "<project><dependencies>" + "".join(rows) + "</dependencies></project>", encoding="utf-8"
        )

    def gradle(self, lines, folder=None, kotlin=False):
        path = folder or self.project
        path.mkdir(parents=True, exist_ok=True)
        name = "build.gradle.kts" if kotlin else "build.gradle"
        (path / name).write_text("dependencies {\n" + lines + "\n}", encoding="utf-8")

    def result(self):
        return analyze(self.project, CLASSES, self.client)

    def nodes(self):
        return self.result()["dependencies"]

    def test_01_mixed_pom_and_requirements(self):
        self.pom([("org.example", "java-demo", "1.0", None)])
        self.requirements("python-demo>=1.0\n")
        result = self.result()
        self.assertEqual({"maven", "pypi"}, {n["ecosystem"] for n in result["dependencies"]})
        self.assertEqual({"pom.xml", "requirements.txt"}, set(result["files"]))

    def test_02_empty_project(self):
        self.assertEqual({"files": [], "dependencies": []}, self.result())

    def test_03_empty_pom_and_requirements(self):
        self.pom([])
        self.requirements("# empty\n")
        self.assertEqual(0, len(self.nodes()))
        self.assertEqual(2, len(self.result()["files"]))

    def test_04_java_purl_contains_group_artifact_version(self):
        self.pom([("org.example", "library", "2.0", None)])
        self.assertEqual("pkg:maven/org.example/library@2.0", self.nodes()[0]["purl"])

    def test_05_python_unpinned_version_is_unresolved(self):
        self.requirements("python-demo>=1.0\n")
        node = self.nodes()[0]
        self.assertEqual("pkg:pypi/python-demo", node["purl"])
        self.assertIsNone(node["resolved_version"])

    def test_06_python_exact_version(self):
        self.requirements("python-demo==1.2.3\n")
        node = self.nodes()[0]
        self.assertEqual("1.2.3", node["resolved_version"])
        self.assertEqual("pkg:pypi/python-demo@1.2.3", node["purl"])
        self.assertEqual([("python-demo", "1.2.3")], self.client.calls)

    def test_07_java_default_scope(self):
        self.pom([("org.example", "library", "1.0", None)])
        self.assertEqual("compile", self.nodes()[0]["scope"])

    def test_08_java_test_scope(self):
        self.pom([("org.example", "library", "1.0", "test")])
        self.assertEqual("test", self.nodes()[0]["scope"])

    def test_09_multiple_java_and_python_packages(self):
        self.pom([("org.example", "a", "1", None), ("org.example", "b", "2", None)])
        self.requirements("python-a>=1\npython-b>=2\n")
        self.assertEqual(4, len(self.nodes()))

    def test_10_identical_names_across_ecosystems_remain_distinct(self):
        self.pom([("org.example", "shared", "1", None)])
        self.requirements("shared>=1\n")
        self.assertEqual(2, len({n["purl"] for n in self.nodes()}))

    def test_11_python_duplicate_lines_are_merged(self):
        self.requirements("shared>=1\nshared>=1\n")
        self.assertEqual(1, len(self.nodes()))

    def test_12_gradle_and_python_mixed(self):
        self.gradle("implementation 'org.example:gradle-demo:1.0'")
        self.requirements("python-demo>=1\n")
        self.assertEqual({"maven", "pypi"}, {n["ecosystem"] for n in self.nodes()})

    def test_13_gradle_kotlin_and_python_mixed(self):
        self.gradle('implementation("org.example:kotlin-demo:1.0")', kotlin=True)
        self.requirements("python-demo>=1\n")
        self.assertEqual(2, len(self.nodes()))

    def test_14_gradle_runtime_scope(self):
        self.gradle("runtimeOnly 'org.example:runtime-demo:1.0'")
        self.assertEqual("runtime", self.nodes()[0]["scope"])

    def test_15_gradle_test_scope(self):
        self.gradle("testImplementation 'org.example:test-demo:1.0'")
        self.assertEqual("test", self.nodes()[0]["scope"])

    def test_16_nested_modules_are_found(self):
        self.pom([("org.example", "nested-java", "1", None)], self.project / "java-app")
        self.requirements("nested-python>=1\n", self.project / "python-app")
        paths = {path.replace("\\", "/") for path in self.result()["files"]}
        self.assertEqual({"java-app/pom.xml", "python-app/requirements.txt"}, paths)

    def test_17_git_directory_is_ignored(self):
        self.requirements("ignored>=1\n", self.project / ".git")
        self.assertEqual([], self.result()["files"])

    def test_18_target_directory_is_ignored(self):
        self.pom([("org.example", "ignored", "1", None)], self.project / "target")
        self.assertEqual([], self.result()["files"])

    def test_19_referenced_requirements_are_included(self):
        self.requirements("-r base.txt\n")
        (self.project / "base.txt").write_text("referenced>=1\n", encoding="utf-8")
        self.assertEqual("referenced", self.nodes()[0]["name"])

    def test_20_result_is_json_serializable(self):
        self.pom([("org.example", "java-demo", "1", None)])
        self.requirements("python-demo>=1\n")
        restored = json.loads(json.dumps(self.result()))
        self.assertEqual(2, len(restored["dependencies"]))


if __name__ == "__main__":
    unittest.main()
