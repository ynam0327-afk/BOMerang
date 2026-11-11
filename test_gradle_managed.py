"""Offline local-POM tests; does not execute Gradle or use public registries."""
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

BOOT = "id 'org.springframework.boot' version '{version}'\nid 'io.spring.dependency-management' version '1.1.7'\n"

class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args): pass

class GradleManagedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.repo = Path(cls.temp.name)
        for boot, selected in [('4.0.9','7.1'), ('4.0.1','6.1')]:
            folder = cls.repo / 'org/springframework/boot/spring-boot-dependencies' / boot
            folder.mkdir(parents=True)
            (folder / f'spring-boot-dependencies-{boot}.pom').write_text(
                '<project><dependencyManagement><dependencies>'
                '<dependency><groupId>org.example</groupId><artifactId>nested-bom</artifactId>'
                f'<version>{selected}</version><type>pom</type><scope>import</scope></dependency>'
                '</dependencies></dependencyManagement></project>', encoding='utf-8')
            nested = cls.repo / 'org/example/nested-bom' / selected
            nested.mkdir(parents=True)
            (nested / f'nested-bom-{selected}.pom').write_text(
                f'<project><properties><library.version>{selected}</library.version></properties>'
                '<dependencyManagement><dependencies><dependency>'
                '<groupId>org.example</groupId><artifactId>library</artifactId>'
                '<version>${library.version}</version></dependency></dependencies>'
                '</dependencyManagement></project>', encoding='utf-8')
        cls.server = ThreadingHTTPServer(('127.0.0.1',0), functools.partial(QuietHandler,directory=str(cls.repo)))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(); cls.temp.cleanup()

    def run_gradle(self, content, kotlin=False, remote=True):
        core = Path(__file__).resolve().parent
        override = os.environ.get('BOMERANG_MANAGED_TEST_CLASSES')
        paths = [Path(override)] if override else [core/'target/classes']
        outputs = []
        for classes in paths:
            self.assertTrue((classes/'com/bomerang/JsonDependencyExporter.class').is_file(), str(classes))
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder)/('build.gradle.kts' if kotlin else 'build.gradle')
                path.write_text(content,encoding='utf-8')
                command = ['java','-Dfile.encoding=UTF-8','-cp',str(classes),'com.bomerang.JsonDependencyExporter',str(path)]
                if remote: command.append('--resolve-maven')
                env = dict(os.environ,BOMERANG_MAVEN_REPO_URL=self.url)
                result = subprocess.run(command,env=env,capture_output=True,text=True,encoding='utf-8',timeout=30,check=True)
                outputs.append(json.loads(result.stdout))
        self.assertTrue(all(rows == outputs[0] for rows in outputs))
        return outputs[0]

    def source(self, version='4.0.9', suffix=''):
        return 'plugins {\n'+BOOT.format(version=version)+'}\n'+suffix+"\ndependencies { implementation 'org.example:library' }\n"

    def test_boot_groovy_nested_bom_and_evidence(self):
        row = self.run_gradle(self.source())[0]
        self.assertEqual('7.1',row['resolved_version'])
        self.assertEqual('',row['declared_version'])
        self.assertEqual('confirmed',row['version_status'])
        self.assertEqual('gradle_bom_management',row['version_evidence']['kind'])
        self.assertTrue(row['version_evidence']['bom'].endswith(':4.0.9'))

    def test_boot_kotlin_uses_own_version(self):
        rows = self.run_gradle('plugins {\nid("org.springframework.boot") version "4.0.1"\nid("io.spring.dependency-management") version "1.1.7"\n}\ndependencies { implementation("org.example:library") }',kotlin=True)
        self.assertEqual('6.1',rows[0]['resolved_version'])

    def test_explicit_version_wins(self):
        row = self.run_gradle(self.source().replace("org.example:library'","org.example:library:9.0'"))[0]
        self.assertEqual('9.0',row['resolved_version'])
        self.assertNotEqual('gradle_bom_management',row['version_evidence']['kind'])

    def test_remote_opt_in_required(self):
        row = self.run_gradle(self.source(),remote=False)[0]
        self.assertIsNone(row['resolved_version'])

    def test_missing_bom_preserves_node(self):
        row = self.run_gradle(self.source('9.9.9'))[0]
        self.assertIsNone(row['resolved_version'])
        self.assertEqual('unresolved',row['version_status'])
        self.assertIn('gradle_bom_lookup_failed',row['resolution_error'])
        self.assertEqual('pkg:maven/org.example/library',row['purl'])

    def test_override_is_not_guessed(self):
        row = self.run_gradle(self.source(suffix="ext['library.version'] = '9.0'"))[0]
        self.assertIsNone(row['resolved_version'])
        self.assertIn('unsupported',row['resolution_error'])

    def test_single_explicit_bom(self):
        row = self.run_gradle("plugins { id 'io.spring.dependency-management' version '1.1.7' }\ndependencyManagement { imports { mavenBom 'org.springframework.boot:spring-boot-dependencies:4.0.1' } }\ndependencies { implementation 'org.example:library' }")[0]
        self.assertEqual('6.1',row['resolved_version'])

    def test_multiple_boms_are_not_guessed(self):
        row = self.run_gradle(self.source(suffix="plugins { id 'io.spring.dependency-management' version '1.1.7' }\ndependencyManagement { imports { mavenBom 'org.example:nested-bom:7.1' } }"))[0]
        self.assertIsNone(row['resolved_version'])

    def test_management_plugin_required(self):
        row = self.run_gradle(self.source().replace("id 'io.spring.dependency-management' version '1.1.7'",''))[0]
        self.assertIsNone(row['resolved_version'])

    def test_missing_entry_preserved(self):
        row = self.run_gradle(self.source().replace('org.example:library','org.example:absent'))[0]
        self.assertIsNone(row['resolved_version'])
        self.assertIn('no_exact_version',row['resolution_error'])

    def test_commented_plugin_not_used(self):
        row = self.run_gradle("// id 'org.springframework.boot' version '4.0.9'\ndependencies { implementation 'org.example:library' }")[0]
        self.assertIsNone(row['resolved_version'])


    def test_platform_in_artifact_name_is_not_a_function(self):
        rows = self.run_gradle(
            self.source() +
            "dependencies { testRuntimeOnly 'org.junit.platform:junit-platform-launcher' }\n"
        )
        library = next(r for r in rows if r["name"] == "library")
        self.assertEqual("7.1", library["resolved_version"])

    def test_actual_platform_function_stays_unresolved(self):
        rows = self.run_gradle(self.source(
            suffix="dependencies { implementation(platform('org.example:bom:1.0')) }"
        ))
        self.assertIsNone(rows[0]["resolved_version"])
        self.assertIn("unsupported", rows[0]["resolution_error"])


    def test_bom_project_coordinates(self):
        folder = self.repo / "org/example/coordinate-bom/8.2"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "coordinate-bom-8.2.pom").write_text(
            "<project><groupId>org.example</groupId>"
            "<artifactId>coordinate-bom</artifactId><version>8.2</version>"
            "<properties><library.version>${project.version}</library.version></properties>"
            "<dependencyManagement><dependencies><dependency>"
            "<groupId>${project.groupId}</groupId><artifactId>library</artifactId>"
            "<version>${library.version}</version></dependency>"
            "</dependencies></dependencyManagement></project>",
            encoding="utf-8"
        )
        code = (
            "plugins { id 'io.spring.dependency-management' version '1.1.7' }\n"
            "dependencyManagement { imports { mavenBom 'org.example:coordinate-bom:8.2' } }\n"
            "dependencies { implementation 'org.example:library' }"
        )
        row = self.run_gradle(code)[0]
        self.assertEqual("8.2", row["resolved_version"])
        self.assertEqual("confirmed", row["version_status"])

if __name__ == '__main__': unittest.main(verbosity=2)
