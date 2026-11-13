"""Managed scopes must not leak library-only test dependencies into consumers."""
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

class ManagedScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.repo = self.folder / 'repo'
        self.repo.mkdir()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(self.repo)))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def publish(self, artifact, body):
        folder = self.repo / 'org/example' / artifact / '1.0'
        folder.mkdir(parents=True, exist_ok=True)
        (folder / (artifact + '-1.0.pom')).write_text(
            '<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId>'
            '<artifactId>' + artifact + '</artifactId><version>1.0</version>' + body + '</project>', encoding='utf-8')

    def dependency(self, artifact, scope=None, version=False):
        return ('<dependency><groupId>org.example</groupId><artifactId>' + artifact + '</artifactId>'
                + ('<version>1.0</version>' if version else '')
                + ('<scope>' + scope + '</scope>' if scope else '') + '</dependency>')

    def run_case(self, managed_scope='test', explicit_scope=None, imported=False, root_direct=False, typed_collision=False, classifier_collision=False):
        managed = '<dependencyManagement><dependencies>' + self.dependency('test-helper', managed_scope, True) + '</dependencies></dependencyManagement>'
        if typed_collision or classifier_collision:
            test_variant = self.dependency('test-helper', 'test', True)
            variant = '<type>test-jar</type>' if typed_collision else '<classifier>tests</classifier>'
            test_variant = test_variant.replace('</artifactId>', '</artifactId>' + variant)
            managed = ('<dependencyManagement><dependencies>'
                       + self.dependency('test-helper', version=True) + test_variant
                       + '</dependencies></dependencyManagement>')
        self.publish('test-helper', '')
        if imported:
            self.publish('scope-bom', managed)
            managed = ('<dependencyManagement><dependencies><dependency><groupId>org.example</groupId>'
                       '<artifactId>scope-bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope>'
                       '</dependency></dependencies></dependencyManagement>')
        self.publish('parent', '<packaging>pom</packaging>' + managed)
        parent = '<parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>1.0</version></parent>'
        self.publish('library', parent + '<dependencies>' + self.dependency('test-helper', explicit_scope) + '</dependencies>')
        body = (parent + '<dependencies>' + self.dependency('test-helper') + '</dependencies>' if root_direct
                else '<dependencies>' + self.dependency('library', version=True) + '</dependencies>')
        pom = self.folder / 'pom.xml'
        pom.write_text('<project>' + body + '</project>', encoding='utf-8')
        classes = Path(__file__).resolve().parent / 'target/classes'
        self.assertTrue((classes/'com/bomerang/JsonDependencyExporter.class').is_file())
        env = dict(os.environ, BOMERANG_MAVEN_REPO_URL='http://127.0.0.1:' + str(self.server.server_port))
        result = subprocess.run(['java', '-Dfile.encoding=UTF-8', '-cp', str(classes),
                                 'com.bomerang.JsonDependencyExporter', str(pom), '--resolve-maven'],
                                env=env, capture_output=True, text=True, encoding='utf-8', check=True, timeout=30)
        return json.loads(result.stdout)

    def test_parent_managed_test_not_transitive(self):
        self.assertEqual(['library'], [row['name'] for row in self.run_case()])

    def test_parent_managed_provided_not_transitive(self):
        self.assertEqual(['library'], [row['name'] for row in self.run_case(managed_scope='provided')])

    def test_explicit_compile_overrides_managed_test(self):
        rows = self.run_case(explicit_scope='compile')
        self.assertEqual({'library', 'test-helper'}, {row['name'] for row in rows})

    def test_root_managed_test_is_retained_as_test(self):
        rows = self.run_case(root_direct=True)
        self.assertEqual(1, len(rows))
        self.assertEqual('test', rows[0]['scope'])

    def test_imported_managed_test_not_transitive(self):
        self.assertEqual(['library'], [row['name'] for row in self.run_case(imported=True)])

    def test_test_jar_scope_does_not_replace_regular_jar_scope(self):
        rows = self.run_case(typed_collision=True)
        self.assertEqual({'library', 'test-helper'}, {row['name'] for row in rows})
        self.assertTrue(all(row['scope'] == 'compile' for row in rows))

    def test_classifier_scope_does_not_replace_regular_jar_scope(self):
        rows = self.run_case(classifier_collision=True)
        self.assertEqual({'library', 'test-helper'}, {row['name'] for row in rows})
        self.assertTrue(all(row['scope'] == 'compile' for row in rows))
