"""Offline HTTP test of Maven POM downloads and recursive JSON export."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from integrated_parser import analyze

ROOT = Path(__file__).resolve().parent
CLASSES = ROOT / "target" / "classes"


@unittest.skipUnless(
    (CLASSES / "com" / "bomerang" / "JsonDependencyExporter.class").is_file(),
    "Compile Java sources into target/classes first",
)
class RemoteMavenTest(unittest.TestCase):
    def test_child_and_grandchild_are_downloaded_and_linked(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            project = base / "project"
            project.mkdir()
            project.joinpath("pom.xml").write_text(self.pom("root", "child"), encoding="utf-8")
            repository = base / "repository"
            self.release(repository, "child", self.pom("child", "grandchild"))
            self.release(repository, "grandchild", self.pom("grandchild", None))
            handler = partial(SimpleHTTPRequestHandler, directory=str(repository))
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                with patch.dict(os.environ, {"BOMERANG_MAVEN_REPO_URL": f"http://127.0.0.1:{server.server_port}"}):
                    result = analyze(project, CLASSES, resolve_maven=True)
            finally:
                server.shutdown()
                server.server_close()
                worker.join()
            nodes = {node["name"]: node for node in result["dependencies"]}
            self.assertEqual({"child", "grandchild"}, set(nodes))
            self.assertEqual([nodes["grandchild"]["purl"]], nodes["child"]["dependencies"])
            self.assertEqual(2, nodes["grandchild"]["depth"])

    @staticmethod
    def pom(artifact, child):
        dependency = (f"<dependencies><dependency><groupId>org.example</groupId>"
                      f"<artifactId>{child}</artifactId><version>1.0</version>"
                      "</dependency></dependencies>") if child else ""
        return f"<project><groupId>org.example</groupId><artifactId>{artifact}</artifactId>" \
               f"<version>1.0</version>{dependency}</project>"

    @staticmethod
    def release(repository, artifact, content):
        path = repository / "org" / "example" / artifact / "1.0"
        path.mkdir(parents=True)
        (path / f"{artifact}-1.0.pom").write_text(content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
