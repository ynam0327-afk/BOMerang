from pypi_client import PyPIClient
from packaging.requirements import Requirement

def test_get_dependencies(monkeypatch):

    fake_metadata = {
        "info": {
            "name": "requests",
            "version": "2.32.5",
            "requires_dist": [
                "charset-normalizer<4,>=2",
                "idna<4,>=2.5",
                "urllib3<3,>=1.21.1",
                "certifi>=2017.4.17"
            ]
        }
    }

    client = PyPIClient()

    def fake_get_release_metadata(package_name, version):
        assert package_name == "requests"
        assert version == "2.32.5"

        return fake_metadata

    monkeypatch.setattr(
        client,
        "get_release_metadata",
        fake_get_release_metadata
    )

    dependencies = client.get_dependencies(
        "requests",
        "2.32.5"
    )

    names = {
        dependency.name
        for dependency in dependencies
    }

    assert "urllib3" in names
    assert "certifi" in names
    assert "idna" in names
    assert "charset-normalizer" in names

def test_get_dependencies_filters_environment_markers():
    client = PyPIClient()

    client.get_release_metadata = lambda package_name, version: {
        "info": {
            "requires_dist": [
                "requests",
                "win-only; sys_platform == 'win32'",
                "linux-only; sys_platform == 'linux'",
            ]
        }
    }

    dependencies = client.get_dependencies("test-package", "1.0.0")
    names = [str(req.name) for req in dependencies]

    assert "requests" in names
    assert ("win-only" in names) == (
        __import__("sys").platform == "win32"
    )
    assert ("linux-only" in names) == (
        __import__("sys").platform.startswith("linux")
    )