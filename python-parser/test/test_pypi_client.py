from pypi_client import PyPIClient


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