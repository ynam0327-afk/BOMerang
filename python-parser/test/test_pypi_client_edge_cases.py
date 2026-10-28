
import io
import json
import socket

import pytest
from urllib.error import HTTPError, URLError

import pypi_client
from pypi_client import PyPIClient


def mock_json_response(monkeypatch, data):
    """Replace the actual HTTP response with a fake response."""
    payload = json.dumps(data).encode("utf-8")

    def fake_urlopen(request, timeout=10):
        return io.BytesIO(payload)

    monkeypatch.setattr(
        pypi_client, "urlopen", fake_urlopen
    )


def test_api_success(monkeypatch):
    """Normal response returns package metadata."""
    mock_json_response(monkeypatch, {
        "info": {"name": "sample", "version": "1.0.0"}
    })

    result = PyPIClient().get_release_metadata(
        "sample", "1.0.0"
    )

    assert result["info"]["name"] == "sample"


@pytest.mark.parametrize("status", [404, 500])
def test_http_error(monkeypatch, status):
    """HTTP errors are converted into RuntimeError."""
    def fake_urlopen(request, timeout=10):
        raise HTTPError(
            request.full_url, status,
            "HTTP error", {}, None
        )

    monkeypatch.setattr(
        pypi_client, "urlopen", fake_urlopen
    )

    with pytest.raises(RuntimeError) as exc:
        PyPIClient().get_release_metadata(
            "sample", "1.0.0"
        )

    assert str(status) in str(exc.value)


def test_network_failure(monkeypatch):
    """Connection errors are reported."""
    def fake_urlopen(request, timeout=10):
        raise URLError("Connection refused")

    monkeypatch.setattr(
        pypi_client, "urlopen", fake_urlopen
    )

    with pytest.raises(RuntimeError, match="Could not connect"):
        PyPIClient().get_release_metadata(
            "sample", "1.0.0"
        )


def test_timeout(monkeypatch):
    """Direct socket timeout propagates to the caller."""
    def fake_urlopen(request, timeout=10):
        raise socket.timeout("Timed out")

    monkeypatch.setattr(
        pypi_client, "urlopen", fake_urlopen
    )

    with pytest.raises(TimeoutError):
        PyPIClient().get_release_metadata(
            "sample", "1.0.0"
        )


def test_invalid_json(monkeypatch):
    """Invalid JSON raises a parsing exception."""
    def fake_urlopen(request, timeout=10):
        return io.BytesIO(b"{invalid-json}")

    monkeypatch.setattr(
        pypi_client, "urlopen", fake_urlopen
    )

    with pytest.raises(json.JSONDecodeError):
        PyPIClient().get_release_metadata(
            "sample", "1.0.0"
        )


def test_empty_release_list(monkeypatch):
    """Empty releases return an empty list."""
    mock_json_response(monkeypatch, {
        "releases": {}
    })

    versions = PyPIClient().get_available_versions(
        "sample"
    )

    assert versions == []


def test_invalid_and_yanked_versions(monkeypatch):
    """Invalid versions and yanked releases are excluded."""
    mock_json_response(monkeypatch, {
        "releases": {
            "1.0.0": [{"yanked": False}],
            "1.1.0": [{"yanked": True}],
            "invalid-version!": [{"yanked": False}],
            "2.0.0": [{"yanked": False}]
        }
    })

    versions = PyPIClient().get_available_versions(
        "sample"
    )

    assert versions == ["1.0.0", "2.0.0"]


def test_malformed_dependency(monkeypatch):
    """Malformed requirements are skipped."""
    mock_json_response(monkeypatch, {
        "info": {
            "requires_dist": [
                "requests>=2.0",
                "invalid requirement !!!",
                "urllib3>=1.0"
            ]
        }
    })

    dependencies = PyPIClient().get_dependencies(
        "sample", "1.0.0"
    )

    names = {dependency.name for dependency in dependencies}

    assert names == {"requests", "urllib3"}
