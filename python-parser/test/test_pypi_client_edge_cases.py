
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
    """Timeouts share the parser's recoverable RuntimeError contract."""
    def fake_urlopen(request, timeout=10):
        raise socket.timeout("Timed out")

    monkeypatch.setattr(
        pypi_client, "urlopen", fake_urlopen
    )

    with pytest.raises(RuntimeError, match="timed out"):
        PyPIClient().get_release_metadata(
            "sample", "1.0.0"
        )


def test_invalid_json(monkeypatch):
    """Invalid JSON shares the parser's recoverable RuntimeError contract."""
    def fake_urlopen(request, timeout=10):
        return io.BytesIO(b"{invalid-json}")

    monkeypatch.setattr(
        pypi_client, "urlopen", fake_urlopen
    )

    with pytest.raises(RuntimeError, match="PyPI response"):
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


def test_release_candidates_require_compatible_distribution_files(monkeypatch):
    mock_json_response(monkeypatch, {"releases": {
        "1": [{"filename": "demo-1.tar.gz", "requires_python": ">=3"}],
        "2": [{"filename": "demo-2-py3-none-any.whl", "requires_python": ">=3"}],
        "3": [],
        "4": [{"filename": "demo-4.tar.gz", "requires_python": ">=999"}],
        "5": [{"filename": "demo-5-cp27-cp27m-win32.whl"}],
        "6": [{"filename": "invalid.whl"}],
        "7": [{"filename": "demo-7.tar.gz", "yanked": True}],
    }})
    assert PyPIClient().get_available_versions("demo") == ["1", "2"]


@pytest.mark.parametrize("metadata", [
    {"info": {"requires_python": ">=999"}},
    {"info": {}, "urls": []},
    {"info": None},
    {"info": {}, "urls": [{"filename": "demo-1-cp27-cp27m-win32.whl"}]},
])
def test_unusable_exact_release_has_explicit_error(monkeypatch, metadata):
    mock_json_response(monkeypatch, metadata)
    with pytest.raises(RuntimeError):
        PyPIClient().get_dependencies("demo", "1")


@pytest.mark.parametrize("requires_dist", ["", {}, 12])
def test_malformed_requires_dist_envelope_has_diagnostic(monkeypatch, requires_dist):
    mock_json_response(monkeypatch, {"info": {"requires_dist": requires_dist}})
    client = PyPIClient()
    assert client.get_dependencies("demo", "1") == []
    assert client.get_dependency_diagnostics("demo", "1")[0]["message"] == "requires_dist must be a list"
