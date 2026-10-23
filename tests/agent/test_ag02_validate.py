"""AG02.1 — scan request validation."""

from __future__ import annotations

import pytest

from aegis.api.schemas import ScanRequest
from aegis.router import RequestInvalid, validate_request

pytestmark = pytest.mark.phase("AG02")


@pytest.fixture
def roots(tmp_path):
    (tmp_path / "scan").mkdir()
    return (str(tmp_path / "scan"),)


def _expect(req: ScanRequest, roots, needle: str):
    with pytest.raises(RequestInvalid) as ei:
        validate_request(req, allowed_source_roots=roots)
    assert needle in ei.value.reason


def test_none_provided_rejected(roots):
    _expect(ScanRequest(), roots, "at least one")


def test_folder_and_repo_mutually_exclusive(roots, tmp_path):
    folder = str(tmp_path / "scan")
    _expect(ScanRequest(folder=folder, repo="https://x/y"), roots, "mutually exclusive")


def test_url_must_be_http(roots):
    _expect(ScanRequest(url="ftp://demo", identities="/id.yml"), roots, "http")


def test_url_requires_identities(roots):
    _expect(ScanRequest(url="http://demo-app:5000"), roots, "identities")


def test_folder_must_exist(roots, tmp_path):
    missing = str(tmp_path / "scan" / "nope")
    _expect(ScanRequest(folder=missing), roots, "does not exist")


def test_folder_outside_roots_rejected(roots, tmp_path):
    outside = tmp_path / "other"
    outside.mkdir()
    _expect(ScanRequest(folder=str(outside)), roots, "outside the allowed")


def test_path_traversal_rejected(roots, tmp_path):
    secret = tmp_path / "secret"
    secret.mkdir()
    traversal = str(tmp_path / "scan" / ".." / "secret")
    _expect(ScanRequest(folder=traversal), roots, "outside the allowed")


def test_symlink_escape_rejected(roots, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "scan" / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")
    _expect(ScanRequest(folder=str(link)), roots, "outside the allowed")


def test_valid_runtime_request(roots):
    req = ScanRequest(url="http://demo-app:5000", identities="/app/identities.yml")
    assert validate_request(req, allowed_source_roots=roots) is req


def test_valid_code_request(roots, tmp_path):
    folder = str(tmp_path / "scan")
    req = ScanRequest(folder=folder)
    assert validate_request(req, allowed_source_roots=roots) is req


def test_valid_correlated_request(roots, tmp_path):
    folder = str(tmp_path / "scan")
    req = ScanRequest(
        url="http://demo-app:5000", folder=folder, identities="/app/identities.yml"
    )
    assert validate_request(req, allowed_source_roots=roots) is req
