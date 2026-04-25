from pathlib import Path

from aegis.policy import PolicyError, assert_target_authorized, load_authorization_reference


def test_authorized_target_passes():
    assert_target_authorized("https://example.com", {"example.com"})


def test_unauthorized_target_fails():
    try:
        assert_target_authorized("https://evil.com", {"example.com"})
    except PolicyError:
        return
    raise AssertionError("Expected PolicyError for unauthorized target")


def test_authorization_reference_required(tmp_path: Path):
    scope = tmp_path / "scope.yaml"
    scope.write_text("authorization_reference: ENG-TEST-123\nauthorized_targets:\n  - example.com\n")
    assert load_authorization_reference(scope) == "ENG-TEST-123"
