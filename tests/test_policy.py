from aegis.policy import PolicyError, assert_target_authorized


def test_authorized_target_passes():
    assert_target_authorized("https://example.com", {"example.com"})


def test_unauthorized_target_fails():
    try:
        assert_target_authorized("https://evil.com", {"example.com"})
    except PolicyError:
        return
    raise AssertionError("Expected PolicyError for unauthorized target")
