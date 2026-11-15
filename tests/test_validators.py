import pytest

from app import validators as v


@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", "example.com"),
    ("https://www.ida.co.th/path?q=1", "www.ida.co.th"),
    ("ตัวอย่าง.ไทย", "xn--72c1a1bt4awk9o.xn--o3cw4h"),
])
def test_normalize_domain_ok(raw, expected):
    assert v.normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "-bad.com", "a..b.com", "x" * 300 + ".com", "1.2.3.4"])
def test_normalize_domain_rejects(raw):
    with pytest.raises(v.ValidationError):
        v.normalize_domain(raw)


def test_email_and_username():
    assert v.normalize_email(" Bob@Example.com ") == "Bob@example.com"
    assert v.normalize_username("@john.doe") == "john.doe"
    for bad in ["no-at-sign", "a@b"]:
        with pytest.raises(v.ValidationError):
            v.normalize_email(bad)
    with pytest.raises(v.ValidationError):
        v.normalize_username("../../etc")


@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True), ("10.0.0.1", False), ("127.0.0.1", False), ("169.254.169.254", False),
    ("192.168.1.1", False), ("::1", False), ("fd00::1", False), ("100.64.0.1", False),
])
def test_is_public_ip(ip, public):
    assert v.is_public_ip(ip) is public


def test_ssrf_guard_blocks_private(monkeypatch):
    monkeypatch.setattr(v.socket, "getaddrinfo",
                        lambda h, p: [(2, 1, 6, "", ("169.254.169.254", 0))])
    with pytest.raises(v.ValidationError, match="non-public"):
        v.assert_public_host("metadata.evil.com")


def test_ssrf_guard_allows_public(monkeypatch):
    monkeypatch.setattr(v.socket, "getaddrinfo", lambda h, p: [(2, 1, 6, "", ("93.184.216.34", 0))])
    assert v.assert_public_host("example.com") == ["93.184.216.34"]
