import pytest

from fastapi_nextauth_jwt import NextAuthJWT


def test_obtain_secret_from_argument():
    secret = "foo"
    JWT = NextAuthJWT(secret=secret)
    assert JWT.secret == secret


def test_obtain_secret_from_env(monkeypatch):
    secret = "foo"
    monkeypatch.setenv("AUTH_SECRET", secret)
    JWT = NextAuthJWT()
    assert JWT.secret == secret


def test_obtain_secret_precedence(monkeypatch):
    secret1 = "foo"
    monkeypatch.setenv("AUTH_SECRET", secret1)

    secret2 = "bar"

    JWT = NextAuthJWT(secret=secret2)
    assert JWT.secret == secret2


def test_obtain_secret_not_set():
    with pytest.raises(ValueError) as exc_info:
        NextAuthJWT()
        assert exc_info.value.message == "Secret not set"


@pytest.mark.filterwarnings("error")
def test_secret_auth_secret_no_url(monkeypatch):
    monkeypatch.setenv("AUTH_SECRET", "foo")
    with pytest.warns(RuntimeWarning, match="AUTH_URL not set"):
        NextAuthJWT()

def test_secret_nextauth_secret_deprecation_warning(monkeypatch):
    monkeypatch.setenv("NEXTAUTH_SECRET", "foo")
    with pytest.deprecated_call():
        NextAuthJWT()

def test_secret_nextauth_url_deprecation_warning(monkeypatch):
    monkeypatch.setenv("AUTH_SECRET", "foo")
    monkeypatch.setenv("NEXTAUTH_URL", "bar")
    with pytest.deprecated_call():
        NextAuthJWT()