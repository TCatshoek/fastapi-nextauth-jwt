import pytest

from fastapi_nextauth_jwt import NextAuthJWT


def test_obtain_secret_from_argument():
    secret = "foo"
    JWT = NextAuthJWT(secret=secret)
    assert JWT.secret == secret


def test_obtain_secret_from_env(monkeypatch):
    secret = "foo"
    monkeypatch.setenv("NEXTAUTH_SECRET", secret)
    JWT = NextAuthJWT()
    assert JWT.secret == secret


def test_obtain_secret_precedence(monkeypatch):
    secret1 = "foo"
    monkeypatch.setenv("NEXTAUTH_SECRET", secret1)

    secret2 = "bar"

    JWT = NextAuthJWT(secret=secret2)
    assert JWT.secret == secret2


def test_obtain_secret_not_set():
    with pytest.raises(ValueError) as exc_info:
        NextAuthJWT()
        assert exc_info.value.message == "Secret not set"
