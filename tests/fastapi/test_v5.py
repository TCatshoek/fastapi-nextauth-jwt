import pytest
from fastapi.testclient import TestClient

from fastapi_nextauth_jwt.exceptions import MissingTokenError, InvalidTokenError, TokenExpiredException
from v5 import app

client = TestClient(app)

cookies = {
    "authjs.session-token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoidDBOWWk4TExkYWVjNlctdlcwN3BRekdUR2dwSmgtaTBLRXlKcHFGcjRqSEkySkRtdDJNTnpqQ0Uwcjc0bDBFT240NmZOMUdMcEpsa09QY0NYZ2JNR3cifQ..VKK_QKVTc0-UxFoOD6ZxZg.pHmOvrG1kCq4IApuJD6lCplq5TBjhxGf_rd43h43kXddPGDwjSEUeRYbcSO-sSfXl8DnXw9Q9e1zJPMlxl1maZRaBV2kAla8kBebL19DPgEDHNVTmW_ujgidlSHk3bbNhOO1U1fXNdvUbQqHOAScjxv60CPJpVd-9CaL6Zw_Teg.S2KOuWV72JtSZca8VhOhQvSFofpKJKVb_jjf_Ld-zWA",
}

cookies_w_csrf = {
    "authjs.session-token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoidDBOWWk4TExkYWVjNlctdlcwN3BRekdUR2dwSmgtaTBLRXlKcHFGcjRqSEkySkRtdDJNTnpqQ0Uwcjc0bDBFT240NmZOMUdMcEpsa09QY0NYZ2JNR3cifQ..VKK_QKVTc0-UxFoOD6ZxZg.pHmOvrG1kCq4IApuJD6lCplq5TBjhxGf_rd43h43kXddPGDwjSEUeRYbcSO-sSfXl8DnXw9Q9e1zJPMlxl1maZRaBV2kAla8kBebL19DPgEDHNVTmW_ujgidlSHk3bbNhOO1U1fXNdvUbQqHOAScjxv60CPJpVd-9CaL6Zw_Teg.S2KOuWV72JtSZca8VhOhQvSFofpKJKVb_jjf_Ld-zWA",
    "authjs.csrf-token": "53e18023db04541f0ffbe3c5f7683d2388806401eb46020f74889fa723a2623b%7C0a44296fabc59e85e37195731d6f132c78bc7884d33594ded089706f215c3647"
}

cookies_invalid = {
    "authjs.session-token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoidDBOWWk4TExkYWVjNlctdlcwN3BRekdUR2dwSmgtaTBLRXlKcHFGcjRqSEkySkRtdDJNTnpqQ0Uwcjc0bDBFT240NmZOMUdMcEpsa09QY0NYZ2JNR3cifQ..VKK_QKVTc0-UxFoOD6ZxZg.pHmOvrG1kCq4IApuJD6lCplq5TBjhxGf_rd43h43kXddPGDwjSEUeRYbcSO-sSfXl8DnXw9Q9e1zJPMlxl1maZRaBV2kAla8kBebL19DPgEDHNVTmW_ujgidlSHk3bbNhOO1U1fXNdvUbQqHOAScjxv60CPJpVd-9CaL6Zw_Teg.S2KOuWV72JtSZca8VhOhQvSFofpFJKVb_jjf_Ld-zWA",
}

expected_jwt = {
  'name': 'asdf',
  'email': 'test@test.nl',
  'sub': '1',
  'iat': 1714146974,
  'exp': 1716738974,
  'jti': '9e8f6368-9236-458d-ba23-2bb95fdbfdbd'
}


@pytest.fixture(autouse=True)
def patch_current_time(monkeypatch):
    # Monkeypatch the current time so tests don't depend on it
    monkeypatch.setattr("fastapi_nextauth_jwt.operations.check_expiry.__defaults__", (1714146975,))


def test_no_csrf():
    client.cookies = cookies
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == expected_jwt


def test_csrf():
    client.cookies = cookies_w_csrf
    response = client.post("/csrf",
                           headers={
                               "X-XSRF-Token": "53e18023db04541f0ffbe3c5f7683d2388806401eb46020f74889fa723a2623b"
                           })

    assert response.status_code == 200
    assert response.json() == expected_jwt


def test_csrf_missing_token():
    with pytest.raises(MissingTokenError) as exc_info:
        client.cookies = cookies
        client.post("/csrf")
        assert exc_info.value.message == "Missing CSRF token: next-auth.csrf-token"


def test_csrf_missing_header():
    with pytest.raises(MissingTokenError) as exc_info:
        client.cookies = cookies_w_csrf
        client.post("/csrf")
        assert exc_info.value.message == "Missing CSRF header: X-XSRF-Token"


def test_csrf_no_csrf_method():
    client.cookies = cookies
    response = client.get("/csrf")

    assert response.status_code == 200
    assert response.json() == expected_jwt


def test_invalid_jwt():
    with pytest.raises(InvalidTokenError) as exc_info:
        client.cookies = cookies_invalid
        client.get("/")
        assert exc_info.value.message == "Invalid JWT format"


def test_expiry(monkeypatch):
    # In this case, we patch the current time to be after the token expiry time
    monkeypatch.setattr("fastapi_nextauth_jwt.operations.check_expiry.__defaults__", (1716738975,))

    with pytest.raises(TokenExpiredException) as exc_info:
        client.cookies = cookies
        client.get("/")
        assert exc_info.value.message == "Token Expired"
