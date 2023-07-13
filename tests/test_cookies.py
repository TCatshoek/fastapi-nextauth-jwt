import pytest
from fastapi_nextauth_jwt.cookies import extract_token
from fastapi_nextauth_jwt.exceptions import MissingTokenError


def test_extract_cookie_single():
    cookies = {
        "next-auth.session-token": "token123"
    }
    cookie_name = "next-auth.session-token"

    token = extract_token(cookies, cookie_name)

    assert token == "token123"


def test_extract_cookie_multi():
    cookies = {
        "next-auth.session-token.0": "token",
        "next-auth.session-token.1": "1",
        "next-auth.session-token.2": "2",
        "next-auth.session-token.3": "3",
    }
    cookie_name = "next-auth.session-token"

    token = extract_token(cookies, cookie_name)

    assert token == "token123"

def test_extract_cookie_missing():
    cookies = {
        "no-cookie": "for-you"
    }
    cookie_name = "next-auth.session-token"

    with pytest.raises(MissingTokenError) as exc_info:
        extract_token(cookies, cookie_name)
        assert exc_info.value.message == f"Missing cookie: {cookie_name}"
