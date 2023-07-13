import pytest

from fastapi_nextauth_jwt.csrf import extract_csrf_info, validate_csrf_info
from fastapi_nextauth_jwt.exceptions import InvalidTokenError


def test_extract_csrf():
    csrf_string = "89f032cc1b6e570b4c5631e1ecae0541e2c6edd42ee47ab143cc55294b4486f3%7Ca7f3c2b6ea7188ced2697febf582f0bdf5b94459c39087b074d939c66d5357f9"
    csrf_cookie_token, csrf_cookie_hash = extract_csrf_info(csrf_string)

    assert csrf_cookie_token == "89f032cc1b6e570b4c5631e1ecae0541e2c6edd42ee47ab143cc55294b4486f3"
    assert csrf_cookie_hash == "a7f3c2b6ea7188ced2697febf582f0bdf5b94459c39087b074d939c66d5357f9"


def test_extract_invalid_csrf():
    csrf_string = "89f032cc1b6e570b4c5631e1ecae0541e2c6edd42ee47ab143cc55294b6ea7188ced2697febf582f0bdf5b94459c39087b074d939c66d5357f9"

    with pytest.raises(InvalidTokenError) as exc_info:
        extract_csrf_info(csrf_string)
        assert exc_info.value.message == "Unrecognized CSRF token format"


def test_validate_csrf():
    csrf_token = "89f032cc1b6e570b4c5631e1ecae0541e2c6edd42ee47ab143cc55294b4486f3"
    csrf_hash = "a7f3c2b6ea7188ced2697febf582f0bdf5b94459c39087b074d939c66d5357f9"
    secret = "6dDnFiDpUlKlbJciCusuFKNYmcf4WpIigldzX/Wb/FA="
    validate_csrf_info(secret, csrf_token, csrf_hash)


def test_validate_csrf_incorrect():
    csrf_token = "89f032cc1b6e570b4c5631e1ecae0541e2c6edd42ee47ab143cc55294b4486f3"
    csrf_hash = "a7f3c2b6ea7188ced2697febf582f0bdf5b94459c39087b074d939c66d5357f9"
    secret = "teehee"
    with pytest.raises(InvalidTokenError) as exc_info:
        validate_csrf_info(secret, csrf_token, csrf_hash)
        assert exc_info.value.message == "CSRF hash mismatch"
