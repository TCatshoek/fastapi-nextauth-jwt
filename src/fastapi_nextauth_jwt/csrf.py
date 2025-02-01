import urllib.parse
from cryptography.hazmat.primitives import hashes
from fastapi_nextauth_jwt.exceptions import InvalidTokenError
from fastapi_nextauth_jwt.logger import get_logger

logger = get_logger()


def extract_csrf_info(csrf_string: str) -> [str, str]:
    logger.debug("Extracting CSRF token and hash from cookie")
    csrf_token_unquoted = urllib.parse.unquote(csrf_string)
    if "|" not in csrf_token_unquoted:
        logger.error("Invalid CSRF token format: missing separator")
        raise InvalidTokenError(status_code=401, message="Unrecognized CSRF token format")
    csrf_cookie_token, csrf_cookie_hash = csrf_token_unquoted.split("|")
    logger.debug("Successfully extracted CSRF token and hash")

    return csrf_cookie_token, csrf_cookie_hash


def validate_csrf_info(secret: str, csrf_token: str, expected_hash: str):
    logger.debug("Validating CSRF token hash")
    csrf_token_bytes = bytes(csrf_token, "ascii")
    secret_bytes = bytes(secret, "ascii")

    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(csrf_token_bytes)
    hasher.update(secret_bytes)
    actual_hash = hasher.finalize().hex()

    if expected_hash != actual_hash:
        logger.error("CSRF hash validation failed")
        raise InvalidTokenError(status_code=401, message="CSRF hash mismatch")

    logger.debug("CSRF hash validation successful")
