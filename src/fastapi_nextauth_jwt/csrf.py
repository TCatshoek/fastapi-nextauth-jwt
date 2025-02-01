import urllib.parse
from cryptography.hazmat.primitives import hashes
from fastapi_nextauth_jwt.exceptions import InvalidTokenError
from fastapi_nextauth_jwt.logger import get_logger

logger = get_logger()


def extract_csrf_info(csrf_string: str) -> [str, str]:
    """
    Extracts CSRF token and hash from the cookie value
    :param csrf_string: The raw CSRF cookie value
    :return: Tuple of (token, hash)
    """
    logger.debug("Starting CSRF token extraction")
    csrf_token_unquoted = urllib.parse.unquote(csrf_string)
    logger.debug("URL-decoded CSRF cookie value")

    if "|" not in csrf_token_unquoted:
        logger.error("CSRF token format error: Missing separator '|' in token")
        logger.debug(f"Invalid token content (first 50 chars): {csrf_token_unquoted[:50]}...")
        raise InvalidTokenError(status_code=401, message="Unrecognized CSRF token format: missing separator")

    csrf_cookie_token, csrf_cookie_hash = csrf_token_unquoted.split("|")
    logger.info("CSRF token and hash successfully extracted")
    logger.debug(f"Token length: {len(csrf_cookie_token)}, Hash length: {len(csrf_cookie_hash)}")

    return csrf_cookie_token, csrf_cookie_hash


def validate_csrf_info(secret: str, csrf_token: str, expected_hash: str):
    """
    Validates the CSRF token against its hash
    :param secret: The secret used for hash validation
    :param csrf_token: The CSRF token to validate
    :param expected_hash: The expected hash value
    """
    logger.debug("Starting CSRF token validation")
    
    try:
        csrf_token_bytes = bytes(csrf_token, "ascii")
        secret_bytes = bytes(secret, "ascii")
    except UnicodeEncodeError as e:
        logger.error("Failed to encode CSRF token or secret as ASCII")
        logger.debug(f"Encoding error details: {str(e)}")
        raise InvalidTokenError(status_code=401, message="Invalid CSRF token encoding")

    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(csrf_token_bytes)
    hasher.update(secret_bytes)
    actual_hash = hasher.finalize().hex()

    if expected_hash != actual_hash:
        logger.error("CSRF hash validation failed")
        logger.debug(f"Expected hash length: {len(expected_hash)}, Actual hash length: {len(actual_hash)}")
        raise InvalidTokenError(status_code=401, message="CSRF hash mismatch")

    logger.info("CSRF token successfully validated")
