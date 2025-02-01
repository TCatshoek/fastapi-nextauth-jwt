from typing import Dict
from fastapi_nextauth_jwt.exceptions import MissingTokenError
from fastapi_nextauth_jwt.logger import get_logger

logger = get_logger()


def extract_token(cookies: Dict[str, str], cookie_name: str):
    """
    Extracts a potentially chunked token from the cookies of a request.
    It may be in a single cookie, or chunked (with suffixes 0...n)
    :param cookies: The cookies dictionary from the request
    :param cookie_name: The name of the cookie to extract
    :return: The encrypted nextauth session token
    """
    encrypted_token = ""
    logger.debug(f"Starting token extraction from cookies. Looking for: {cookie_name}")

    # Do we have a session cookie with the expected name?
    if cookie_name in cookies:
        encrypted_token = cookies[cookie_name]
        logger.info(f"Found token in single cookie: {cookie_name}")

    # Or maybe a chunked session cookie?
    elif f"{cookie_name}.0" in cookies:
        logger.info(f"Found chunked cookie starting with: {cookie_name}.0")
        counter = 0
        while f"{cookie_name}.{counter}" in cookies:
            chunk_name = f"{cookie_name}.{counter}"
            logger.debug(f"Processing chunk: {chunk_name}")
            encrypted_token += cookies[chunk_name]
            counter += 1
        logger.info(f"Successfully reconstructed token from {counter} chunks")

    # Or no cookie at all
    else:
        available_cookies = list(cookies.keys())
        logger.error(f"Required cookie not found: {cookie_name}. Available cookies: {available_cookies}")
        raise MissingTokenError(status_code=401, message=f"Missing cookie: {cookie_name}")

    logger.debug(f"Extracted token of length: {len(encrypted_token)}")
    return encrypted_token
