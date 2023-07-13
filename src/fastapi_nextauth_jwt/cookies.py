from typing import Dict
from fastapi_nextauth_jwt.exceptions import MissingTokenError


def extract_token(cookies: Dict[str, str], cookie_name: str):
    """
    Extracts a potentially chunked token from the cookies of a request.
    It may be in a single cookie, or chunked (with suffixes 0...n)
    :param req: The request to extract the token from
    :return: The encrypted nextauth session token
    """
    encrypted_token = ""

    # Do we have a session cookie with the expected name?
    if cookie_name in cookies:
        encrypted_token = cookies[cookie_name]

    # Or maybe a chunked session cookie?
    elif f"{cookie_name}.0" in cookies:
        counter = 0
        while f"{cookie_name}.{counter}" in cookies:
            encrypted_token += cookies[f"{cookie_name}.{counter}"]
            counter += 1

    # Or no cookie at all
    else:
        raise MissingTokenError(status_code=401, message=f"Missing cookie: {cookie_name}")

    return encrypted_token
