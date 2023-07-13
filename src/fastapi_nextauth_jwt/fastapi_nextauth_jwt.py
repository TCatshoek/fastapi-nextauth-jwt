import json
from json import JSONDecodeError

import os
from typing import Set, Any

from starlette.requests import Request

from jose import jwe
from jose.exceptions import JWEError
from cryptography.hazmat.primitives import hashes

from fastapi_nextauth_jwt.operations import derive_key
from fastapi_nextauth_jwt.cookies import extract_token
from fastapi_nextauth_jwt.csrf import extract_csrf_info, validate_csrf_info
from fastapi_nextauth_jwt.exceptions import InvalidTokenError, MissingTokenError, CSRFMismatchError


class NextAuthJWT:
    def __init__(self,
                 secret: str,
                 cookie_name: str = None,
                 secure_cookie: bool = None,
                 csrf_cookie_name: str = None,
                 csrf_header_name: str = "X-XSRF-Token",
                 info: bytes = b"NextAuth.js Generated Encryption Key",
                 salt: bytes = b"",
                 hash_algorithm: Any = hashes.SHA256(),
                 csrf_prevention_enabled: bool = None,
                 csrf_methods: Set[str] = None):
        """
        Initializes a new instance of the NextAuthJWT class.

        Args:
            secret (str): The secret used for key derivation.

            cookie_name (str, optional): The name of the session cookie. Defaults to "__Secure-next-auth.session-token"
             if using secure cookies, otherwise "next-auth.session-token"

            secure_cookie (bool, optional): Indicates if the session cookie is a secure cookie. Defaults to True
             if NEXTAUTH_URL starts with https://. else False.

            csrf_cookie_name (str, optional): The name of the CSRF token cookie. Defaults to
             "__Host-next-auth.csrf-token" if using secure cookies, else "next-auth.csrf-token".

            csrf_header_name (str, optional): The name of the CSRF token header. Defaults to "X-XSRF-Token".
            info (bytes, optional): The context for key derivation. Defaults to b"NextAuth.js Generated Encryption Key".
            salt (bytes, optional): The salt used for key derivation. Defaults to b"".
            hash_algorithm (Any, optional): The hash algorithm used for key derivation. Defaults to hashes.SHA256().

            csrf_prevention_enabled (bool, optional): Indicates if CSRF prevention is enabled.
             Defaults to True if ENV == "dev, else False.

            csrf_methods (Set[str], optional): The HTTP methods that require CSRF protection.
             Defaults to {'POST', 'PUT', 'PATCH', 'DELETE'}.

        Example:
            >>> auth = NextAuthJWT(secret=os.getenv("NEXTAUTH_SECRET"))
        """

        self.secret = secret

        if secure_cookie is None:
            secure_cookie = os.getenv("NEXTAUTH_URL", "").startswith("https://")

        if cookie_name is None:
            self.cookie_name = "__Secure-next-auth.session-token" if secure_cookie else "next-auth.session-token"
        else:
            self.cookie_name = cookie_name

        if csrf_cookie_name is None:
            self.csrf_cookie_name = "__Host-next-auth.csrf-token" if secure_cookie else "next-auth.csrf-token"
        else:
            self.csrf_cookie_name = csrf_cookie_name

        self.csrf_header_name = csrf_header_name

        self.key = derive_key(
            secret=secret,
            length=32,
            salt=salt,
            algorithm=hash_algorithm,
            context=info
        )

        if csrf_prevention_enabled is None:
            self.csrf_prevention_enabled = False if os.environ.get("ENV") == "dev" else True
        else:
            self.csrf_prevention_enabled = csrf_prevention_enabled

        if csrf_methods is None:
            self.csrf_methods = {'POST', 'PUT', 'PATCH', 'DELETE'}
        else:
            self.csrf_methods = csrf_methods

    def __call__(self, req: Request = None):
        encrypted_token = extract_token(req.cookies, self.cookie_name)

        if self.csrf_prevention_enabled:
            self.check_csrf_token(req)

        try:
            decrypted_token_string = jwe.decrypt(encrypted_token, self.key)
            return json.loads(decrypted_token_string)
        except (JWEError, JSONDecodeError) as e:
            print(e)
            raise InvalidTokenError(status_code=401, message="Invalid JWT format")

    def check_csrf_token(self, req: Request):
        if req.method not in self.csrf_methods:
            return

        if self.csrf_cookie_name not in req.cookies:
            raise MissingTokenError(status_code=401, message=f"Missing CSRF token: {self.csrf_cookie_name}")
        if self.csrf_header_name not in req.headers:
            raise MissingTokenError(status_code=401, message=f"Missing CSRF header: {self.csrf_header_name}")

        csrf_cookie_token, csrf_cookie_hash = extract_csrf_info(req.cookies[self.csrf_cookie_name])

        # Validate if it was indeed set by the server
        # See https://github.com/nextauthjs/next-auth/blob/50fe115df6379fffe3f24408a1c8271284af660b/src/core/lib/csrf-token.ts
        # for info on how the CSRF cookie is created
        validate_csrf_info(self.secret, csrf_cookie_token, csrf_cookie_hash)

        # Check if the CSRF token in the headers matches the one in the cookie
        csrf_header_token = req.headers[self.csrf_header_name]

        if csrf_header_token != csrf_cookie_token:
            raise CSRFMismatchError(status_code=401, message="CSRF Token mismatch")