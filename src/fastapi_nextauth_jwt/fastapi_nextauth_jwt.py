import json
import typing
from functools import partial
from json import JSONDecodeError

import os
from typing import Set, Any, Literal, List

from starlette.requests import Request

from jose import jwe
from jose.exceptions import JWEError
from cryptography.hazmat.primitives import hashes

from fastapi_nextauth_jwt.operations import derive_key, check_expiry
from fastapi_nextauth_jwt.cookies import extract_token
from fastapi_nextauth_jwt.csrf import extract_csrf_info, validate_csrf_info
from fastapi_nextauth_jwt.exceptions import InvalidTokenError, MissingTokenError, CSRFMismatchError, \
    UnsupportedEncryptionAlgorithmException
from fastapi_nextauth_jwt.logger import get_logger

logger = get_logger()

EncAlgs = Literal["A256CBC-HS512", "A256GCM"]
_supported_encryption_algs = list(typing.get_args(EncAlgs))


class NextAuthJWT:
    def __init__(self,
                 secret: str = None,
                 cookie_name: str = None,
                 secure_cookie: bool = None,
                 csrf_cookie_name: str = None,
                 csrf_header_name: str = "X-XSRF-Token",
                 info: bytes = b"Auth.js Generated Encryption Key",
                 salt: typing.Union[bytes, None] = None,
                 auto_append_salt: bool = True,
                 hash_algorithm: Any = hashes.SHA256(),
                 encryption_algorithm: EncAlgs = "A256CBC-HS512",
                 csrf_prevention_enabled: bool = None,
                 csrf_methods: Set[str] = None,
                 check_expiry: bool = True):
        """
        Initializes a new instance of the NextAuthJWT class.

        Args:
            secret (str): The secret used for key derivation. If not set, will be obtained from NEXTAUTH_SECRET env var.

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

             check_expiry (bool, optional): Whether or not to check the token for expiry. Defaults to True

        Example:
            >>> auth = NextAuthJWT(secret=os.getenv("NEXTAUTH_SECRET"))
        """

        if secret is not None:
            self.secret = secret
        else:
            env_secret = os.getenv("NEXTAUTH_SECRET")
            if env_secret is None:
                logger.error("NEXTAUTH_SECRET environment variable is not set")
                raise ValueError("NEXTAUTH_SECRET environment variable is not set")
            self.secret = env_secret
            logger.debug("Successfully loaded NEXTAUTH_SECRET from environment")

        if secure_cookie is None:
            nextauth_url = os.getenv("NEXTAUTH_URL")
            if nextauth_url is None:
                logger.warning("NEXTAUTH_URL environment variable is not set. This may cause issues with cookie handling.")
            secure_cookie = os.getenv("NEXTAUTH_URL", "").startswith("https://")
            logger.debug(f"Secure cookie setting determined: {secure_cookie}")

        if cookie_name is None:
            self.cookie_name = "__Secure-authjs.session-token" if secure_cookie else "authjs.session-token"
        else:
            self.cookie_name = cookie_name
        logger.debug(f"Using cookie name: {self.cookie_name}")

        if csrf_cookie_name is None:
            self.csrf_cookie_name = "__Host-authjs.csrf-token" if secure_cookie else "authjs.csrf-token"
        else:
            self.csrf_cookie_name = csrf_cookie_name
        logger.debug(f"Using CSRF cookie name: {self.csrf_cookie_name}")

        if salt is None:
            salt = bytes(self.cookie_name, "ascii")

        self.csrf_header_name = csrf_header_name

        if encryption_algorithm not in _supported_encryption_algs:
            logger.error(f"Unsupported encryption algorithm: {encryption_algorithm}")
            raise UnsupportedEncryptionAlgorithmException(status_code=500, message=encryption_algorithm)

        self.encryption_algorithm = encryption_algorithm
        logger.debug(f"Using encryption algorithm: {self.encryption_algorithm}")

        key_length = 64 if self.encryption_algorithm == "A256CBC-HS512" else 32
        logger.debug(f"Using key length: {key_length}")

        self.key = derive_key(
            secret=self.secret,
            length=key_length,
            salt=salt,
            algorithm=hash_algorithm,
            context=info + b" (" + salt + b")" if auto_append_salt else info
        )
        logger.debug("Key derivation completed successfully")

        if csrf_prevention_enabled is None:
            self.csrf_prevention_enabled = False if os.environ.get("ENV") == "dev" else True
        else:
            self.csrf_prevention_enabled = csrf_prevention_enabled
        logger.info(f"CSRF prevention {'enabled' if self.csrf_prevention_enabled else 'disabled'}")

        if csrf_methods is None:
            self.csrf_methods = {'POST', 'PUT', 'PATCH', 'DELETE'}
        else:
            self.csrf_methods = csrf_methods
        logger.debug(f"CSRF protection methods: {self.csrf_methods}")

        self.check_expiry = check_expiry
        logger.debug(f"Token expiry check {'enabled' if self.check_expiry else 'disabled'}")

    def __call__(self, req: Request = None):
        logger.debug("Processing request authentication")
        encrypted_token = extract_token(req.cookies, self.cookie_name)

        if self.csrf_prevention_enabled:
            logger.debug("Checking CSRF token")
            self.check_csrf_token(req)

        try:
            decrypted_token_string = jwe.decrypt(encrypted_token, self.key)
            token = json.loads(decrypted_token_string)
            logger.debug("Successfully decrypted and parsed token")
        except (JWEError, JSONDecodeError) as e:
            logger.error(f"Token decryption/parsing failed: {str(e)}")
            raise InvalidTokenError(status_code=401, message="Invalid JWT format")

        if self.check_expiry:
            if "exp" not in token:
                logger.error("Token missing expiration claim")
                raise InvalidTokenError(status_code=401, message="Invalid JWT format, missing exp")
            try:
                check_expiry(token['exp'])
                logger.debug("Token expiration check passed")
            except Exception as e:
                logger.error(f"Token expiration check failed: {str(e)}")
                raise

        return token

    def check_csrf_token(self, req: Request):
        if req.method not in self.csrf_methods:
            logger.debug(f"CSRF check skipped for method {req.method}")
            return

        if self.csrf_cookie_name not in req.cookies:
            logger.error(f"Missing CSRF cookie: {self.csrf_cookie_name}")
            raise MissingTokenError(status_code=401, message=f"Missing CSRF token: {self.csrf_cookie_name}")
        if self.csrf_header_name not in req.headers:
            logger.error(f"Missing CSRF header: {self.csrf_header_name}")
            raise MissingTokenError(status_code=401, message=f"Missing CSRF header: {self.csrf_header_name}")

        csrf_cookie_token, csrf_cookie_hash = extract_csrf_info(req.cookies[self.csrf_cookie_name])
        logger.debug("CSRF token and hash extracted from cookie")

        try:
            # Validate if it was indeed set by the server
            # See https://github.com/nextauthjs/next-auth/blob/50fe115df6379fffe3f24408a1c8271284af660b/src/core/lib/csrf-token.ts
            # for info on how the CSRF cookie is created
            validate_csrf_info(self.secret, csrf_cookie_token, csrf_cookie_hash)
            logger.debug("CSRF token validation successful")
        except Exception as e:
            logger.error(f"CSRF token validation failed: {str(e)}")
            raise

        csrf_header_token = req.headers[self.csrf_header_name]

        if csrf_header_token != csrf_cookie_token:
            logger.error("CSRF token mismatch between header and cookie")
            raise CSRFMismatchError(status_code=401, message="CSRF Token mismatch")

        logger.debug("CSRF check completed successfully")


NextAuthJWTv4 = partial(
    NextAuthJWT,
    info=b"NextAuth.js Generated Encryption Key",
    salt=b"",
    auto_append_salt=False,
    encryption_algorithm="A256GCM",
    cookie_name="__Secure-next-auth.session-token"\
        if os.getenv("NEXTAUTH_URL", "").startswith("https://")\
        else "next-auth.session-token",
    csrf_cookie_name="__Host-next-auth.csrf-token"\
        if os.getenv("NEXTAUTH_URL", "").startswith("https://")\
        else "next-auth.csrf-token"
)
