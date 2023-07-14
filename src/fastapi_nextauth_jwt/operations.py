from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import time

from fastapi_nextauth_jwt.exceptions import TokenExpiredException


def derive_key(secret: str, length: int, salt: bytes, algorithm, context: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=algorithm,
        length=length,
        salt=salt,
        info=context
    )
    return hkdf.derive(bytes(secret, "ascii"))


def check_expiry(exp: int, deadline: int = None):
    if deadline is None:
        deadline = time.time()
    if exp > deadline:
        raise TokenExpiredException(403, "Token Expired")
