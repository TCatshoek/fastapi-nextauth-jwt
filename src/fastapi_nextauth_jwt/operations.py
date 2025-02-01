from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import time

from fastapi_nextauth_jwt.exceptions import TokenExpiredException
from fastapi_nextauth_jwt.logger import get_logger

logger = get_logger()


def derive_key(secret: str, length: int, salt: bytes, algorithm, context: bytes) -> bytes:
    logger.debug(f"Deriving key with length {length}")
    hkdf = HKDF(
        algorithm=algorithm,
        length=length,
        salt=salt,
        info=context
    )
    key = hkdf.derive(bytes(secret, "ascii"))
    logger.debug("Key derivation completed")
    return key


def check_expiry(exp: int, cur_time: int = None):
    if cur_time is None:
        cur_time = time.time()
    logger.debug(f"Checking token expiry. Token expires at: {exp}, current time: {cur_time}")

    if exp < cur_time:
        logger.warning(f"Token expired. Expired {cur_time - exp} seconds ago")
        raise TokenExpiredException(403, "Token Expired")

    logger.debug(f"Token is valid. {exp - cur_time} seconds remaining")
