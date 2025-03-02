from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import time

from fastapi_nextauth_jwt.exceptions import TokenExpiredException
from fastapi_nextauth_jwt.logger import get_logger

logger = get_logger()


def derive_key(secret: str, length: int, salt: bytes, algorithm, context: bytes) -> bytes:
    """
    Derives a key using HKDF
    :param secret: The secret to derive from
    :param length: The desired key length
    :param salt: The salt for key derivation
    :param algorithm: The hash algorithm to use
    :param context: The context info for key derivation
    :return: The derived key
    """
    logger.info(f"Starting key derivation with {algorithm.__class__.__name__}")
    logger.debug(f"Key derivation parameters - Length: {length}, Salt length: {len(salt)}, Context length: {len(context)}")

    try:
        hkdf = HKDF(
            algorithm=algorithm,
            length=length,
            salt=salt,
            info=context
        )
        key = hkdf.derive(bytes(secret, "ascii"))
        logger.info("Key derivation completed successfully")
        logger.debug(f"Generated key length: {len(key)}")
        return key
    except Exception as e:
        logger.error(f"Key derivation failed: {str(e)}")
        raise


def check_expiry(exp: int, cur_time: int = None):
    """
    Checks if a token has expired
    :param exp: The expiration timestamp
    :param cur_time: The current time (defaults to now)
    """
    if cur_time is None:
        cur_time = time.time()
    
    logger.debug(f"Checking token expiry - Expires at: {exp} ({time.ctime(exp)})")
    logger.debug(f"Current time: {cur_time} ({time.ctime(cur_time)})")
    
    time_remaining = exp - cur_time
    if time_remaining < 0:
        logger.warning(f"Token expired {abs(time_remaining):.1f} seconds ago")
        raise TokenExpiredException(403, f"Token expired {abs(time_remaining):.1f} seconds ago")
    
    if time_remaining < 300:  # 5 minutes
        logger.warning(f"Token will expire soon. {time_remaining:.1f} seconds remaining")
    else:
        logger.info(f"Token is valid. {time_remaining:.1f} seconds remaining")
