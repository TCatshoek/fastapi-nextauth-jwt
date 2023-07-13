from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_key(secret: str, length: int, salt: bytes, algorithm, context: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=algorithm,
        length=length,
        salt=salt,
        info=context
    )
    return hkdf.derive(bytes(secret, "ascii"))
