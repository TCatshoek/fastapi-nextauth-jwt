from fastapi_nextauth_jwt import operations
from cryptography.hazmat.primitives import hashes


def test_derive_key():
    secret = "aUblGYhT507qxin/mQ+UlvyUjuR5dI9I8yKm5ZeVWDQ="

    derived_key = operations.derive_key(
        secret,
        32,
        b"",
        hashes.SHA256(),
        b"NextAuth.js Generated Encryption Key"
    )

    expected_key = b'\x80\x00\xd1\x07*=\xa0}\xaa\x18\xeb\xee\x9c\x95\xbcXzr\xc3\x17\x98\x9f\xbc\xd9\xbfU\xbay0\xcfh\x01'

    assert expected_key == derived_key
