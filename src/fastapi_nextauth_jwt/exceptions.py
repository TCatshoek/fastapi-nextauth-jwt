from fastapi import HTTPException

class NextAuthJWTException(HTTPException):
    def __init__(self, *args: object):
        super().__init__(args)
        self.detail = None
        self.status_code = None


class MissingTokenError(NextAuthJWTException):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.detail = message


class InvalidTokenError(NextAuthJWTException):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.detail = message


class CSRFMismatchError(NextAuthJWTException):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.detail = message


class TokenExpiredException(NextAuthJWTException):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.detail = message


class UnsupportedEncryptionAlgorithmException(NextAuthJWTException):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.detail = message
