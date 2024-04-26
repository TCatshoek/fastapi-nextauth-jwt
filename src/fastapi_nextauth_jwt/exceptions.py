class NextAuthJWTException(Exception):
    def __init__(self, *args: object):
        super().__init__(args)
        self.message = None
        self.status_code = None


class MissingTokenError(NextAuthJWTException):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class InvalidTokenError(NextAuthJWTException):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class CSRFMismatchError(NextAuthJWTException):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class TokenExpiredException(NextAuthJWTException):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class UnsupportedEncryptionAlgorithmException(NextAuthJWTException):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
