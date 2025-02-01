class NextAuthJWTException(Exception):
    """Base exception class for all NextAuthJWT exceptions"""
    def __init__(self, *args: object):
        super().__init__(args)
        self.message = None
        self.status_code = None

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(status_code={self.status_code}, message='{self.message}')"


class MissingTokenError(NextAuthJWTException):
    """Raised when a required token is not found in the request"""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = f"Authentication failed: {message}"


class InvalidTokenError(NextAuthJWTException):
    """Raised when a token is found but is invalid (wrong format, can't be decrypted, etc)"""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = f"Invalid token: {message}"


class CSRFMismatchError(NextAuthJWTException):
    """Raised when CSRF token validation fails"""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = f"CSRF validation failed: {message}"


class TokenExpiredException(NextAuthJWTException):
    """Raised when a token has expired"""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = f"Token expired: {message}"


class UnsupportedEncryptionAlgorithmException(NextAuthJWTException):
    """Raised when an unsupported encryption algorithm is specified"""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = f"Unsupported encryption algorithm: {message}. Supported algorithms: ['A256CBC-HS512', 'A256GCM']"
