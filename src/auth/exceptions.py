"""
Authentication-specific exceptions.
"""
from fastapi import HTTPException, status

class AuthException(HTTPException):
    """Base class for authentication exceptions."""
    def __init__(self, status_code: int, detail: str):
        super().__init__(status_code=status_code, detail=detail)

class InvalidCredentialsException(AuthException):
    """Exception raised when credentials are invalid."""
    def __init__(self, detail: str = "Invalid credentials"):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

class EmailAlreadyExistsException(AuthException):
    """Exception raised when email already exists."""
    def __init__(self, detail: str = "Email already registered"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

class VerificationCodeInvalidException(AuthException):
    """Exception raised when verification code is invalid."""
    def __init__(self, detail: str = "Invalid verification code"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

class AccountStatusException(AuthException):
    """Exception raised when account status prevents an operation."""
    def __init__(self, status: str, detail: str = None):
        message = detail or f"Account status '{status}' prevents this operation"
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=message)

class TokenExpiredException(AuthException):
    """Exception raised when token has expired."""
    def __init__(self, detail: str = "Token has expired"):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

class InvalidTokenException(AuthException):
    """Exception raised when token is invalid."""
    def __init__(self, detail: str = "Invalid token"):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

class PasswordResetException(AuthException):
    """Exception raised during password reset."""
    def __init__(self, detail: str = "Password reset failed"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class AccountLockedException(AuthException):
    """Exception raised when account is locked."""
    def __init__(self, detail: str = "Account is locked"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

class PermissionDeniedException(AuthException):
    """Exception raised when user doesn't have required permissions."""
    def __init__(self, detail: str = "Permission denied"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

class RoleDeniedException(AuthException):
    """Exception raised when user doesn't have required role."""
    def __init__(self, required_roles: list, user_role: str):
        detail = f"Access denied. Required roles: {required_roles}. Your role: {user_role}"
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)
