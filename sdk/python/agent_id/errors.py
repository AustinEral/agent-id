"""Error types for agent-id.

Mirrors the Rust error hierarchy for consistency across implementations.
"""


class AIPError(Exception):
    """Base exception for agent-id operations."""


class InvalidDIDError(AIPError):
    """DID format is invalid."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Invalid DID format: {message}")


class InvalidSignatureError(AIPError):
    """Signature verification failed."""

    def __init__(self, message: str = "Signature verification failed") -> None:
        super().__init__(message)


class KeyError(AIPError):
    """Key operation failed."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Key error: {message}")


class SerializationError(AIPError):
    """Serialization or canonicalization failed."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Serialization error: {message}")


class ValidationError(AIPError):
    """Validation failed."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Validation error: {message}")
