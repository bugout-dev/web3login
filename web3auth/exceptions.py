class MoonstreamAuthorizationVerificationError(Exception):
    """
    Raised when invalid signer is provided.
    """


class MoonstreamAuthorizationExpired(Exception):
    """
    Raised when signature is expired by time.
    """
