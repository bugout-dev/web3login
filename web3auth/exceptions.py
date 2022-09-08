class MoonstreamVerificationError(Exception):
    """
    Raised when invalid signer or schema is provided.
    """


class MoonstreamAuthorizationExpired(Exception):
    """
    Raised when signature is expired by time.
    """
