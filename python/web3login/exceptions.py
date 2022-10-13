class Web3AuthorizationExpired(Exception):
    """
    Raised when signature is expired by time.
    """


class Web3AuthorizationWrongApplication(Exception):
    """
    Raised when wrong application provided.
    """


class Web3VerificationError(Exception):
    """
    Raised when invalid signer or schema is provided.
    """
