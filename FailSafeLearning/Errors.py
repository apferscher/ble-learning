class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class ConnectionError(Error):
    """
    Exception raised if connection to peripheral failed
    """

    def __init__(self):
        self.message = "Failed to detect advertisements of peripheral or connection failed"


class NonDeterministicError(Error):
    """
    Exception raised if non-deterministic behavior in query is detected
    """

    def __init__(self):
        self.message = "Non-determinism in query execution detected."

class RepeatedNonDeterministicError(Error):
    """
    Exception raised if non-deterministic behavior in query is detected
    """
    def __init__(self):
        self.message = "Non-determinism in query execution detected."

