class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class ConnectionError(Error):
    """
    Exception raised if connection to peripheral failed
    """

    def __init__(self):
        self.message = "Failed to detect advertisements of peripheral or connection failed"