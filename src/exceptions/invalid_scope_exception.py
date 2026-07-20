class InvalidScopeError(Exception):
    """Exception raised when a requested scope is invalid or not allowed for the client."""

    def __init__(self, message: str = "Requested scope is not allowed for this client."):
        self.message = message
        super().__init__(self.message)
