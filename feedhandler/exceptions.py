class BaseError(Exception):
    """Base class for exceptions in this module."""

    def __init__(self, message, recovery_suggestion):
        self.message = message
        self.recovery_suggestion = recovery_suggestion
        super().__init__(f'{message} \n Recovery Suggestion: {recovery_suggestion}')


class ConfigurationError(BaseError): ...


class AuthenticationError(BaseError): ...
