class DomainError(RuntimeError):
    """Expected application failure that can be safely returned to an API client."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
