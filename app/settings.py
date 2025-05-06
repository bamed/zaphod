class Settings:
    def __init__(self):
        # CORS settings
        self.ALLOWED_ORIGINS = ["*"]  # For development. In production, specify exact origins
        self.ALLOWED_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        self.ALLOWED_HEADERS = [
            "Content-Type",
            "Authorization",
            "X-Request-ID",
            "X-API-Key"
        ]