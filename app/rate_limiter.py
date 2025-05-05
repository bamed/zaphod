class RateLimiter:
    def __init__(self):
        self.requests = {}

    async def check_rate_limit(self, client_id: str, max_requests: int = 10, window_seconds: int = 60) -> bool:
        import time
        current_time = time.time()
        
        # Initialize or clean old requests for this client
        if client_id not in self.requests:
            self.requests[client_id] = []
        else:
            # Remove requests older than the window
            self.requests[client_id] = [
                req_time for req_time in self.requests[client_id]
                if current_time - req_time < window_seconds
            ]
        
        # Check if current requests are within limit
        if len(self.requests[client_id]) >= max_requests:
            return False
        
        # Add current request
        self.requests[client_id].append(current_time)
        return True