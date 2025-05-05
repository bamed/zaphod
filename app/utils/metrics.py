from collections import Counter
from threading import Lock
from typing import Dict

from prometheus_client import Counter, Histogram, Gauge

# Request metrics
request_count = Counter(
    'api_requests_total',
    'Total API requests',
    ['endpoint', 'provider', 'status']
)

request_latency = Histogram(
    'api_request_latency_seconds',
    'Request latency',
    ['endpoint', 'provider']
)

# Provider metrics
provider_health = Gauge(
    'provider_health',
    'Provider health status',
    ['provider']
)

model_usage = Counter(
    'model_usage_total',
    'Total model usage',
    ['provider', 'model']
)

token_usage = Counter(
    'token_usage_total',
    'Total tokens used',
    ['provider', 'model', 'type']
)

class MetricsCollector:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MetricsCollector, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        self._lock = Lock()
        self._request_count = Counter()
        self._durations: Dict[str, float] = {}
        
    @staticmethod
    def record_request(endpoint: str, provider: str, status: str, duration: float):
        request_count.labels(endpoint=endpoint, provider=provider, status=status).inc()
        request_latency.labels(endpoint=endpoint, provider=provider).observe(duration)

    @staticmethod
    def update_provider_health(provider: str, is_healthy: bool):
        provider_health.labels(provider=provider).set(1 if is_healthy else 0)

    @staticmethod
    def record_model_usage(provider: str, model: str, input_tokens: int, output_tokens: int):
        model_usage.labels(provider=provider, model=model).inc()
        token_usage.labels(provider=provider, model=model, type="input").inc(input_tokens)
        token_usage.labels(provider=provider, model=model, type="output").inc(output_tokens)