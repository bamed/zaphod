# model_registry.py
import json
import os
import time
from abc import ABC, abstractmethod
from typing import Dict, Optional, Any, List, Union
from functools import wraps
import logging
import boto3
from jsonschema import validate
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'utils'))
from .utils.constants import VERSION, DEFAULT_CONFIG, CONFIG_SCHEMA, ProviderType
from .utils.exceptions import ModelProviderError, ConfigurationError, ValidationError
from .utils.metrics import MetricsCollector
from .utils.logging_config import setup_logging
import asyncio

class RetryDecorator:
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(self.max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    delay = self.base_delay * (2 ** attempt)  # Exponential backoff
                    logging.warning(f"Attempt {attempt + 1} failed: {str(e)}. Retrying in {delay}s")
                    time.sleep(delay)
            raise last_exception
        return wrapper

class ModelProvider(ABC):
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.metrics = MetricsCollector()
        self._initialize_provider()

    @abstractmethod
    def _initialize_provider(self) -> None:
        """Initialize the provider with necessary setup"""
        pass

    @abstractmethod
    def generate(
            self,
            prompt: str,
            max_tokens: int,
            temperature: Optional[float] = None,
            **kwargs: Any
    ) -> Dict[str, str]:
        """Generate text using the model"""
        pass

    @abstractmethod
    def is_healthy(self) -> bool:
        """Check if the provider is healthy"""
        pass

    def validate_input(self, prompt: str, max_tokens: int, temperature: Optional[float]) -> None:
        """Validate input parameters"""
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValidationError("Prompt must be a non-empty string")

        if not isinstance(max_tokens, int) or max_tokens <= 0:
            raise ValidationError("max_tokens must be a positive integer")

        if temperature is not None:
            if not isinstance(temperature, (int, float)) or not 0 <= temperature <= 1:
                raise ValidationError("Temperature must be between 0 and 1")

class BedrockProvider(ModelProvider):
    def _initialize_provider(self) -> None:
        try:
            self.client = boto3.client('bedrock-runtime')
            self.logger.info("Initialized Bedrock provider")
        except Exception as e:
            self.logger.error(f"Failed to initialize Bedrock provider: {e}")
            raise ModelProviderError(f"Bedrock initialization failed: {str(e)}", "bedrock")

    @RetryDecorator(max_retries=3)
    def generate(
            self,
            prompt: str,
            max_tokens: int,
            temperature: Optional[float] = None,
            **kwargs: Any
    ) -> Dict[str, str]:
        self.validate_input(prompt, max_tokens, temperature)

        start_time = time.time()
        try:
            model_id = kwargs.get('model_id', self.config['models']['default'])
            temp = temperature if temperature is not None else 0.7

            response = self.client.invoke_model(
                modelId=model_id,
                contentType='application/json',
                accept='application/json',
                body=json.dumps({
                    'prompt': prompt,
                    'max_tokens': max_tokens,
                    'temperature': temp
                })
            )

            result = json.loads(response['body'].read())

            # Record metrics
            duration = time.time() - start_time
            self.metrics.record_model_usage("bedrock", model_id, len(prompt.split()), len(result.get('generated_text', '').split()))
            self.metrics.record_request('generate', 'bedrock', 'success', duration)

            return result

        except Exception as e:
            self.metrics.record_request('generate', 'bedrock', 'error', time.time() - start_time)
            raise ModelProviderError(f"Bedrock generation failed: {str(e)}", "bedrock")

    def is_healthy(self) -> bool:
        try:
            # Simple health check
            self.generate("test", 1, temperature=0.1)
            return True
        except Exception:
            return False

class VastProvider(ModelProvider):
    def _initialize_provider(self) -> None:
        # Similar to BedrockProvider implementation
        pass

    @RetryDecorator(max_retries=3)
    def generate(self, prompt: str, max_tokens: int, temperature: Optional[float] = None, **kwargs: Any) -> Dict[str, str]:
        # Similar to BedrockProvider implementation
        pass

    def is_healthy(self) -> bool:
        # Similar to BedrockProvider implementation
        pass

class ModelRegistry:
    def __init__(self, config_path: str = "config/config.json"):
        self.version = VERSION
        self._config_path = config_path
        self.logger = setup_logging(DEFAULT_CONFIG['system']['log_level'])
        self.providers: Dict[str, ModelProvider] = {}
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._initialized = False  # Add initialization flag

        try:
            self.config = self._load_config(config_path)
            self._initialize_providers()
            self._start_health_check_thread()
            self._initialized = True  # Set flag after successful initialization
        except Exception as e:
            self.logger.critical(f"Failed to initialize ModelRegistry: {e}", exc_info=True)
            raise

    async def get_health_status(self) -> Dict[str, bool]:
        """Get health status of all providers"""
        status = {}
        for name, provider in self.providers.items():
            try:
                status[name] = provider.is_healthy()
            except Exception as e:
                self.logger.error(f"Error checking health for provider {name}: {e}")
                status[name] = False
        return status

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load and validate configuration"""
        try:
            config_path = os.path.abspath(config_path)
            if not config_path.startswith(os.path.abspath('config/')):
                raise ConfigurationError("Invalid config path")

            if not os.path.exists(config_path):
                self.logger.warning(f"Config file not found at {config_path}, using defaults")
                return DEFAULT_CONFIG

            # Check file size
            if os.path.getsize(config_path) > 1024 * 1024:  # 1MB limit
                raise ConfigurationError("Config file too large")

            with open(config_path, 'r') as f:
                config = json.load(f)

            # Merge with defaults
            merged_config = self._merge_configs(DEFAULT_CONFIG, config)

            # Validate against schema
            validate(instance=merged_config, schema=CONFIG_SCHEMA)

            # Replace environment variables
            merged_config = self._replace_env_vars(merged_config)

            return merged_config

        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in config file: {str(e)}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {str(e)}")

    def _merge_configs(self, default: Dict[str, Any], custom: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge configuration with defaults"""
        result = default.copy()

        for key, value in custom.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value

        return result

    def _replace_env_vars(self, obj: Any) -> Any:
        """Replace environment variables in configuration"""
        if isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
            env_var = obj[2:-1]
            allowed_vars = {
                'VAST_API_KEY', 'VAST_API_URL',
                'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_REGION'
            }
            if env_var not in allowed_vars:
                raise ConfigurationError(f"Invalid environment variable: {env_var}")
            return os.getenv(env_var, obj)
        elif isinstance(obj, dict):
            return {k: self._replace_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._replace_env_vars(item) for item in obj]
        return obj

    def _initialize_providers(self) -> None:
        """Initialize configured providers"""
        provider_classes = {
            ProviderType.BEDROCK: BedrockProvider,
            ProviderType.VAST: VastProvider
        }

        for provider_name, provider_config in self.config['providers'].items():
            if provider_config.get('enabled', False):
                provider_type = ProviderType(provider_name)
                provider_class = provider_classes.get(provider_type)

                if provider_class:
                    try:
                        self.providers[provider_name] = provider_class(provider_config, self.logger)
                        self.logger.info(f"Initialized provider: {provider_name}")
                    except Exception as e:
                        self.logger.error(f"Failed to initialize provider {provider_name}: {e}")

    def _start_health_check_thread(self) -> None:
        """Start background health check thread"""
        def health_check():
            while True:
                for name, provider in self.providers.items():
                    is_healthy = provider.is_healthy()
                    self.metrics.update_provider_health(name, is_healthy)
                time.sleep(60)  # Check every minute

        self.executor.submit(health_check)

    def get_provider(self, provider_name: str) -> Optional[ModelProvider]:
        """Get provider by name"""
        return self.providers.get(provider_name)

    def get_default_provider(self) -> Optional[ModelProvider]:
        """Get default provider"""
        default_name = self.config['system']['default_provider']
        return self.providers.get(default_name)

    def get_endpoint_config(self, endpoint_name: str) -> Dict[str, Any]:
        """Get endpoint configuration"""
        return self.config.get('endpoints', {}).get(endpoint_name, {})

    def list_providers(self) -> List[str]:
        """List available providers"""
        return list(self.providers.keys())

    def list_models(self) -> Dict[str, List[str]]:
        """List available models per provider"""
        return {
            name: provider.config['models']['available']
            for name, provider in self.providers.items()
        }

    async def generate(
        self,
        prompt: str,
        max_length: int,
        temperature: Optional[float] = None,
        provider: Optional[str] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Generate text using the specified or default provider"""
        try:
            # Get the appropriate provider
            if provider:
                model_provider = self.get_provider(provider)
                if not model_provider:
                    raise ModelProviderError(f"Provider {provider} not found or not enabled")
            else:
                model_provider = self.get_default_provider()
                if not model_provider:
                    raise ModelProviderError("No default provider available")

            # Generate the text
            result = model_provider.generate(
                prompt=prompt,
                max_tokens=max_length,
                temperature=temperature,
                **kwargs
            )

            return result

        except Exception as e:
            self.logger.error(f"Generation failed: {str(e)}")
            raise ModelProviderError(f"Generation failed: {str(e)}")

    async def cleanup(self):
        """Proper cleanup of all resources"""
        # First, stop accepting new tasks
        self.executor.shutdown(wait=False)
        
        # Clean up all providers
        cleanup_tasks = []
        for provider in self.providers.values():
            if hasattr(provider, 'cleanup'):
                cleanup_tasks.append(provider.cleanup())
        
        # Wait for all cleanup tasks to complete
        if cleanup_tasks:
            await asyncio.gather(*cleanup_tasks, return_exceptions=True)
        
        # Final executor shutdown
        self.executor.shutdown(wait=True)
    
    def __del__(self):
        if not self.executor._shutdown:
            self.executor.shutdown(wait=False)