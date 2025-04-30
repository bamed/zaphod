# utils/constants.py
from enum import Enum
from typing import Dict, Any

VERSION = "1.0.0"

class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class ProviderType(str, Enum):
    VAST = "vast"
    BEDROCK = "bedrock"

# Default configurations
DEFAULT_CONFIG: Dict[str, Any] = {
    "version": VERSION,
    "system": {
        "log_level": "INFO",
        "max_tokens_default": 512,
        "default_provider": "vast",
        "request_timeout": 30,
        "max_retries": 3
    },
    "providers": {
        "vast": {
            "enabled": True,
            "priority": 1,
            "models": {
                "default": "mistralai/Mistral-7B-Instruct-v0.3",
                "available": []
            },
            "config": {}
        }
    },
    "endpoints": {
        "generate": {
            "max_tokens": 512,
            "temperature": 0.7,
            "timeout": 30
        },
        "analyze": {
            "max_tokens": 1024,
            "temperature": 0.7,
            "timeout": 45
        }
    }
}

# Schema for configuration validation
CONFIG_SCHEMA = {
    "type": "object",
    "required": ["version", "system", "providers"],
    "properties": {
        "version": {"type": "string"},
        "system": {
            "type": "object",
            "required": ["log_level", "default_provider"],
            "properties": {
                "log_level": {"type": "string", "enum": list(LogLevel.__members__.keys())},
                "max_tokens_default": {"type": "integer", "minimum": 1},
                "default_provider": {"type": "string"},
                "request_timeout": {"type": "integer", "minimum": 1},
                "max_retries": {"type": "integer", "minimum": 0}
            }
        },
        "providers": {
            "type": "object",
            "patternProperties": {
                "^[a-zA-Z0-9_]+$": {
                    "type": "object",
                    "required": ["enabled", "models"],
                    "properties": {
                        "enabled": {"type": "boolean"},
                        "priority": {"type": "integer"},
                        "models": {
                            "type": "object",
                            "required": ["default", "available"],
                            "properties": {
                                "default": {"type": "string"},
                                "available": {"type": "array", "items": {"type": "string"}}
                            }
                        },
                        "config": {"type": "object"}
                    }
                }
            }
        }
    }
}