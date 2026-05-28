"""
authgate-kernel configuration — pydantic-settings based.

All configuration is read from environment variables (with optional .env file).
Defaults are conservative for production; override for development.

Environment variables (all prefixed AUTHGATE_):
  AUTHGATE_LOG_LEVEL         DEBUG | INFO | WARNING | ERROR (default: INFO)
  AUTHGATE_AUDIT_PATH        path to .jsonl audit log (default: None = in-memory)
  AUTHGATE_CONFIDENCE_WARN   confidence threshold for warnings (default: 0.8)
  AUTHGATE_MAX_CHAIN_DEPTH   max delegation depth (default: 16)
  AUTHGATE_FREEZE_REGISTRY   freeze registry on verifier init (default: false)
  AUTHGATE_AUDIT_ENABLED     enable audit logging (default: true)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class AuthgateSettings:
    log_level: str = "INFO"
    audit_path: str | None = None
    confidence_warn_threshold: float = 0.8
    max_chain_depth: int = 16
    freeze_registry_on_init: bool = False
    audit_enabled: bool = True

    @classmethod
    def from_env(cls) -> AuthgateSettings:
        """Read configuration from environment variables."""
        def _get(key: str, default: str) -> str:
            return os.environ.get(f"AUTHGATE_{key}", default)

        def _bool(key: str, default: bool) -> bool:
            val = os.environ.get(f"AUTHGATE_{key}")
            if val is None:
                return default
            return val.strip().lower() in ("1", "true", "yes")

        def _float(key: str, default: float) -> float:
            val = os.environ.get(f"AUTHGATE_{key}")
            return float(val) if val is not None else default

        def _int(key: str, default: int) -> int:
            val = os.environ.get(f"AUTHGATE_{key}")
            return int(val) if val is not None else default

        return cls(
            log_level=_get("LOG_LEVEL", "INFO").upper(),
            audit_path=os.environ.get("AUTHGATE_AUDIT_PATH"),
            confidence_warn_threshold=_float("CONFIDENCE_WARN", 0.8),
            max_chain_depth=_int("MAX_CHAIN_DEPTH", 16),
            freeze_registry_on_init=_bool("FREEZE_REGISTRY", False),
            audit_enabled=_bool("AUDIT_ENABLED", True),
        )


_default: AuthgateSettings | None = None


def get_settings() -> AuthgateSettings:
    """Return the process-global settings singleton (lazy, from environment)."""
    global _default
    if _default is None:
        _default = AuthgateSettings.from_env()
    return _default


def override_settings(**kwargs) -> None:
    """Override specific settings at runtime. Useful in tests."""
    global _default
    if _default is None:
        _default = AuthgateSettings.from_env()
    for k, v in kwargs.items():
        setattr(_default, k, v)


def reset_settings() -> None:
    """Reset to environment-derived defaults. Use in test teardown."""
    global _default
    _default = None
