"""Thread-safe TTLCache manager with SHA-256 key hashing for metadata caching."""

from __future__ import annotations

import functools
import hashlib
import json
import logging
from threading import Lock
from typing import Any, Callable, Optional, TypeVar

from cachetools import TTLCache

from config.settings import SETTINGS, CacheConfig

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

# Sentinel object to distinguish cache misses from functions that return None
_CACHE_MISS = object()


class MetadataCache:
    """TTLCache wrapper with SHA-256 key hashing for BigQuery metadata."""

    def __init__(self, config: Optional[CacheConfig] = None) -> None:
        self.config = config or SETTINGS.cache
        self.lock = Lock()
        self._cache: Optional[TTLCache[str, Any]] = None
        if self.config.enabled:
            self._cache = TTLCache(
                maxsize=self.config.max_cache_entries,
                ttl=self.config.metadata_ttl_seconds,
            )
            logger.info(
                "MetadataCache initialized: maxsize=%d, ttl=%ds",
                self.config.max_cache_entries,
                self.config.metadata_ttl_seconds,
            )
        else:
            logger.info("MetadataCache disabled by configuration")

    @property
    def is_enabled(self) -> bool:
        return self.config.enabled and self._cache is not None

    @staticmethod
    def generate_key(prefix: str, *args: Any, **kwargs: Any) -> str:
        """Create a deterministic SHA-256 hashed cache key."""
        payload = {
            "prefix": prefix,
            "args": args,
            "kwargs": {k: kwargs[k] for k in sorted(kwargs.keys())},
        }
        serialized = json.dumps(payload, sort_keys=True, default=str)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return f"{prefix}:{digest}"

    def get(self, key: str) -> Optional[Any]:
        """Retrieve an item from cache if enabled and valid.

        Returns _CACHE_MISS sentinel if the key is not found (never returns None for a miss).
        """
        if not self.is_enabled or self._cache is None:
            return _CACHE_MISS
        with self.lock:
            val = self._cache.get(key, _CACHE_MISS)
            if val is not _CACHE_MISS:
                logger.debug("Cache hit for key: %s", key)
            else:
                logger.debug("Cache miss for key: %s", key)
            return val

    def set(self, key: str, value: Any) -> None:
        """Store an item in cache if enabled."""
        if not self.is_enabled or self._cache is None:
            return
        with self.lock:
            self._cache[key] = value
            logger.debug("Cached key: %s", key)

    def delete(self, key: str) -> None:
        """Remove an item from cache."""
        if not self.is_enabled or self._cache is None:
            return
        with self.lock:
            self._cache.pop(key, None)

    def clear(self) -> None:
        """Clear all cached entries."""
        if self._cache is not None:
            with self.lock:
                self._cache.clear()
            logger.info("MetadataCache cleared")

    def __len__(self) -> int:
        if self._cache is None:
            return 0
        with self.lock:
            return len(self._cache)

    def __bool__(self) -> bool:
        return True


# Global cache instance
CACHE = MetadataCache()


def cached(prefix: str, cache_instance: Optional[MetadataCache] = None) -> Callable[[F], F]:
    """Decorator to cache synchronous and asynchronous function results."""
    cache = cache_instance if cache_instance is not None else CACHE

    def decorator(func: F) -> F:
        if asyncio_iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                if not cache.is_enabled:
                    return await func(*args, **kwargs)

                key = cache.generate_key(prefix, *args, **kwargs)
                cached_val = cache.get(key)
                if cached_val is not _CACHE_MISS:
                    return cached_val

                result = await func(*args, **kwargs)
                cache.set(key, result)
                return result

            return async_wrapper  # type: ignore

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            if not cache.is_enabled:
                return func(*args, **kwargs)

            key = cache.generate_key(prefix, *args, **kwargs)
            cached_val = cache.get(key)
            if cached_val is not _CACHE_MISS:
                return cached_val

            result = func(*args, **kwargs)
            cache.set(key, result)
            return result

        return sync_wrapper  # type: ignore

    return decorator


def asyncio_iscoroutinefunction(func: Any) -> bool:
    """Helper to detect coroutines."""
    import inspect
    return inspect.iscoroutinefunction(func)
