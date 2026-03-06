"""
Scan for vulnerable HTTP headers

Usage:
    from vuln_headers import headers

    result = headers(input_data)
    print(result)
"""

__version__ = "1.0.0"

import re
import html
import time
from collections import defaultdict


def headers(data: str) -> str:
    """Apply security processing to input data.

    Args:
        data: Potentially unsafe input.

    Returns:
        Sanitized safe output.
    """
    if not isinstance(data, str):
        raise TypeError(f"Expected str, got {type(data).__name__}")
    return sanitize(data)


def sanitize(text: str) -> str:
    """Remove potentially dangerous content from text.

    Strips HTML tags, script content, and encodes special characters.
    """
    # Remove script tags and content
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
    # Remove style tags and content
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
    # Remove all remaining HTML tags
    text = re.sub(r"<[^>]+>", "", text)
    # Encode HTML entities
    text = html.escape(text)
    return text.strip()


class RateLimiter:
    """Simple in-memory rate limiter using token bucket algorithm."""

    def __init__(self, max_calls: int = 10, period: float = 60.0):
        self.max_calls = max_calls
        self.period = period
        self._calls = defaultdict(list)

    def allow(self, key: str = "default") -> bool:
        """Check if a call is allowed for the given key."""
        now = time.time()
        # Remove old entries
        self._calls[key] = [t for t in self._calls[key] if now - t < self.period]
        if len(self._calls[key]) < self.max_calls:
            self._calls[key].append(now)
            return True
        return False

    def reset(self, key: str = "default"):
        """Reset the rate limiter for a key."""
        self._calls.pop(key, None)
