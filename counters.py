"""Atomic counters on the Django cache.

Every budget in this module (wrong-code guesses, lockout tiers, sends, guest
mints, SMS spend) used to be ``count = cache.get(k) or 0; cache.set(k,
count + 1)``. Under concurrency that is a lost update: N parallel requests
all read the same count and all pass, so a budget of 5 guesses becomes 5 per
*wave* of parallel requests. ``cache.add`` + ``cache.incr`` are single
operations on every shared backend (Redis ``SET NX`` / ``INCRBY``), so each
caller gets its own number.
"""
from __future__ import annotations

__all__ = ["bump", "claim"]


def bump(key: str, ttl: int, cache=None) -> int:
    """Increment *key* and return the new value; the first bump starts a
    window of *ttl* seconds (the window is not extended by later bumps)."""
    if cache is None:
        from django.core.cache import cache
    for _ in range(3):
        cache.add(key, 0, ttl)
        try:
            return int(cache.incr(key))
        except ValueError:
            # Expired between add and incr; start the next window.
            continue
    # A cache that keeps losing the key is not counting anything: answer as
    # if the budget were spent rather than as if it were untouched.
    return 2**31


def claim(key: str, ttl: int, cache=None) -> bool:
    """Take *key* for *ttl* seconds; ``False`` when somebody holds it."""
    if cache is None:
        from django.core.cache import cache
    return bool(cache.add(key, 1, ttl))
