"""Fictional contact data that is valid and never reaches a real person.

Runtime-safe: no pytest, no Django at import time — a project's seeder or demo
fixture command can call it as well as a test. ``stapel_auth.testing.
unique_phone`` draws from the same pool.
"""
from __future__ import annotations

import random

__all__ = ["FICTIONAL_PHONE_POOL_SIZE", "fictional_phone"]

# NANP 555-0100..0199 is reserved for fiction in every area code: these
# numbers are valid for libphonenumber and never reach a real subscriber.
_AREA_CODES = (
    201, 202, 203, 205, 206, 207, 208, 212, 213, 214, 215, 216, 217, 218, 301,
    303, 304, 305, 312, 313, 314, 401, 402, 404, 405, 406, 407, 408, 410, 412,
    415, 503, 504, 505, 512, 602, 617, 702, 713, 801, 802, 808, 812, 816, 901,
    904, 914, 916, 919, 971,
)

#: How many distinct numbers :func:`fictional_phone` can return.
FICTIONAL_PHONE_POOL_SIZE = len(_AREA_CODES) * 100


def fictional_phone_at(index: int) -> str:
    """The ``index``-th number of the pool (modulo its size), in E.164."""
    n = int(index) % FICTIONAL_PHONE_POOL_SIZE
    area, line = _AREA_CODES[n // 100], 100 + n % 100
    return f"+1{area}555{line:04d}"


def fictional_phone(rng: random.Random | None = None) -> str:
    """A valid E.164 phone from the reserved fictional range (NANP 555-01XX).

    ``rng`` makes it reproducible (``random.Random(seed)``); without one the
    draw comes from the system source. Numbers repeat across calls once the
    pool (:data:`FICTIONAL_PHONE_POOL_SIZE`) is exhausted — a seeder that needs
    them distinct takes a ``random.Random(...).sample`` of indexes and calls
    :func:`fictional_phone_at`.
    """
    source = rng if rng is not None else random.SystemRandom()
    return fictional_phone_at(source.randrange(FICTIONAL_PHONE_POOL_SIZE))
