#!/usr/bin/env python3
"""Sliding-window rate limiter for block operations.

Containment measure: if a publisher's HMAC key is ever compromised and used
to mass-block traffic, the agent caps the damage per minute instead of
DoS-ing itself.
"""
from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    def __init__(self, max_per_minute: int):
        self.max = max_per_minute
        self.events: deque[float] = deque()
        self.lock = threading.Lock()

    def allow(self) -> bool:
        now = time.monotonic()
        with self.lock:
            while self.events and self.events[0] < now - 60:
                self.events.popleft()
            if len(self.events) >= self.max:
                return False
            self.events.append(now)
            return True
