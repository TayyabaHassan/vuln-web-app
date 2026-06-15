"""Per-IP sliding-window rate limiter (stdlib only).

Closes VULN-7 (No Rate Limiting). Pre-fix, an attacker could brute-force
POST /login at the speed of the network -- every attempt cost only one
bcrypt verify on the server, and there was no cap on attempts per source.

This middleware caps the number of POSTs a single IP can issue in a
rolling time window (defaults: 5 POSTs per 60 seconds). Throttled POSTs
get HTTP 429 with a Retry-After header BEFORE the route handler runs --
so the (intentionally slow) bcrypt verify and SQLite write are never
invoked on a throttled call.

State lives in a process-local dict[str, deque[float]]; restarts wipe it.
For an educational lab on localhost this is fine; a production deployment
would back the counter with Redis. See CLAUDE.md "Rate Limiting After the
Fix" for the operational notes.

Spec refs (FR-XX / NFR-XX / EC-XX) in the inline comments below point at
the source-of-truth requirements in .claude/specs/no-rate-limiting-fix.md.
"""

import asyncio
import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-process, per-IP sliding-window rate limiter scoped to POST requests.

    Stdlib-only (collections.deque + asyncio.Lock + time.monotonic). Counter
    state is intentionally not persisted across restarts -- see the parent
    spec's Operational Note for the trade-off.
    """

    def __init__(self, app, max_requests: int, window_seconds: int):
        super().__init__(app)
        self._max = max_requests
        self._window = window_seconds
        # bucket per source IP. defaultdict(deque) means we don't need an
        # explicit "create bucket on first POST" check -- the lookup creates
        # an empty deque transparently. The deque stores the time.monotonic()
        # timestamps of the last N POSTs from that IP, ordered oldest-to-
        # newest, with stale entries dropped from the LEFT (popleft is O(1)).
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        # One async lock for the whole map. Held only during the
        # prune/check/append sequence -- NEVER across `await call_next`,
        # so a slow handler on one IP cannot block other IPs' counters.
        self._lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next):
        # FR-01 / FR-07: method check is the first statement. Every non-POST
        # request bypasses the limiter with zero state access.
        if request.method != "POST":
            return await call_next(request)

        # FR-03: client IP, with a defensive fallback so a missing
        # request.client never raises. We use the TCP-level peer address
        # (request.client.host) -- we deliberately do NOT trust
        # X-Forwarded-For or any other header, because trusting client-
        # controlled headers in the lab would let an attacker spoof
        # source IPs and bypass the limit.
        client = request.client
        ip = client.host if client is not None else "unknown"

        try:
            now = time.monotonic()  # NOT time.time() -- monotonic is immune
                                    # to wall-clock jumps (NTP slew, manual
                                    # `date -s`) that could otherwise reset
                                    # or freeze the window.
            cutoff = now - self._window
            async with self._lock:
                bucket = self._buckets[ip]
                # FR-02 step 3: prune stale entries from the left.
                # Anything older than `cutoff` has fallen out of the
                # rolling window and no longer counts.
                while bucket and bucket[0] < cutoff:
                    bucket.popleft()
                # FR-02 step 4: length check against the configured max.
                # `>=` (not `>`) is what makes the 6th POST trigger
                # throttling when max=5: the deque holds 5 in-window
                # timestamps and we reject before appending the 6th.
                if len(bucket) >= self._max:
                    oldest = bucket[0]
                    # FR-04 + EC-11: integer floor of 1 second.
                    # Retry-After tells the client roughly when the
                    # oldest in-window request will fall off the left,
                    # making a slot free again.
                    retry_after = max(1, int(self._window - (now - oldest)))
                    return JSONResponse(
                        status_code=429,
                        content={"error": "Too many requests", "retry_after": retry_after},
                        headers={"Retry-After": str(retry_after)},
                    )
                # FR-02 step 5: record this request and forward.
                # Append happens BEFORE we forward, so a request that
                # crashes the handler still counts against quota --
                # closes the "trigger 500s to dodge the limit" trick.
                bucket.append(now)
        except Exception:
            # NFR-07: fail-open on any unexpected bookkeeping error.
            # A broken limiter denying every request is worse than no
            # limiter for a few seconds. Contrast with CSRFMiddleware,
            # which fails CLOSED -- the trade-off is different there
            # because a missing CSRF check re-opens the vulnerability,
            # while a missing rate-limit just temporarily slows brute-
            # forcing back to bcrypt-bound (still expensive) territory.
            return await call_next(request)

        return await call_next(request)
