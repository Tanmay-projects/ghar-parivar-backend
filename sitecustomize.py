"""Runtime reliability patch for Render/Supabase network reads.

Python imports sitecustomize automatically during startup. We only retry
idempotent HTTP reads so a transient Supabase connection failure does not
surface to the browser as the generic `Failed to fetch` error.
"""
import time

try:
    import httpx

    _original_send = httpx.Client.send

    def _send_with_read_retry(self, request, *args, **kwargs):
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            last_error = None
            for attempt in range(3):
                try:
                    return _original_send(self, request, *args, **kwargs)
                except httpx.TransportError as exc:
                    last_error = exc
                    if attempt < 2:
                        time.sleep(0.35 * (attempt + 1))
            raise last_error
        return _original_send(self, request, *args, **kwargs)

    httpx.Client.send = _send_with_read_retry
except Exception:
    # Never prevent the API from starting if the HTTP client implementation changes.
    pass
