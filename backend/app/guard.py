"""Invisible DoS guard: counts real requests per client in 1 s windows, runs the detector, enforces mitigations."""
import threading, time
from collections import Counter

from starlette.responses import PlainTextResponse

from .engine import Engine
from .mitigation import RATE_CAP


class Guard:
    def __init__(self, app, engine: Engine, window=1.0):
        self.app, self.engine, self.win = app, engine, window
        self.lock, self.counts, self.sizes = threading.Lock(), Counter(), []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            time.sleep(self.win)
            with self.lock:
                c, sz = dict(self.counts), self.sizes
                self.counts, self.sizes = Counter(), []
            if c:
                try:
                    self.engine.process(dict(counts=c, syn_ratio=.1, mean_size=max(40., sum(sz) / len(sz))), "live")
                except Exception:
                    pass

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        ip = (scope.get("client") or ("0.0.0.0",))[0]
        hdr = dict(scope["headers"])
        size = int(hdr.get(b"content-length", b"0") or 0) + 400
        with self.lock:
            self.counts[ip] += 1
            n = self.counts[ip]
            self.sizes.append(size)
        a = self.engine.mit.active.get(ip)
        if ip not in self.engine.mit.allow_list and a and (a["action"] == "block" or n > RATE_CAP):
            code = 403 if a["action"] == "block" else 429
            return await PlainTextResponse("Too many requests", code, {"Retry-After": "5"})(scope, receive, send)
        await self.app(scope, receive, send)
