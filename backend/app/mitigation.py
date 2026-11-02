"""Graduated mitigation: rate-limit -> temporary block, auto-expiry, allow-list. Simulation only:
it tracks decisions and computes how much traffic would be dropped; it never touches a firewall."""
RATE_CAP = 10  # packets/s a rate-limited source may still send


class Mitigator:
    def __init__(self, limit_ttl=5, block_ttl=20):
        self.limit_ttl, self.block_ttl = limit_ttl, block_ttl
        self.active, self.allow_list, self.events = {}, set(), []

    def log(self, t, msg):
        self.events.append({"t": t, "msg": msg})
        del self.events[:-100]

    def expire(self, t):
        for ip, a in list(self.active.items()):
            if a["expires"] <= t:
                del self.active[ip]
                self.log(t, f"{a['action']} on {ip} expired")

    def filter(self, counts):
        passed = dropped = 0
        for ip, c in counts.items():
            a = self.active.get(ip)
            keep = 0 if a and a["action"] == "block" else min(c, RATE_CAP) if a else c
            passed += keep; dropped += c - keep
        return passed, dropped

    def apply(self, t, offenders):
        limited = blocked = 0
        for ip in offenders:
            if ip in self.allow_list:
                continue
            cur = self.active.get(ip)
            if cur is None:
                self.active[ip] = dict(action="rate_limit", since=t, expires=t + self.limit_ttl); limited += 1
            elif cur["action"] == "rate_limit":
                self.active[ip] = dict(action="block", since=t, expires=t + self.block_ttl); blocked += 1
            else:
                cur["expires"] = t + self.block_ttl
        if limited: self.log(t, f"rate-limited {limited} source(s)")
        if blocked: self.log(t, f"blocked {blocked} source(s) for {self.block_ttl} windows")

    def allow(self, t, ip, flag):
        if flag:
            self.allow_list.add(ip)
            if self.active.pop(ip, None): self.log(t, f"{ip} allow-listed and unblocked")
        else:
            self.allow_list.discard(ip)

    def table(self, t):
        return [dict(ip=ip, action=a["action"], expires_in=max(0, a["expires"] - t))
                for ip, a in sorted(self.active.items(), key=lambda x: (x[1]["action"] != "block", x[0]))]
