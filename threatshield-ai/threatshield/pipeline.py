"""Inference pipeline: detectors -> (independent) explainer -> optional hardware link. Standalone without hardware."""
import time, sqlite3, json
from .url_engine import UrlEngine
from .sms_engine import SmsEngine
from .net_engine import NetEngine
from .explain.engine import explain, risk_level
from .hal.link import make_link, encode
from .common import ROOT

class Pipeline:
    def __init__(self, db=None, backend="template"):
        self.url, self.sms, self.net = UrlEngine(), SmsEngine(), NetEngine()
        self.backend, self.hw = backend, make_link("loopback"); self.hw.connect()
        self.db = sqlite3.connect(db or ":memory:", check_same_thread=False)
        self.db.execute("create table if not exists h(ts real, engine text, input text, label text, risk text, prob real, latency_ms real)")
    def _run(self, engine, fn, inp, shown):
        t = time.perf_counter(); v = fn(inp); ms = (time.perf_counter() - t) * 1000
        ex = explain(v, self.backend); fl = 0
        hw_status = self.hw.send(encode(engine, ex["risk"], v["probability"], v["label"], fl))
        self.db.execute("insert into h values(?,?,?,?,?,?,?)", (time.time(), engine, shown[:120], v["label"], ex["risk"], v["probability"], ms)); self.db.commit()
        return dict(verdict=v, explanation=ex, latency_ms=round(ms, 3), hardware=dict(backend=self.hw.name, status_bits=hw_status))
    def scan_url(self, u):
        if not isinstance(u, str) or not u.strip(): raise ValueError("empty url")
        return self._run("url", self.url.scan, u.strip(), u)
    def scan_sms(self, t):
        if not isinstance(t, str) or not t.strip(): raise ValueError("empty message")
        return self._run("sms", self.sms.scan, t, t)
    def scan_flow(self, f):
        return self._run("network", self.net.scan, f, json.dumps(f))
    def history(self, n=50):
        return [dict(zip(["ts", "engine", "input", "label", "risk", "prob", "latency_ms"], r)) for r in
                self.db.execute("select * from h order by ts desc limit ?", (n,))]
