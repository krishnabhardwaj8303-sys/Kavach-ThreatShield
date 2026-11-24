"""Latency / memory / size benchmark (desktop x86_64 only). python evaluation/bench.py"""
import time, json, os, platform, psutil, numpy as np
from threatshield.common import MODELS, RESULTS
from threatshield.pipeline import Pipeline
proc = psutil.Process(); rss0 = proc.memory_info().rss
p = Pipeline(); rss1 = proc.memory_info().rss
urls = ["http://paypal.verify.kaso.tk/login", "https://www.google.com/search?q=x", "http://185.1.2.3/a.php"] * 70
sms = ["Your SBI KYC expires today, update PAN at http://bit.ly/ab12", "Hi, lunch at 1?", "Tell the agent OTP 483921 for refund"] * 70
flow = dict(duration=2, pkts=900, bytes_out=40000, bytes_in=2000, uniq_ports=250, syn_ratio=.8, pkt_rate=450, out_in_ratio=20)
def lat(fn, xs):
    fn(xs[0]); t = []
    for x in xs:
        s = time.perf_counter(); fn(x); t.append((time.perf_counter() - s) * 1000)
    return dict(p50_ms=float(np.percentile(t, 50)), p95_ms=float(np.percentile(t, 95)), n=len(t))
rep = dict(environment=dict(arch=platform.machine(), cpu_count=os.cpu_count(), python=platform.python_version(), note="DESKTOP x86_64 development test only; NOT an ARM device"),
    detector_latency_only=dict(url=lat(p.url.scan, urls), sms=lat(p.sms.scan, sms), network=lat(p.net.scan, [flow] * 210)),
    full_pipeline_latency=dict(url=lat(p.scan_url, urls), sms=lat(p.scan_sms, sms), network=lat(p.scan_flow, [flow] * 210)),
    memory_mb=dict(model_load_rss_delta=round((rss1 - rss0) / 1e6, 1), process_rss_after=round(proc.memory_info().rss / 1e6, 1)),
    model_sizes_kb={f.name: round(f.stat().st_size / 1024, 1) for f in MODELS.glob("*.joblib")})
old = RESULTS / "deployment_report.json"
if old.exists(): rep["executorch"] = json.loads(old.read_text()).get("executorch")
(RESULTS / "deployment_report.json").write_text(json.dumps(rep, indent=1)); print(json.dumps(rep, indent=1))
