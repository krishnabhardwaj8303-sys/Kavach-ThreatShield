"""Flask API + dashboard. Run: python -m threatshield.app"""
import json
from flask import Flask, jsonify, request, send_from_directory
from .pipeline import Pipeline
from .common import ROOT, RESULTS
from .data.synth import FLOW_FEATS

def create_app(db=None, backend="template"):
    app = Flask(__name__, static_folder=str(ROOT / "frontend")); pipe = Pipeline(db, backend)
    def guard(fn):
        try: return jsonify(fn())
        except (ValueError, KeyError, TypeError) as e: return jsonify(error=f"invalid input: {e}"), 400
    @app.get("/")
    def index(): return send_from_directory(app.static_folder, "index.html")
    @app.post("/api/scan/url")
    def u(): return guard(lambda: pipe.scan_url((request.get_json(silent=True) or {}).get("url")))
    @app.post("/api/scan/sms")
    def s(): return guard(lambda: pipe.scan_sms((request.get_json(silent=True) or {}).get("text")))
    @app.post("/api/scan/flow")
    def f(): return guard(lambda: pipe.scan_flow((request.get_json(silent=True) or {}).get("flow")))
    @app.get("/api/history")
    def h(): return jsonify(pipe.history())
    @app.get("/api/metrics")
    def m():
        out = {}
        for k in ["url", "sms", "net", "deployment"]:
            fp = RESULTS / f"{k}_metrics.json" if k != "deployment" else RESULTS / "deployment_report.json"
            out[k] = json.loads(fp.read_text()) if fp.exists() else None
        return jsonify(out)
    @app.get("/api/hardware/status")
    def hs(): return jsonify(pipe.hw.status())
    @app.post("/api/hardware/diagnostic")
    def hd():
        from .hal.link import encode, decode
        good = encode("url", "high", .9, "phishing"); bad = bytearray(good); bad[3] ^= 1
        return jsonify(good_frame_status=pipe.hw.send(good), corrupted_frame_status=pipe.hw.send(bytes(bad)),
                       note="Diagnostics run against the LOOPBACK software model, not real hardware.")
    @app.get("/api/flow_features")
    def ff(): return jsonify(FLOW_FEATS)
    return app

if __name__ == "__main__":
    create_app(str(ROOT / "scan_history.db")).run(host="127.0.0.1", port=8000)
