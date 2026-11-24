import pytest, json
from threatshield.pipeline import Pipeline
from threatshield.app import create_app
from threatshield.hal.link import encode, decode, LoopbackLink, crc8
from threatshield.explain.engine import explain, validate, template_explain, risk_level
from threatshield.url_engine import extract, NAMES
from threatshield.data.synth import url_dataset, sms_dataset
from threatshield.url_engine import split

@pytest.fixture(scope="module")
def pipe(): return Pipeline()

def test_url_features_shape(): assert len(extract("http://1.2.3.4/a@b")) == len(NAMES)
def test_url_ip_feature(): assert extract("http://1.2.3.4/x")[NAMES.index("has_ip")] == 1
def test_url_split_no_domain_leak():
    tr, va, te = split(url_dataset(3000))
    dom = lambda d: {".".join(u.split("//")[1].split("/")[0].split("@")[-1].split(".")[-2:]) for u, _ in d}
    assert not (dom(tr) & dom(te)) and not (dom(tr) & dom(va))
def test_sms_split_no_template_leak():
    d = sms_dataset(50); tr = {(c, i) for _, c, i in d if i % 5 < 3}; te = {(c, i) for _, c, i in d if i % 5 == 4}
    assert not (tr & te)
def test_phish_url(pipe):
    r = pipe.scan_url("http://paypal.verify.kaso.tk/login"); assert r["verdict"]["label"] == "phishing" and r["explanation"]["risk"] == "high"
def test_benign_url(pipe): assert pipe.scan_url("https://www.google.com/search?q=x")["explanation"]["risk"] == "low"
def test_sms_scam_and_legit(pipe):
    assert pipe.scan_sms("Your SBI KYC expires today, update PAN at http://bit.ly/ab12")["verdict"]["label"] != "legit"
    assert pipe.scan_sms("Hi, are we meeting for lunch?")["verdict"]["label"] == "legit"
def test_network(pipe):
    f = dict(duration=2, pkts=900, bytes_out=40000, bytes_in=2000, uniq_ports=250, syn_ratio=.8, pkt_rate=450, out_in_ratio=20)
    assert pipe.scan_flow(f)["verdict"]["label"] != "normal"
def test_empty_inputs(pipe):
    with pytest.raises(ValueError): pipe.scan_url("  ")
    with pytest.raises(ValueError): pipe.scan_sms("")
def test_explainer_cannot_override_label(pipe):
    v = pipe.url.scan("http://paypal.verify.kaso.tk/login"); out = template_explain(v)
    assert validate(out, v); out["label"] = "benign"; assert not validate(out, v)
    out = template_explain(v); out["evidence"].append("invented evidence"); assert not validate(out, v)
def test_ollama_fallback_when_unavailable(pipe):
    v = pipe.url.scan("http://paypal.verify.kaso.tk/login"); o = explain(v, "ollama"); assert o["backend"] == "template" and "note" in o
def test_hal_roundtrip():
    f = encode("sms", "high", .8, "kyc"); d = decode(f); assert d["engine"] == "sms" and d["risk"] == "high" and abs(d["confidence"] - .8) < .01
def test_hal_crc_and_sync_errors():
    l = LoopbackLink(); l.connect(); f = bytearray(encode("url", "low", .1, "benign")); f[2] ^= 1
    assert l.send(bytes(f)) & 8 and l.send(b"\x00" * 7) & 16 and l.errors == 2
def test_crc8_known_vector(): assert crc8(b"123456789") == 0xF4
def test_hal_requires_connect():
    with pytest.raises(ConnectionError): LoopbackLink().send(encode("url", "low", 0, "benign"))
def test_api():
    c = create_app().test_client()
    r = c.post("/api/scan/url", json={"url": "http://185.1.2.3/login"}); assert r.status_code == 200 and "explanation" in r.get_json()
    assert c.post("/api/scan/url", json={}).status_code == 400
    assert c.get("/api/history").get_json()[0]["engine"] == "url"
    assert c.post("/api/hardware/diagnostic").get_json()["corrupted_frame_status"] & 8
    assert c.get("/").status_code == 200 and c.get("/api/metrics").status_code == 200

# ---- Kavach UART bridge driver (frame format read from user's uart_to_reg_bridge.v) ----
def test_kavach_frames():
    from threatshield.hal.kavach import encode_read, encode_write, decode_reply, decode_status
    assert encode_write(0x08, 0xDEADBEEF) == bytes([1, 8, 0xDE, 0xAD, 0xBE, 0xEF])
    assert encode_read(0xFC) == bytes([2, 0xFC, 0, 0, 0, 0]) and decode_reply(b"KAVA") == 0x4B415641
    assert decode_status(0x25) == dict(bist_pass=True, bist_fail=False, replay_detected=True, authentication_grant=False, auth_denied_bist=False, auth_denied_replay=True)
    with pytest.raises(ValueError): encode_write(0x100, 0)
    with pytest.raises(ValueError): encode_write(0, 1 << 32)

def test_kavach_rtl_cosim():
    import os, shutil, subprocess, sys
    if not os.environ.get("KAVACH_RTL_DIR") or not shutil.which("iverilog"): pytest.skip("needs KAVACH_RTL_DIR and iverilog")
    r = subprocess.run([sys.executable, "hardware/kavach_integration/run_cosim.py"], capture_output=True, text=True); assert r.returncode == 0, r.stdout
