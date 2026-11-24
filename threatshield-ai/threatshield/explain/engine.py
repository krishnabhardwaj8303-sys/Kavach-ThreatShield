"""Explanation engine. NEVER changes the detector label. Backends: 'template' (deterministic, no LLM)
and 'ollama' (local Llama via http://localhost:11434, optional, UNTESTED here: no Llama weights/network access).
Every output is validated: cited evidence must exist in the verdict, label/risk must equal the detector's."""
import json, urllib.request

REC = {"phishing": ["Do not open the link or enter credentials.", "Type the official site address manually.", "Report the URL to your bank/CERT-In (cybercrime.gov.in)."],
       "sms": ["Do not click links or call numbers in the message.", "Never share OTP, UPI PIN or card details.", "Verify through the official app or the number on your card.", "Report to 1930 / cybercrime.gov.in."],
       "network": ["Review the source host and isolate it if it is yours.", "Check firewall logs for the flagged port range.", "Escalate to the network administrator."],
       "safe": ["No action needed. Stay alert for unexpected requests."]}

def risk_level(v):
    p, t = v["probability"], v["threshold"]
    if v["engine"] == "network": return "high" if v["label"] not in ("normal",) and p >= .5 else ("medium" if v["label"] != "normal" else "low")
    return "high" if p >= t else ("medium" if p >= t * .5 else "low")

def _evidence(v):
    out = []
    for i in v["indicators"]:
        if "description" in i: out.append(i["description"])
        elif "token" in i: out.append(f"Message wording associated with '{v['label']}': '{i['token']}'")
        else: out.append(f"{i['feature']}={i['value']} deviates {i['z_vs_normal']} std from normal")
    return out

def template_explain(v):
    r = risk_level(v); ev = _evidence(v); kind = {"url": "phishing", "sms": "sms", "network": "network"}[v["engine"]]
    safe = r == "low"
    s = (f"No strong threat indicators found ({v['probability']:.0%} threat score)." if safe else
         f"Flagged as '{v['label']}' with {v['probability']:.0%} calibrated score ({r} risk).")
    return dict(label=v["label"], risk=r, summary=s, evidence=ev, recommendations=REC["safe" if safe else kind], backend="template")

def validate(out, v):
    allowed = set(_evidence(v))
    if out.get("label") != v["label"] or out.get("risk") != risk_level(v): return False
    return all(e in allowed for e in out.get("evidence", []))

def ollama_explain(v, model="llama3.2:1b", url="http://localhost:11434/api/generate", timeout=60):
    base = template_explain(v)
    prompt = ("You explain a security detector's verdict. Do not change the label or risk. Use ONLY this evidence. "
              'Reply JSON {"summary": str}.\n' + json.dumps({"label": v["label"], "risk": base["risk"], "evidence": base["evidence"]}))
    req = urllib.request.Request(url, json.dumps({"model": model, "prompt": prompt, "stream": False, "format": "json"}).encode(), {"Content-Type": "application/json"})
    txt = json.loads(json.loads(urllib.request.urlopen(req, timeout=timeout).read())["response"])["summary"]
    base.update(summary=str(txt)[:600], backend=f"ollama:{model}"); return base

def explain(v, backend="template"):
    if backend == "ollama":
        try:
            o = ollama_explain(v)
            if validate(o, v): return o
        except Exception as e:
            t = template_explain(v); t["note"] = f"ollama unavailable ({type(e).__name__}); template used"; return t
    return template_explain(v)
