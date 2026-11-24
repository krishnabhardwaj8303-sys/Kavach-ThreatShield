"""Phishing URL engine: lexical features -> compared models -> calibrated probability."""
import re, math, json, joblib, numpy as np
from urllib.parse import urlparse
from collections import Counter
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.calibration import CalibratedClassifierCV
from sklearn.inspection import permutation_importance
from sklearn.metrics import f1_score
from .common import MODELS, RESULTS, VERSION, bucket, binary_metrics, pick_threshold, brier
from .data.synth import url_dataset, BRANDS, KW, BAD_TLD

NAMES = ["url_len", "host_len", "n_dots", "n_hyphens", "digit_ratio", "has_ip", "has_at", "is_https",
         "n_subdomains", "bad_tld", "entropy", "brand_in_subdomain", "n_keywords", "path_len",
         "query_len", "punycode", "brand_not_registered"]
DESC = {"has_ip": "Host is a raw IP address", "has_at": "URL contains '@' (hides real host)",
        "is_https": "Connection is not HTTPS", "n_subdomains": "Unusually many subdomain levels",
        "bad_tld": "Domain uses a TLD frequently abused for phishing", "n_hyphens": "Many hyphens in the host",
        "brand_in_subdomain": "Brand name appears in a subdomain (impersonation)", "n_keywords": "Credential/urgency keywords in URL",
        "punycode": "Punycode (xn--) host, possible look-alike", "entropy": "High character randomness",
        "url_len": "Very long URL", "brand_not_registered": "Brand name present but not the registered domain",
        "digit_ratio": "High digit ratio", "n_dots": "Many dots in host"}

def _ent(s):
    c = Counter(s); n = len(s) or 1
    return -sum(v / n * math.log2(v / n) for v in c.values())

def host_of(url):
    u = url if "://" in url else "http://" + url
    p = urlparse(u); h = p.hostname or ""
    return u, p, h

def extract(url):
    u, p, h = host_of(url); parts = h.split("."); tld = parts[-1] if parts else ""
    reg = ".".join(parts[-2:]) if len(parts) >= 2 else h
    sub = parts[:-2] if len(parts) > 2 else []
    low = u.lower(); subj = ".".join(sub).lower()
    return [len(u), len(h), h.count("."), h.count("-"), sum(c.isdigit() for c in h) / (len(h) or 1),
            int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h))), int("@" in (p.netloc or "")),
            int(p.scheme == "https"), len(sub), int(tld in BAD_TLD), _ent(h),
            int(any(b in subj for b in BRANDS)), sum(k in low for k in KW), len(p.path), len(p.query),
            int("xn--" in h), int(any(b in low for b in BRANDS) and not any(reg.startswith(b + ".") for b in BRANDS))]

def split(data):
    tr, va, te = [], [], []
    for u, y in data:
        h = host_of(u)[2]; key = ".".join(h.split(".")[-2:])
        b = bucket(key); (tr if b < 7 else va if b == 7 else te).append((u, y))
    return tr, va, te

def train(seed=7):
    tr, va, te = split(url_dataset(seed=seed))
    f = lambda d: (np.array([extract(u) for u, _ in d]), np.array([y for _, y in d]))
    (Xtr, ytr), (Xva, yva), (Xte, yte) = f(tr), f(va), f(te)
    cands = {"logreg": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
             "random_forest": RandomForestClassifier(200, min_samples_leaf=2, class_weight="balanced", random_state=0, n_jobs=1),
             "hist_gb": HistGradientBoostingClassifier(random_state=0)}
    val = {}
    for n, m in cands.items():
        m.fit(Xtr, ytr); val[n] = float(f1_score(yva, m.predict(Xva)))
    best = max(val, key=val.get)
    cal = CalibratedClassifierCV(cands[best], method="isotonic", cv=3).fit(Xtr, ytr)
    pva = cal.predict_proba(Xva)[:, 1]; thr = pick_threshold(yva, pva, .95)
    pte = cal.predict_proba(Xte)[:, 1]
    imp = permutation_importance(cands[best], Xva, yva, n_repeats=5, random_state=0, scoring="f1")
    importance = dict(sorted(zip(NAMES, map(float, imp.importances_mean)), key=lambda kv: -kv[1]))
    ben = Xtr[ytr == 0]
    meta = dict(version=VERSION, selected=best, validation_f1=val, threshold=thr, importance=importance,
                benign_p95=np.percentile(ben, 95, axis=0).tolist(), seed=seed,
                sizes=dict(train=len(tr), val=len(va), test=len(te)),
                test=binary_metrics(yte, pte, thr), test_brier=brier(yte, pte),
                data_note="SYNTHETIC data; split by registered domain; not real-world accuracy")
    joblib.dump(dict(model=cal, meta=meta), MODELS / "url_model.joblib")
    (RESULTS / "url_metrics.json").write_text(json.dumps(meta, indent=1))
    return meta

class UrlEngine:
    def __init__(self):
        d = joblib.load(MODELS / "url_model.joblib"); self.m, self.meta = d["model"], d["meta"]
    def scan(self, url):
        x = extract(url); p = float(self.m.predict_proba([x])[0, 1]); thr = self.meta["threshold"]
        imp, p95 = self.meta["importance"], self.meta["benign_p95"]
        fired = []
        for i, n in enumerate(NAMES):
            if n in DESC and ((n == "is_https" and x[i] == 0) or (n != "is_https" and x[i] > max(p95[i], 0) and x[i] > 0)):
                fired.append((imp.get(n, 0), n))
        ind = [{"feature": n, "value": round(float(x[NAMES.index(n)]), 3), "description": DESC[n]} for _, n in sorted(fired, reverse=True)[:5]]
        return dict(engine="url", probability=p, threshold=thr, label="phishing" if p >= thr else ("suspicious" if p >= thr / 2 else "benign"), indicators=ind)
