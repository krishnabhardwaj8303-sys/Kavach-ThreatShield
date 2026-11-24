"""Network anomaly engine (defensive): flow features -> IsolationForest (unsupervised) + RandomForest (classes)."""
import json, joblib, numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from .common import MODELS, RESULTS, VERSION, binary_metrics
from .data.synth import flow_dataset, FLOW_FEATS, FLOW_CLASSES

LOGF = lambda X: np.log1p(np.asarray(X, float))

def train(seed=5):
    X, y = flow_dataset(seed=seed); F = LOGF(X)
    Xtr, Xt, ytr, yt = train_test_split(F, y, test_size=.4, stratify=y, random_state=0)
    Xva, Xte, yva, yte = train_test_split(Xt, yt, test_size=.5, stratify=yt, random_state=0)
    iso = IsolationForest(n_estimators=100, random_state=0).fit(Xtr[ytr == 0])
    s = lambda M: -iso.score_samples(M)
    sv = s(Xva); bv = (yva != 0).astype(int)
    thr = min(np.quantile(sv[bv == 0], .95), np.quantile(sv, .5))  # <=5% FPR on validation normals
    rf = RandomForestClassifier(150, min_samples_leaf=2, class_weight="balanced", random_state=0, n_jobs=1).fit(Xtr, ytr)
    pr = rf.predict(Xte)
    meta = dict(version=VERSION, iso_threshold=float(thr), classes=FLOW_CLASSES, features=FLOW_FEATS, seed=seed,
                normal_mean=Xtr[ytr == 0].mean(0).tolist(), normal_std=(Xtr[ytr == 0].std(0) + 1e-6).tolist(),
                sizes=dict(train=len(Xtr), val=len(Xva), test=len(Xte)),
                test_iforest_normal_vs_suspicious=binary_metrics((yte != 0).astype(int), s(Xte), thr),
                test_rf_normal_vs_suspicious=binary_metrics((yte != 0).astype(int), (pr != 0).astype(int), .5),
                test_rf_report=classification_report(yte, pr, target_names=FLOW_CLASSES, output_dict=True, zero_division=0),
                test_rf_confusion_matrix=confusion_matrix(yte, pr).tolist(),
                data_note="SYNTHETIC flows (generator in data/synth.py); not real traffic, not CIC-IDS/UNSW")
    joblib.dump(dict(iso=iso, rf=rf, meta=meta), MODELS / "net_model.joblib")
    (RESULTS / "net_metrics.json").write_text(json.dumps(meta, indent=1))
    return meta

class NetEngine:
    def __init__(self):
        d = joblib.load(MODELS / "net_model.joblib"); self.iso, self.rf, self.meta = d["iso"], d["rf"], d["meta"]
    def scan(self, flow: dict):
        x = [float(flow[k]) for k in FLOW_FEATS]; f = LOGF([x])
        a = float(-self.iso.score_samples(f)[0]); pr = self.rf.predict_proba(f)[0]; k = int(pr.argmax())
        z = (f[0] - np.array(self.meta["normal_mean"])) / np.array(self.meta["normal_std"])
        ind = [{"feature": FLOW_FEATS[i], "value": x[i], "z_vs_normal": round(float(z[i]), 2)} for i in np.argsort(-np.abs(z))[:4] if abs(z[i]) > 2]
        sus = k != 0 or a >= self.meta["iso_threshold"]
        return dict(engine="network", probability=float(1 - pr[0]), anomaly_score=a, threshold=self.meta["iso_threshold"],
                    label=FLOW_CLASSES[k] if k != 0 else ("anomalous" if sus else "normal"), indicators=ind)
