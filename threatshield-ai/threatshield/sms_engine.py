"""Scam SMS engine: multiclass TF-IDF (word + char) linear/NB models, split by TEMPLATE for unseen-text testing."""
import re, json, joblib, numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import ComplementNB
from sklearn.metrics import f1_score, classification_report, confusion_matrix
from .common import MODELS, RESULTS, VERSION, binary_metrics, pick_threshold, brier
from .data.synth import sms_dataset, CATS

def clean(t):
    t = t.lower(); t = re.sub(r"https?://\S+|\b\S+\.(tk|xyz|top|ml|click|info|ru|cf)\S*", " URL ", t)
    t = re.sub(r"\+?\d{10,}", " PHONE ", t); t = re.sub(r"\b\d{4,}\b", " NUM ", t)
    return re.sub(r"\s+", " ", t).strip()

class Vec:
    def __init__(self):
        self.w = TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)
        self.c = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True, max_features=30000)
    def fit(self, X): self.w.fit(X); self.c.fit(X); return self
    def transform(self, X): return hstack([self.w.transform(X), self.c.transform(X)]).tocsr()
    def names(self): return list(self.w.get_feature_names_out()) + list(self.c.get_feature_names_out())

def train(seed=11):
    d = sms_dataset(seed=seed)
    part = lambda k: [(clean(t), c) for t, c, i in d if (i % 5 < 3 if k == "tr" else i % 5 == (3 if k == "va" else 4))]
    tr, va, te = part("tr"), part("va"), part("te")
    # NOTE: legit has 12 templates, others 5: i%5 gives disjoint template sets per split for all classes.
    X = lambda s: [t for t, _ in s]; Y = lambda s: np.array([CATS.index(c) for _, c in s])
    v = Vec().fit(X(tr)); Xtr, Xva, Xte = v.transform(X(tr)), v.transform(X(va)), v.transform(X(te))
    ytr, yva, yte = Y(tr), Y(va), Y(te)
    cands = {"logreg_C1": LogisticRegression(C=1, max_iter=3000), "logreg_C10": LogisticRegression(C=10, max_iter=3000),
             "complement_nb": ComplementNB(alpha=.3)}
    val = {}
    for n, m in cands.items():
        m.fit(Xtr, ytr); val[n] = float(f1_score(yva, m.predict(Xva), average="macro"))
    best = max(val, key=val.get)
    lr = cands["logreg_C10"] if val["logreg_C10"] >= val["logreg_C1"] else cands["logreg_C1"]  # explainable linear model
    final = cands[best]; li = CATS.index("legit")
    sc = lambda m, Xm: 1 - m.predict_proba(Xm)[:, li]
    thr = pick_threshold((yva != li).astype(int), sc(final, Xva), .97)
    pte = final.predict_proba(Xte); pred = pte.argmax(1)
    meta = dict(version=VERSION, selected=best, validation_macro_f1=val, scam_threshold=thr, classes=CATS, seed=seed,
                sizes=dict(train=len(tr), val=len(va), test=len(te)),
                test_macro_f1=float(f1_score(yte, pred, average="macro")),
                test_report=classification_report(yte, pred, target_names=CATS, output_dict=True, zero_division=0),
                test_confusion_matrix=confusion_matrix(yte, pred).tolist(),
                test_scam_vs_legit=binary_metrics((yte != li).astype(int), sc(final, Xte), thr),
                data_note="SYNTHETIC template-generated SMS; test templates unseen in training; not real-world accuracy")
    joblib.dump(dict(vec=v, final=final, lr=lr, meta=meta), MODELS / "sms_model.joblib")
    (RESULTS / "sms_metrics.json").write_text(json.dumps(meta, indent=1))
    return meta

class SmsEngine:
    def __init__(self):
        d = joblib.load(MODELS / "sms_model.joblib"); self.v, self.m, self.lr, self.meta = d["vec"], d["final"], d["lr"], d["meta"]
        self.fn = np.array(self.v.names()); self.li = CATS.index("legit")
    def scan(self, text):
        x = self.v.transform([clean(text)]); pr = self.m.predict_proba(x)[0]; k = int(pr.argmax())
        scam_p = float(1 - pr[self.li]); thr = self.meta["scam_threshold"]
        lab = CATS[k] if scam_p >= thr else "legit"
        c = int(self.lr.predict(x)[0]) if lab == "legit" else CATS.index(lab)
        contrib = self.lr.coef_[c] * x.toarray()[0]; idx = np.argsort(-contrib)[:6]
        ind = [{"token": str(self.fn[i]), "weight": round(float(contrib[i]), 4)} for i in idx if contrib[i] > 0 and len(self.fn[i]) > 2][:5]
        return dict(engine="sms", probability=scam_p, threshold=thr, label=lab, class_probabilities={CATS[i]: round(float(p), 4) for i, p in enumerate(pr)}, indicators=ind)
