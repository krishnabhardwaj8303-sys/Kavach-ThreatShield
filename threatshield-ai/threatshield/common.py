"""Shared paths, versioning, metrics."""
from pathlib import Path
import numpy as np, zlib
ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "models"
RESULTS = ROOT / "evaluation" / "results"
VERSION = "0.1.0"

def bucket(key: str, n: int = 10) -> int:
    return zlib.crc32(key.encode()) % n

def binary_metrics(y, p, thr=0.5):
    y = np.asarray(y); pred = (np.asarray(p) >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    d = lambda a, b: a / b if b else 0.0
    pr, rc = d(tp, tp + fp), d(tp, tp + fn)
    return dict(threshold=float(thr), accuracy=d(tp + tn, len(y)), precision=pr, recall=rc,
                f1=d(2 * pr * rc, pr + rc), fpr=d(fp, fp + tn), fnr=d(fn, fn + tp),
                confusion_matrix=[[tn, fp], [fn, tp]], n=int(len(y)))

def pick_threshold(y, p, min_recall=0.95):
    """Highest threshold on VALIDATION data that still reaches min_recall."""
    best = 0.5
    for t in np.linspace(0.02, 0.98, 97):
        if binary_metrics(y, p, t)["recall"] >= min_recall:
            best = float(t)
    return best

def brier(y, p):
    return float(np.mean((np.asarray(p) - np.asarray(y)) ** 2))
