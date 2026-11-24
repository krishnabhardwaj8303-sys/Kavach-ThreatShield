"""Reproducible training: python train_all.py"""
from threatshield import url_engine, sms_engine, net_engine
import json
for n, m in [("URL", url_engine), ("SMS", sms_engine), ("NET", net_engine)]:
    meta = m.train(); print(n, "selected:", meta.get("selected", "rf+iforest"))
