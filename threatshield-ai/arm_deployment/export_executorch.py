"""Train a small MLP flow classifier (torch), export to ExecuTorch .pte (fp32 portable; XNNPACK int8 attempted),
run the .pte with the ExecuTorch runtime on THIS machine (x86_64) and compare with torch.
Run: PYTHONPATH=. python arm_deployment/export_executorch.py"""
import json, time, os, traceback, numpy as np, torch
from sklearn.model_selection import train_test_split
from threatshield.data.synth import flow_dataset
from threatshield.common import MODELS, RESULTS
from threatshield.net_engine import LOGF
torch.manual_seed(0)
X, y = flow_dataset(); F = LOGF(X).astype(np.float32); mu, sd = F.mean(0), F.std(0) + 1e-6
Xtr, Xt, ytr, yt = train_test_split((F - mu) / sd, y, test_size=.4, stratify=y, random_state=0)
Xva, Xte, yva, yte = train_test_split(Xt, yt, test_size=.5, stratify=yt, random_state=0)
net = torch.nn.Sequential(torch.nn.Linear(8, 32), torch.nn.ReLU(), torch.nn.Linear(32, 16), torch.nn.ReLU(), torch.nn.Linear(16, 4))
opt = torch.optim.Adam(net.parameters(), 1e-2); lf = torch.nn.CrossEntropyLoss()
xt, yt_ = torch.tensor(Xtr), torch.tensor(ytr)
for ep in range(150): opt.zero_grad(); lf(net(xt), yt_).backward(); opt.step()
net.eval(); acc = lambda m, X_, y_: float((m(torch.tensor(X_)).argmax(1).numpy() == y_).mean())
rep = dict(arch=os.uname().machine, torch_val_acc=acc(net, Xva, yva), torch_test_acc=acc(net, Xte, yte),
           torch_state_dict_kb=round(len(__import__("pickle").dumps(net.state_dict())) / 1024, 1))
ex = (torch.zeros(1, 8),)
from executorch.exir import to_edge
def export(prog, name):
    et = prog.to_executorch(); p = MODELS / name; p.write_bytes(et.buffer); return p
def run_pte(p):
    from executorch.runtime import Runtime
    m = Runtime.get().load_program(str(p)).load_method("forward"); out = []; t = []
    for r in Xte[:300]:
        s = time.perf_counter(); o = m.execute([torch.tensor(r[None])])[0]; t.append((time.perf_counter() - s) * 1000); out.append(int(o.argmax()))
    return float((np.array(out) == yte[:300]).mean()), float(np.percentile(t, 50)), float(np.percentile(t, 95))
try:
    p = export(to_edge(torch.export.export(net, ex)), "flow_mlp_fp32.pte"); a, p50, p95 = run_pte(p)
    rep["fp32_portable"] = dict(pte_kb=round(p.stat().st_size / 1024, 1), runtime_acc_first300=a, p50_ms=p50, p95_ms=p95)
except Exception: rep["fp32_portable"] = dict(error=traceback.format_exc()[-600:])
try:
    from executorch.backends.xnnpack.partition.xnnpack_partitioner import XnnpackPartitioner
    p = export(to_edge(torch.export.export(net, ex)).to_backend(XnnpackPartitioner()), "flow_mlp_xnnpack_fp32.pte"); a, p50, p95 = run_pte(p)
    rep["xnnpack_fp32"] = dict(pte_kb=round(p.stat().st_size / 1024, 1), runtime_acc_first300=a, p50_ms=p50, p95_ms=p95)
except Exception: rep["xnnpack_fp32"] = dict(error=traceback.format_exc()[-600:])
try:
    from torchao.quantization.pt2e.quantize_pt2e import prepare_pt2e, convert_pt2e
    from executorch.backends.xnnpack.quantizer.xnnpack_quantizer import XNNPACKQuantizer, get_symmetric_quantization_config
    from executorch.backends.xnnpack.partition.xnnpack_partitioner import XnnpackPartitioner
    q = XNNPACKQuantizer().set_global(get_symmetric_quantization_config())
    g = torch.export.export(net, ex).module(); g = prepare_pt2e(g, q); [g(torch.tensor(r[None])) for r in Xtr[:200]]; g = convert_pt2e(g)
    p = export(to_edge(torch.export.export(g, ex)).to_backend(XnnpackPartitioner()), "flow_mlp_xnnpack_int8.pte"); a, p50, p95 = run_pte(p)
    rep["xnnpack_int8"] = dict(pte_kb=round(p.stat().st_size / 1024, 1), runtime_acc_first300=a, p50_ms=p50, p95_ms=p95)
except Exception: rep["xnnpack_int8"] = dict(error=traceback.format_exc()[-600:])
rep["scope"] = ("Executed on x86_64 desktop with ExecuTorch runtime. ARM compatibility NOT verified on ARM silicon or QEMU. "
                "Only the network-flow MLP is exported; URL/SMS sklearn models are not ExecuTorch-exported.")
d = RESULTS / "deployment_report.json"; full = json.loads(d.read_text()) if d.exists() else {}
full["executorch"] = rep; d.write_text(json.dumps(full, indent=1)); print(json.dumps(rep, indent=1))
