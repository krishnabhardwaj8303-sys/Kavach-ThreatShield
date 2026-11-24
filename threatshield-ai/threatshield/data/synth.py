"""SYNTHETIC data generators. Metrics on these are NOT real-world accuracy.
Split rules prevent leakage: URLs by registered domain, SMS by template, flows iid."""
import random, numpy as np

SYL = "ka ra mi to ne lu sa vo di pe han bar qui zen tek lon mar pri go fin".split()
BRANDS = "paypal sbi hdfc icici amazon paytm netflix apple google microsoft".split()
KW = "login verify secure update account kyc confirm banking signin wallet".split()
GOOD_TLD = ["com", "org", "in", "net", "co.in", "gov.in", "edu", "io"]
BAD_TLD = ["tk", "xyz", "top", "ml", "click", "info", "ru", "cf"]
PATHW = "home about products news docs help blog pricing contact search store orders".split()

def _w(r, n=None): return "".join(r.choice(SYL) for _ in range(n or r.randint(2, 3)))

def _benign(r):
    host = _w(r) + ("-" + _w(r) if r.random() < .08 else "")
    if r.random() < .1: host = r.choice(BRANDS)
    host += "." + r.choice(GOOD_TLD)
    if r.random() < .3: host = r.choice(["www", "mail", "blog", "docs", "shop"]) + "." + host
    path = "/".join(r.choice(PATHW) for _ in range(r.randint(0, 3)))
    if r.random() < .1: path = r.choice(["account", "login", "signin"]) + "/" + path
    q = f"?id={r.randint(1,99999)}&utm_source={_w(r)}" if r.random() < .2 else ""
    return f"{'https' if r.random() < .9 else 'http'}://{host}/{path}{q}"

def _phish(r):
    k = r.choice(["ip", "brandsub", "hyphen", "longsub", "at", "puny", "clean", "clean"])
    b, kw, w = r.choice(BRANDS), r.choice(KW), _w(r)
    bt, gt = r.choice(BAD_TLD), r.choice(GOOD_TLD)
    sch = "http" if r.random() < .6 else "https"
    if k == "ip": return f"http://{r.randint(1,223)}.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}/{kw}/{w}.php"
    if k == "brandsub": return f"{sch}://{b}.{kw}.{w}.{bt}/{kw}"
    if k == "hyphen": return f"{sch}://{b}-{kw}-{w}.{bt}/"
    if k == "longsub": return f"{sch}://{_w(r)}.{_w(r)}.{kw}.{_w(r)}.{gt}/{kw}?session={r.randint(10**8,10**9)}"
    if k == "at": return f"http://{b}.com@{w}.{bt}/{kw}"
    if k == "puny": return f"{sch}://xn--{w}-{r.randint(100,999)}.{gt}/{kw}"
    return f"https://{w}-{_w(r)}.{gt}/{kw}/{r.choice(PATHW)}"  # hard: clean-looking

def url_dataset(n=12000, seed=7, phish_rate=.3):
    r = random.Random(seed); seen, out = set(), []
    while len(out) < n:
        y = int(r.random() < phish_rate); u = (_phish if y else _benign)(r)
        if u not in seen: seen.add(u); out.append((u, y))
    return out

BANKS = ["SBI", "HDFC", "ICICI", "Axis Bank", "PNB"]
T = {
 "banking": ["Dear customer your {bank} account is blocked. Verify now {link}",
   "{bank} alert: suspicious login detected. Secure your account at {link}",
   "Your {bank} debit card will be deactivated today. Call {ph} immediately",
   "URGENT {bank}: unusual activity on your account, confirm identity {link}",
   "{bank} NetBanking access suspended. Reactivate here {link}"],
 "kyc": ["Your {bank} KYC expires today. Update PAN now {link} or account freezes",
   "KYC pending! Complete e-KYC within 24 hrs {link}",
   "Dear user, Aadhaar-PAN link failed. Update details {link} to avoid block",
   "{bank} re-KYC required. Send documents at {link}",
   "Final notice: KYC verification incomplete, wallet will be closed {link}"],
 "payment": ["Pay Rs {amt} now to avoid penalty, UPI request pending {link}",
   "You received a collect request of Rs {amt}. Approve to get refund {link}",
   "Electricity bill overdue Rs {amt}. Pay today or power cut {link}",
   "Refund of Rs {amt} on hold. Enter UPI PIN to receive {link}",
   "Send Rs {amt} to {ph} to release your pending parcel"],
 "delivery": ["Your parcel is held. Pay customs fee Rs {amt} at {link}",
   "Delivery failed. Reschedule your package {link}",
   "Courier: address incomplete, update within 12 hours {link}",
   "Your order could not be delivered, confirm address {link}",
   "Package #{otp} on hold, small fee required {link}"],
 "otp": ["Your OTP is {otp}. Share it with our agent to complete refund",
   "Do not ignore: tell us the OTP {otp} to cancel the transaction on {bank}",
   "Agent verification: reply with the code {otp} you just received",
   "OTP {otp} for Rs {amt} payment. If not you, call {ph} and read the code",
   "Send the 6 digit code {otp} to confirm your {bank} reward"],
 "prize": ["Congratulations! You won Rs {amt} lottery. Claim at {link}",
   "You are selected for a free iPhone. Claim now {link}",
   "Lucky draw winner! Collect Rs {amt} prize, pay processing fee {link}",
   "Winner notice: gift voucher worth Rs {amt} waiting {link}",
   "Your mobile number won the jackpot, call {ph} to claim"],
 "investment": ["Earn Rs {amt} daily with guaranteed returns. Join our VIP group {link}",
   "Double your money in 7 days, crypto trading tips {link}",
   "Stock tip: 300% profit assured, limited seats {link}",
   "Work from home, earn Rs {amt} per task, message {ph}",
   "Exclusive IPO allotment guaranteed profit, deposit now {link}"],
 "phishing": ["Your account password expires today, sign in to keep access {link}",
   "Unusual sign-in on your email. Review activity {link}",
   "Tax refund available, submit bank details {link}",
   "Netflix payment failed. Update billing {link}",
   "Your SIM will be blocked, verify your number {link}"],
 "legit": ["Your OTP for login is {otp}. Do not share it with anyone. -{bank}",
   "Rs {amt} debited from A/c XX{otp} on 12-Nov. Avl bal updated. -{bank}",
   "Hi {name}, are we still meeting for lunch at 1?",
   "Your order has been delivered. Thank you for shopping with us",
   "Reminder: your appointment is tomorrow at 10 AM",
   "Happy birthday {name}! Hope you have a great day",
   "Your electricity bill of Rs {amt} was paid successfully. Thank you",
   "Mom: call me when you reach home",
   "Your cab is arriving in 3 minutes. Driver {name}",
   "Salary of Rs {amt} credited to your account. -{bank}",
   "Meeting moved to 4pm, see the updated invite in your email",
   "Your package will arrive today between 2 and 5 PM, no action needed"],
}
CATS = list(T)

def _fill(t, r):
    s = t.format(bank=r.choice(BANKS), amt=r.choice([499, 1500, 25000, 5000000, 899]),
        link=r.choice([f"http://bit.ly/{_w(r,2)}{r.randint(1,99)}", f"https://{_w(r)}-{r.choice(KW)}.{r.choice(BAD_TLD)}/x"]),
        otp=r.randint(100000, 999999), name=r.choice(["Anil", "Priya", "Ravi", "Sara"]),
        ph=f"+91{r.randint(7000000000,9999999999)}")
    if r.random() < .3: s = s.lower()
    if r.random() < .2: s = s.replace(".", "").replace(",", "")
    return s

def sms_dataset(per_cat=700, seed=11):
    """Returns (text,label,template_idx). Split by template_idx % 5 -> test templates are unseen."""
    r = random.Random(seed); out = []
    for c in CATS:
        for _ in range(per_cat):
            i = r.randrange(len(T[c])); out.append((_fill(T[c][i], r), c, i))
    return out

FLOW_FEATS = ["duration", "pkts", "bytes_out", "bytes_in", "uniq_ports", "syn_ratio", "pkt_rate", "out_in_ratio"]
FLOW_CLASSES = ["normal", "port_scan", "flood", "exfiltration"]

def flow_dataset(n=8000, seed=5):
    g = np.random.default_rng(seed); rows, ys = [], []
    for _ in range(n):
        c = g.choice(4, p=[.7, .1, .1, .1])
        if c == 0:
            d = g.lognormal(1.5, 1.2); p = g.lognormal(4, 1.0); bo = p * g.lognormal(5.5, .8); bi = p * g.lognormal(6.3, .8)
            up = g.integers(1, 4); syn = g.beta(1, 20)
        elif c == 1:
            d = g.lognormal(1.0, 1.0); p = g.lognormal(4.8, 1.0); bo = p * g.lognormal(3.8, .5); bi = p * g.lognormal(3.0, 1.0)
            up = g.integers(15, 400); syn = g.beta(8, 3)
        elif c == 2:
            d = g.lognormal(1.0, 1.0); p = g.lognormal(8.5, .9); bo = p * g.lognormal(4.2, .4); bi = p * g.lognormal(1.5, 1.0)
            up = g.integers(1, 3); syn = g.beta(6, 4)
        else:
            d = g.lognormal(3.5, 1.0); p = g.lognormal(5.5, 1.0); bo = p * g.lognormal(7.2, .6); bi = p * g.lognormal(4.0, .8)
            up = g.integers(1, 3); syn = g.beta(1, 25)
        d = max(d, .01)
        rows.append([d, p, bo, bi, up, syn, p / d, bo / (bi + 1)]); ys.append(int(c))
    return np.array(rows), np.array(ys)
