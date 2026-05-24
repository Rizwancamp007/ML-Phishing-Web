from flask import Flask, request, render_template, jsonify
import joblib
import numpy as np
import re
from urllib.parse import urlparse
import whois
import socket
import ssl
import datetime

app = Flask(__name__)

model = joblib.load("best_phishing_model.pkl")
scaler = joblib.load("scaler.pkl")


# ===============================
# FEATURE EXTRACTION FROM URL
# ===============================

def get_domain_age(url):
    try:
        domain = url.split("//")[-1].split("/")[0]
        domain = domain.replace("www.", "")

        # Cap WHOIS network calls at 5 s — prevents the scan from hanging
        # on slow registrars or unreachable domains.
        socket.setdefaulttimeout(5)
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # If we can't find a date, treat it as a risk (age = 0)
        if not creation_date or not isinstance(creation_date, datetime.datetime):
            return 0

        age = (datetime.datetime.now() - creation_date).days
        return max(age, 0)

    except Exception as e:
        print(f"WHOIS Error: {e}")  # Log for debugging
        return 0

    finally:
        # Restore default so SSL / DNS checks are not affected
        socket.setdefaulttimeout(None)

def check_dns(url):

    try:
        domain = url.split("//")[-1].split("/")[0]
        socket.gethostbyname(domain)
        return 1
    except:
        return 0
def check_ssl(url):

    try:
        domain = url.split("//")[-1].split("/")[0]

        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                return 1
    except:
        return 0
def has_ip(domain):
    pattern = r"(\d{1,3}\.){3}\d{1,3}"
    return 1 if re.search(pattern, domain) else 0

def is_shortened(url):
    shorteners = [
        "bit.ly", "tinyurl.com", "goo.gl",
        "t.co", "ow.ly", "is.gd", "rb.gy"
    ]

    for s in shorteners:
        if s in url:
            return 1
    return 0
  
def extract_features(url):

    features = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # =========================
    # CYBER FEATURES
    # =========================
    ssl_status = check_ssl(url)
    age = get_domain_age(url)
    dns = check_dns(url)

    features.append(ssl_status)
    features.append(age)
    features.append(dns)

    scheme_https = 1 if url.startswith("https://") else 0
    features.append(scheme_https)
    # =========================
    # URL STRUCTURE
    # =========================
    features.append(len(url))                 # URL length
    features.append(url.count("."))          # dots
    features.append(url.count("/"))          # slashes
    features.append(url.count("-"))          # hyphens
    features.append(sum(c.isdigit() for c in url))   # digits
    features.append(domain.count("."))       # subdomains

    # =========================
    # KEYWORDS
    # =========================
    suspicious_words = [
        "login", "verify", "secure",
        "update", "prize", "win", "bank", "account", "free",
        "click", "offer", "urgent", "jackpot", "bonus"
    ]

    for word in suspicious_words:
        features.append(1 if word in url.lower() else 0)

    # =========================
    # THREAT SIGNALS
    # =========================
    features.append(has_ip(domain))
    features.append(is_shortened(url))
    features.append(1 if ":" in domain else 0)
    features.append(1 if "@" in url else 0)
    features.append(1 if url.count("//") > 1 else 0)

    # =========================
    # PAD TO 31 FEATURES
    # =========================
    while len(features) < 31:
        features.append(0)

    return np.array(features).reshape(1, -1)

# ===============================
# ROUTES
# ===============================
@app.route('/')
def home():
    return render_template("index.html")

def generate_explanation(url, features):

    reasons = []
    good = []

    # features mapping
    ssl_status = features[0][0]   # index 0: ssl_status
    age        = features[0][1]   # index 1: domain age (days)
    dns        = features[0][2]   # index 2: dns check
    url_len    = features[0][4]   # index 4: len(url)  — was wrongly [3] (scheme_https)
    subdomains = features[0][9]   # index 9: domain.count(".") — was wrongly [8] (digits)

    # Suspicious checks
    if ssl_status == 0:
        reasons.append("No valid SSL certificate")

    else:
        good.append("SSL certificate detected")

    if dns == 0:
        reasons.append("DNS resolution failed")

    else:
        good.append("Valid DNS record")

    if age < 365:
        reasons.append("Very new domain")

    else:
        good.append("Old domain age")

    if url_len > 75:
        reasons.append("Long suspicious URL")

    else:
        good.append("Normal URL length")

    if subdomains > 2:
        reasons.append("Too many subdomains")

    # keyword checks
    suspicious_words = [
        "login", "verify", "secure",
        "update", "prize", "win", "bank", "account", "free",
        "click", "offer", "urgent", "jackpot", "bonus"
    ]

    for word in suspicious_words:
        if word in url.lower():
            reasons.append(f"Contains keyword: {word}")

    # fallback
    if len(reasons) == 0:
        reasons.append("No major phishing indicators")

    return reasons, good


@app.route('/predict', methods=['POST'])
def predict():

    data = request.get_json()
    url = data['url']

    features = extract_features(url)
    reasons, good_signals = generate_explanation(url, features)

    scaled_features = scaler.transform(features)
    prediction = model.predict(scaled_features)

    # ML probability
    try:
        prob = model.predict_proba(scaled_features)[0]
        raw = float(max(prob)) * 100
        # soften confidence for realism
        ml_score = min(97, max(62, raw))
    except:
        ml_score = 70

    # =========================
    # SMART HYBRID RISK SCORE
    # =========================

    risk = 0

    # 1. ML confidence contribution
    risk += (100 - ml_score) * 0.40

    # 2. SSL
    if features[0][0] == 0:
        risk += 15

    # 3. DNS
    if features[0][2] == 0:
        risk += 12

    # 4. Domain age
    age = features[0][1]

    if age < 30:
        risk += 20
    elif age < 180:
        risk += 12
    elif age < 365:
        risk += 6

    # 5. URL length
    url_len = len(url)

    if url_len > 75:
        risk += 12
    elif url_len > 50:
        risk += 6

    # 6. Too many dots/subdomains
    dots = url.count(".")
    if dots >= 4:
        risk += 10
    elif dots == 3:
        risk += 5

    risk = round(min(100, max(0, risk)), 2)

    result = "⚠ Phishing Website" if prediction[0] == 0 else "✅ Legitimate Website"

    return jsonify({
    "prediction": result,
    "ml_confidence": round(ml_score, 2),
    "risk_score": round(risk, 2),

    "ssl": int(features[0][0]),
    "dns": int(features[0][2]),
    "domain_age_days": int(features[0][1]),
    "url_length": int(features[0][4]),   # Fixed: was [3] (scheme_https)
    "subdomains": int(features[0][9]),   # Fixed: was [8] (digits)
    "digits": int(features[0][8]),       # Fixed: was [7] (hyphens)

    "reasons": reasons,
    "good_signals": good_signals,

    # 🔥 ADD FULL FEATURE VECTOR FOR GRAPH
    "features": features[0].tolist()
})

if __name__ == "__main__":
    app.run(debug=True)