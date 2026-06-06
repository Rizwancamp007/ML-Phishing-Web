# 🛡️ Website Phishing Detection — URL Phishing Classifier

> A machine learning–powered web application that detects phishing URLs in real time using hybrid risk scoring, live cyber signal analysis, and an interactive visual interface.

---

## 📌 Overview

Phishing attacks remain one of the most common cyber threats, tricking users into revealing sensitive information by mimicking legitimate websites. This project combines **static URL feature extraction** with **real-time cyber signal analysis** (SSL, DNS, WHOIS domain age) to classify websites as phishing or legitimate.

---

## ✨ Features

- 🔍 **Real-time URL scanning** via a Flask REST API
- 🤖 **Machine Learning classifier** — Decision Tree with 92% accuracy
- 📊 **Hybrid Risk Score (0–100)** combining ML confidence + live cyber signals
- 🔐 **SSL / DNS / WHOIS** domain age verification
- 📈 **Interactive signal breakdown chart** (Chart.js)
- 💡 **Explainable output** — plain-language risk reasons and safe signals
- 🎨 **Modern responsive UI** with animated risk meter and pulse alerts

---

## 🧠 Machine Learning Models

| Model | Accuracy | Precision | Recall | F1-Score |
|---|---|---|---|---|
| **Decision Tree** ✅ | **92%** | **0.96** | **0.86** | **0.91** |
| K-Nearest Neighbors | ~90% | 0.93 | 0.85 | 0.89 |
| Logistic Regression | ~88% | 0.91 | 0.83 | 0.87 |

> The **Decision Tree** was selected as the best model and deployed in the Flask application.

---

## 📂 Dataset

| Property | Value |
|---|---|
| Source | UCI ML Repository — Phishing Websites Dataset |
| Total Records | 11,055 websites |
| Features | 31 input features + 1 label |
| Phishing samples | 4,898 (label = 0) |
| Legitimate samples | 6,157 (label = 1) |
| Missing values | None |

---

## ⚙️ System Architecture

```
URL Input
   │
   ▼
urlparse → SSL Check → DNS Check → WHOIS Age → URL Heuristics → Keyword Scan
   │
   ▼
numpy array → StandardScaler → Decision Tree Model
   │
   ▼
ML Probability + Cyber Signals → Hybrid Risk Score (0–100)
   │
   ▼
Flask API Response → Web UI (Verdict + Risk Meter + Chart)
```

---

## 🚀 Getting Started

### Prerequisites

```bash
Python 3.8+
pip
```

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/phishing-detection.git
cd phishing-detection

# Install dependencies
pip install -r requirements.txt
```

### Run the App

```bash
python app.py
```

Then open your browser at `http://localhost:5000`

---

## 🌐 API Usage

**Endpoint:** `POST /predict`

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "prediction": "Legitimate",
  "risk_score": 18.5,
  "ssl": true,
  "dns": true,
  "domain_age_days": 4200,
  "url_length": 19,
  "subdomains": 0,
  "reasons": [],
  "good_signals": ["Valid SSL certificate", "DNS resolves", "Established domain"]
}
```

---

## 📊 Risk Score Thresholds

| Score | Verdict | Indicator |
|---|---|---|
| 0 – 34 | ✅ Legitimate Website | 🟢 Green |
| 35 – 49 | ⚠️ Low Risk / Caution | 🟡 Yellow |
| 50 – 74 | 🔶 Suspicious Website | 🟠 Amber |
| 75 – 100 | 🚨 High Risk Phishing | 🔴 Red (pulse) |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| ML Training | Python, scikit-learn, joblib |
| Backend API | Flask |
| Feature Extraction | socket, ssl, whois, re |
| Frontend | HTML / CSS / JavaScript |
| Charts | Chart.js |
| Data | pandas, numpy |

---

## 📁 Project Structure

```
phishing-detection/
│
├── app.py                      # Flask backend & feature extraction
├── phishing_detection.ipynb    # Model training notebook
├── best_phishing_model.pkl     # Trained Decision Tree model
├── scaler.pkl                  # Fitted StandardScaler
├── phishing.csv                # Dataset
├── templates/
│   └── index.html              # Web UI
├── requirements.txt
└── README.md
```

---

## ⚠️ Limitations

- Feature mismatch: model trained on pre-computed dataset; Flask extracts features live (approximation)
- WHOIS lookups add 1–5 seconds latency on slow registrars
- No result caching — repeated scans re-run all network checks
- Model may not generalise to highly novel phishing techniques

---

## 🔮 Future Work

- [ ] Retrain model on URL-derived features matching the Flask extraction pipeline exactly
- [ ] Add Redis/SQLite caching for WHOIS and DNS results
- [ ] Integrate Random Forest / XGBoost for improved robustness
- [ ] Implement cross-validation and ROC-AUC evaluation
- [ ] Deploy with Gunicorn + Nginx for production
- [ ] Build a browser extension for inline URL checking
- [ ] Add user feedback loop to flag incorrect predictions and retrain

---

## 📚 References

1. [UCI ML Repository — Phishing Websites Dataset](https://archive.ics.uci.edu/ml/datasets/phishing+websites)
2. Pedregosa et al. *Scikit-learn: Machine Learning in Python.* JMLR 12 (2011)
3. [Flask Documentation](https://flask.palletsprojects.com/)
4. [Python-whois library](https://pypi.org/project/python-whois/)
5. [Chart.js Documentation](https://www.chartjs.org/docs/)
6. APWG. *Phishing Activity Trends Report, Q4 2023.*
7. Abdelhamid N. et al. *Phishing detection based on machine learning.* IEEE 2014.

---


<p align="center">
  Made with ❤️ and ☕ by <strong>Rizwan Khan</strong>
</p>
