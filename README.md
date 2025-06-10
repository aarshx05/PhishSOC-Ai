```markdown
# 🛡️ PhishSOC-Ai — Phishing Detection & SOC Integration Suite

PhishSOC-Ai is a comprehensive AI-powered phishing detection system designed for use in **Security Operations Centers (SOCs)**. It combines **screenshot analysis**, **email sentiment classification**, **threat intelligence enrichment**, and **real-time Splunk integration** to generate a **compounded phishing threat score**.

---

## 🧠 What It Does

PhishSOC-Ai automates the triage and analysis of suspected phishing emails with custom-trained models and intelligent logic across multiple layers of inspection:

- ✅ **Email content analysis** via NLP transformers  
- 🧾 **Threat intelligence** based on domains, IPs, and URLs  
- 😠 **Sentiment detection** to assess urgency or manipulation  
- 📷 **Screenshot processing** to detect visual phishing tricks  
- 📡 **Real-time data forwarding to Splunk**  
- 📊 **Unified phishing score** shown on a local dashboard

---

## 🗂️ Project Structure

```

PhishSOC-Ai/
├── app.py                  # Web dashboard and main orchestration
├── analyze.py              # Full analysis logic
├── sentiment.py            # NLP sentiment/phishing classification
├── emails/
│   └── new\_mtp.py          # Email fetching and parsing
├── splunk.py               # Integration with Splunk
├── model/                  # 🔒 Custom ML models (excluded)
├── requirements.txt        # Python dependencies
├── README.md
└── .gitignore

````

---

## 🚀 Quick Start Guide

### 1. Clone the Repository

```bash
git clone https://github.com/aarshx05/PhishSOC-Ai.git
cd PhishSOC-Ai
````

### 2. Setup Virtual Environment (Recommended)

Using Conda:

```bash
conda create -n phishsoc-env python=3.10
conda activate phishsoc-env
```

Or using `venv`:

```bash
python -m venv phishsoc-env
phishsoc-env\Scripts\activate   # On Windows
```

### 3. Install Required Packages

```bash
pip install -r requirements.txt
```

---

## 📁 Model Folder Access

The `model/` directory includes **custom-tuned models** for phishing detection and screenshot analysis. Due to size and licensing restrictions, it is **not included in this repository**.

📥 To get access, please send an email to:

> **[aarsh.chaurasia.201007@gmail.com](mailto:aarsh.chaurasia.201007@gmail.com)**
> Subject: `Request: PhishSOC-Ai model folder`

Once you receive the archive:

1. Extract it to the project root (so it creates `PhishSOC-Ai/model/`)
2. Ensure model paths are preserved as expected.

---

## 🧪 Running the System

After setting everything up:

```bash
python app.py             # Launches the dashboard
python emails/new_mtp.py  # Parses emails and saves metadata
python splunk.py          # Sends events to Splunk
python analyze.py         # Core phishing analysis pipeline
```

Then open your browser at:
**`http://localhost:5000/`**

---

## 📷 Screenshot / Analysis Flow

> 
![image](https://github.com/user-attachments/assets/046bec6f-b466-4258-9a39-f798ed054aed)
![image](https://github.com/user-attachments/assets/8fdb3b17-6188-4116-981c-88ab835232ec)

---

## 🔗 Splunk Integration

PhishSOC-Ai supports forwarding parsed and scored phishing events to **Splunk Enterprise or Splunk Cloud** using HTTP Event Collector (HEC). Modify the `splunk.py` file to include your Splunk HEC token and URL:

```python
SPLUNK_HEC_URL = 'https://your-splunk-instance:8088'
SPLUNK_TOKEN = 'Your_HEC_Token'
```

---

## 🛠 Dependencies

Key Python packages used:

* `transformers` (HuggingFace)
* `scikit-learn`, `pandas`, `numpy`
* `opencv-python`, `Pillow`
* `flask`, `requests`
* `tensorflow` or `torch` (depending on your model backend)
* `splunk-sdk` (for integration)

---

## 📄 License

This project is for **educational and research purposes only**. Commercial or malicious use is strictly prohibited.

---

## 🤝 Contributions

Pull requests and improvements are welcome.
Just open an issue or fork the project!

---

```

---
