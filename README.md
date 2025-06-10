# 🛡️ PhishSOC-AI – AI-Powered Phishing Detection & SOC Integration Suite  

**PhishSOC-AI** is an advanced, AI-driven phishing detection platform designed for **Security Operations Centers (SOC)**. It automates phishing email analysis through multi-layered inspection—combining **NLP-based sentiment classification**, **threat intelligence enrichment**, **screenshot forensics**, and **real-time Splunk integration**—to generate a consolidated **phishing threat score**.  

---

## ✨ Key Features  

| Feature                      | Description                                                                 |
|------------------------------|-----------------------------------------------------------------------------|
| **📧 Email Content Analysis** | NLP transformers detect phishing cues (e.g., urgency, impersonation).      |
| **🔍 Threat Intelligence**   | Enriches domains/IPs/URLs with threat feeds (e.g., VirusTotal, AbuseIPDB). |
| **😠 Sentiment Detection**   | Identifies manipulative language (e.g., "Urgent action required!").        |
| **📸 Screenshot Analysis**   | Custom CV models detect visual phishing (fake login pages, brand spoofing).|
| **📊 Splunk Integration**    | Forwards structured alerts to Splunk via HEC for SOC workflows.            |
| **📈 Unified Dashboard**     | Local Flask UI displays threat scores, analysis metadata, and trends.      |

---

## 🏗️ Project Architecture  

```bash
PhishSOC-AI/
├── app/                      # Flask dashboard and API endpoints
│   ├── static/               # JS/CSS assets
│   └── templates/            # HTML frontend
├── core/                     # Analysis modules
│   ├── analyzer.py           # Orchestrates scoring pipeline
│   ├── sentiment.py          # NLP phishing classifier (BERT/RoBERTa)
│   └── screenshot_ai.py      # OpenCV/TensorFlow visual detection
├── integrations/
│   ├── splunk_hec.py         # Splunk HEC event forwarding
│   └── email_parser.py       # MIME/EML parsing (Exchange/IMAP)
├── model/                    # Custom-trained ML models (⚠️ excluded)
├── tests/                    # Unit/integration tests
├── requirements.txt          # Python dependencies
└── config.yaml               # API keys, Splunk HEC, model paths
```

---

## 🚀 Deployment Guide  

### Prerequisites  
- Python 3.10+  
- Splunk HEC (for integration)  
- GPU recommended for screenshot analysis  

### 1. Clone & Setup  
```bash
git clone https://github.com/aarshx05/PhishSOC-AI.git
cd PhishSOC-AI
python -m venv venv && source venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

### 2. Configure Secrets  
Edit `config.yaml`:  
```yaml
splunk:
  hec_url: "https://your-splunk:8088"
  hec_token: "xxxx-xxxx"  
threat_intel:
  virustotal_api_key: "YOUR_VT_KEY"
```

### 3. Request Model Access  
Email **[aarsh.chaurasia.201007@gmail.com](mailto:aarsh.chaurasia.201007@gmail.com)** with subject:  
`PhishSOC-AI Model Access Request`  
Place downloaded models in `/model/`.  

### 4. Launch  
```bash
flask run --host=0.0.0.0  # Starts dashboard (http://localhost:5000)
python core/analyzer.py   # Runs analysis pipeline
```

---

## 🔌 Splunk Integration  
![Splunk Dashboard Example](https://github.com/user-attachments/assets/8fdb3b17-6188-4116-981c-88ab835232ec)  
Events are forwarded as JSON:  
```json
{
  "threat_score": 0.92,
  "sender_ip": "185.143.223.1", 
  "indicators": ["fake-login.microsoft.com"],
  "sentiment": "high_urgency"
}
```

---

## 🛠️ Tech Stack  
- **ML/NLP**: HuggingFace Transformers, TensorFlow/Keras  
- **Computer Vision**: OpenCV, Pillow  
- **Backend**: Flask, Python 3.10  
- **Threat Intel**: VirusTotal, AbuseIPDB APIs  
- **SOC Integration**: Splunk HEC  

---

## 📜 License  
**Research/Educational Use Only** – Commercial use prohibited.  

---

## 📬 Contact  
For contributions or issues:  
- **Email**: [aarsh.chaurasia.201007@gmail.com](mailto:aarsh.chaurasia.201007@gmail.com)  
- **GitHub Issues**: [https://github.com/aarshx05/PhishSOC-AI/issues](https://github.com/aarshx05/PhishSOC-AI/issues)  

---

### ✨ Contributors Welcome!  
Submit PRs or open discussions for feature requests.  

--- 
