import json
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
from textblob import TextBlob

# Load urgency detection model
model_path = "./model/content/urgency_detection_model"  # Update with actual path
urgency_tokenizer = AutoTokenizer.from_pretrained(model_path)
urgency_model = AutoModelForSequenceClassification.from_pretrained(model_path)
urgency_analyzer = pipeline("text-classification", model=urgency_model, tokenizer=urgency_tokenizer)

def detect_urgency(email_content):
    """
    Detects urgency based on model prediction and keyword presence.
    """
    urgency_keywords = ["urgent", "immediately", "act now", "limited time", "verify", "update", "account locked"]
    urgency_score = sum(1 for word in urgency_keywords if word in email_content.lower()) * 0.5

    model_result = urgency_analyzer(email_content)[0]
    model_score = min(model_result['score'] * 1.5, 1.5) if model_result['label'] == 'LABEL_1' else 0

    return min(model_score + urgency_score, 2)  # Max score = 2

def detect_spelling_errors(email_content):
    """
    Detects spelling/grammar issues using TextBlob.
    """
    blob = TextBlob(email_content)
    corrected_text = str(blob.correct())
    return 1 if corrected_text != email_content else 0

def detect_sensitive_info_requests(email_content):
    """
    Detects sensitive information requests in emails.
    """
    sensitive_keywords = ['password', 'credit card', 'ssn', 'social security number', 'bank account']
    return 2 if any(keyword in email_content.lower() for keyword in sensitive_keywords) else 0

def phishing_score(email_content):
    """
    Calculates phishing score based on multiple parameters.
    """
    urgency_score = detect_urgency(email_content)
    structure_anomaly_score = detect_spelling_errors(email_content)
    sender_reputation_score = detect_sensitive_info_requests(email_content)

    # Weighted scoring
    score = (0.70 * urgency_score) + (0.30 * structure_anomaly_score)

    # Interpret results
    results = {
        "urgency_detected": urgency_score > 0.75,
        "structural_anomaly": structure_anomaly_score > 0.5,
        "phishing_score": score,
        "overall_analysis": "Negative" if score > 1.0 else "Positive"
    }
    return results

def load_email_from_json(json_file_path):
    """
    Loads email content from a JSON file.
    """
    try:
        with open(json_file_path, 'r') as file:
            data = json.load(file)
        return data.get("body", "")
    except FileNotFoundError:
        return "Error: File not found."
    except json.JSONDecodeError:
        return "Error: Invalid JSON format."

