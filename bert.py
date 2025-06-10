import json
import re
from transformers import AutoTokenizer, pipeline, AutoModelForSeq2SeqLM
from nltk.tokenize import sent_tokenize

# Load the phishing detection model
MODEL_NAME = "./model/phishing_model"
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
phishing_classifier = pipeline("text-classification", model=MODEL_NAME, tokenizer=tokenizer)

# Load the summarization model
model_directory = "./model/t5_small_model"
tokenizer_summarizer = AutoTokenizer.from_pretrained(model_directory)
model = AutoModelForSeq2SeqLM.from_pretrained(model_directory)
summarizer = pipeline("summarization", model=model, tokenizer=tokenizer_summarizer)


def load_email_from_json(json_file):
    """Load the email data from a JSON file."""
    with open(json_file, 'r') as f:
        email_data = json.load(f)
    return email_data


def chunk_text(text, max_length=500, overlap=100):
    """Split the email body into overlapping chunks for better classification."""
    tokens = tokenizer.encode(text, add_special_tokens=False)
    chunks = []
    
    for i in range(0, len(tokens), max_length - overlap):
        chunk_tokens = tokens[i:i + max_length]
        chunk_text = tokenizer.decode(chunk_tokens)
        chunks.append(chunk_text)
    
    return chunks


def classify_phishing(text):
    """Classify if the given text is phishing or not, returning label and adjusted score."""
    result = phishing_classifier(text)[0]
    raw_score = result["score"]
    adjusted_score = raw_score if result["label"] == "phishing" else 1 - raw_score  # Simple inversion for benign
    return result["label"], adjusted_score

def summarize_text(text):
    """Generate a summary of the email body."""
    summary = summarizer(text, max_length=500, min_length=50, do_sample=False)
    return summary[0]['summary_text']


def analyze_body(body):
    """Analyze the email body for phishing content."""
    summary = summarize_text(body)
    label_summary, score_summary = classify_phishing(summary)
    
    chunks = chunk_text(body)
    chunk_results = []
    total_score = 0
    
    for chunk in chunks:
        label, score = classify_phishing(chunk)
        chunk_results.append({"text": chunk, "label": label, "score": score})
        total_score += score
    
    avg_score = total_score / len(chunks) if chunks else 0
    final_decision = "phishing" if avg_score > 0.5 else "not phishing"
    
    return {
        "summary": summary,
        "summary_classification": {"label": label_summary, "score": score_summary},
        "chunk_analysis": chunk_results,
        "average_chunk_score": avg_score,
        "final_decision": final_decision
    }


def analyze_email(json_file):
    """Analyze an email (from JSON) for phishing risks."""
    email_data = load_email_from_json(json_file)
    body = email_data.get("body", "")
    subject = email_data.get("subject", "")

    # Extract URLs and email addresses
    extracted_ids = re.findall(r'https?://\S+|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
    unique_ids = list(set(extracted_ids))

    # Save unique IDs to a file
    with open("./txtDriver/extracted_links.txt", "w", encoding="utf-8") as file:
        file.write("\n".join(unique_ids) + "\n")

    result = {
        "subject": subject,
        "extracted_links": unique_ids,
        "body_analysis": analyze_body(body),
    }
    
    return result
