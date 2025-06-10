import json
import requests
import time
import os
import re

# Splunk HEC Configuration
SPLUNK_URL = "https://prd-p-p06ft.splunkcloud.com:8088"
SPLUNK_TOKEN = "3cc650c4-4d3e-45b2-bfa8-d2f20b96c9bb"

# Directory to monitor
MONITOR_DIR = "processed"  # Change this to your directory path
UPLOADED_FILES_LIST = "./txtDriver/uploaded_files.txt"
CHECK_INTERVAL = 2  # Time in seconds to check for new files

# Headers for the request
headers = {
    "Authorization": f"Splunk {SPLUNK_TOKEN}",
    "Content-Type": "application/json"
}

def get_uploaded_files():
    """Retrieve the list of already uploaded files from the tracking file."""
    if not os.path.exists(UPLOADED_FILES_LIST):
        return set()
    with open(UPLOADED_FILES_LIST, "r") as f:
        return set(line.strip() for line in f)

def update_uploaded_files(file_name):
    """Add a file to the uploaded files list."""
    with open(UPLOADED_FILES_LIST, "a") as f:
        f.write(file_name + "\n")

def read_json_file(file_path):
    """Read the JSON file and return its content."""
    try:
        with open(file_path, "r") as file:
            data = json.load(file)
            return data  # Could be a list or a dictionary
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def extract_username(file_name):
    """Extracts the username from the filename before the first underscore."""
    match = re.match(r"(.*?)_", file_name)
    return match.group(1) if match else "unknown"

def send_log_to_splunk(log_data):
    """Send the log data to Splunk HEC."""
    try:
        response = requests.post(f"{SPLUNK_URL}/services/collector", headers=headers, json=log_data, verify=False)
        print(f"Response Code: {response.status_code}")
        print(f"Response Text: {response.text}")
    except Exception as e:
        print(f"Error sending data to Splunk: {e}")

def format_log(json_data, file_name):
    """Format JSON data into a structured log format for Splunk."""
    user_name = extract_username(file_name)
    
    if isinstance(json_data, list):
        logs = []
        for item in json_data:
            logs.append({
                "event": {
                    "timestamp": item.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ")),
                    "phishing_result": item.get("phishing_result", {}),
                    "bert_result": item.get("bert_result", {}),
                    "creen_result": item.get("creen_result", []),
                    "threat_result": item.get("threat_result", []),
                    "user": user_name  # Adding extracted user field
                },
                "sourcetype": "_json",
                "index": "main"
            })
        return logs

    return [{
        "event": {
            "timestamp": json_data.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ")),
            "phishing_result": json_data.get("phishing_result", {}),
            "bert_result": json_data.get("bert_result", {}),
            "creen_result": json_data.get("creen_result", []),
            "threat_result": json_data.get("threat_result", []),
            "user": user_name  # Adding extracted user field
        },
        "sourcetype": "_json",
        "index": "main"
    }]

def monitor_directory():
    """Monitor the directory for new JSON files and upload them to Splunk."""
    uploaded_files = get_uploaded_files()

    while True:
        json_files = [f for f in os.listdir(MONITOR_DIR) if f.endswith(".json")]

        for file_name in json_files:
            if file_name not in uploaded_files:
                print(f"New file detected: {file_name}. Uploading to Splunk...")

                json_data = read_json_file(os.path.join(MONITOR_DIR, file_name))
                if json_data is not None:
                    structured_logs = format_log(json_data, file_name)
                    
                    if isinstance(structured_logs, list):
                        for log in structured_logs:
                            send_log_to_splunk(log)
                    else:
                        send_log_to_splunk(structured_logs)

                    update_uploaded_files(file_name)
                    uploaded_files.add(file_name)

        time.sleep(CHECK_INTERVAL)

# Run the monitoring function
monitor_directory()