import os
import time
import json
import datetime
from sentiment import phishing_score, load_email_from_json
from bert import analyze_email
import creen
from threat import analyze_urls_from_file
import json
import imaplib
import base64
directory_to_watch = "./emails/target"
processed_directory = "processed"
os.makedirs(processed_directory, exist_ok=True)





IMAP_SERVER = "imap.gmail.com"

# Account credentials
EMAIL_ACCOUNT = "hackiittest@gmail.com"
PASSWORD = "inrm jczy mzkl vtgu"


def flag_email(file_path):
    # Check if the file exists
    if not os.path.exists(file_path):
        print("File not found. Please check the file name and try again.")
        exit()

    # Extract encoded Message-ID from filename
    json_file = os.path.basename(file_path)  # Extract just the filename
    try:
        encoded_message_id = json_file.split("_email_")[1].replace(".json", "")
    except IndexError:
        print("Invalid filename format. Expected '_email_' in the filename.")
        exit()

    # Decode to get the original Message-ID
    padding = '=' * (-len(encoded_message_id) % 4)  # Add padding back if necessary
    try:
        message_id = base64.urlsafe_b64decode(encoded_message_id + padding).decode()
    except Exception as e:
        print("Error decoding Message-ID:", e)
        exit()

    print("Decoded Message-ID:", message_id)

    # Connect to the Gmail IMAP server
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ACCOUNT, PASSWORD)
    except imaplib.IMAP4.error:
        print("Failed to log in to the email account. Check your credentials.")
        exit()

    # Check if the "Phishing" folder exists, create it if it doesn't
    status, folders = mail.list()
    folder_exists = any(b'"Phishing"' in folder for folder in folders)

    if not folder_exists:
        print("Folder 'Phishing' does not exist. Creating it now...")
        mail.create("Phishing")
    else:
        print("Folder 'Phishing' already exists.")

    # Select the inbox to search for the email
    mail.select("inbox")

    # Search for the email using its Message-ID
    status, messages = mail.search(None, f'HEADER Message-ID "{message_id}"')
    email_ids = messages[0].split()

    if not email_ids:
        print("No email found with the specified Message-ID.")
    else:
        # Move the email to the "Phishing" folder
        for email_id in email_ids:
            mail.store(email_id, '+X-GM-LABELS', 'Phishing')  # Add label
            mail.store(email_id, '+FLAGS', '\\Deleted')  # Mark as deleted from inbox

        print("Email moved to the 'Phishing' folder successfully.")

    # Expunge and close the connection
    mail.expunge()
    mail.close()
    mail.logout()











def process_json_file(file_path):
    try:
        
        # Process email for phishing score
        email_content = load_email_from_json(file_path)
        phishing_result = phishing_score(email_content)
        
        # Process email with BERT model
        bert_result = analyze_email(file_path)
        
        # Process extracted links with creen
        creen_result = creen.process_links_from_file("./txtDriver/extracted_links.txt", "./txtDriver/chromedriver.exe", "static/ssout")
        
        # Process extracted links with threat analysis (No API key required here)
        threat_result = analyze_urls_from_file("./txtDriver/extracted_links.txt", "c36d5e070a99547b93067c7ffc4a5f9213da86e7a336ed283a3c3be0fb4f3c1e")
        
        # Create log entry
        log_entry = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "phishing_result": phishing_result,
            "bert_result": bert_result,
            "creen_result": creen_result,
            "threat_result": threat_result
        }


        # Save to processed directory
        output_file = os.path.join(processed_directory, os.path.basename(file_path))
        with open(output_file, "w") as outfile:
            json.dump(log_entry, outfile, indent=4)
        
        summary_score = bert_result["body_analysis"]["summary_classification"]["score"]

        print("\n\n" + str(summary_score) + "\n\n")  # Convert score to string before concatenation
        print(file_path)

        if summary_score > 0.50:  # No need for parentheses around the condition
            flag_email(file_path)  # Ensure this function is defined


        # Remove original file after processing
        os.remove(file_path)
        print(f"Processed and removed: {file_path}")
    except Exception as e:
        print(f"Error processing {file_path}: {e}")

if __name__ == "__main__":
    while True:
        json_files = [f for f in os.listdir(directory_to_watch) if f.endswith(".json")]
        for json_file in json_files:
            file_path = os.path.join(directory_to_watch, json_file)
            process_json_file(file_path)
        time.sleep(10)  # Check every 10 seconds
