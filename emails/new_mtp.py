import imaplib
import email
import json
import os
import time
import base64
import secrets
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

# Email accounts to monitor
ACCOUNTS = [
    {"username": "hackiittest", "email": "hackiittest@gmail.com", "password": "inrm jczy mzkl vtgu"}
]

# Directory to store email JSON files
OUTPUT_DIR = "target"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Generate a random AES-256 key (store securely)
AES_KEY = secrets.token_bytes(32)

# AES-256 encryption function
def encrypt_aes256(plaintext, key):
    """Encrypts text using AES-256-CBC mode."""
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode()

# Function to get the last email Message-ID
def get_last_message_id(mail):
    """Returns the Message-ID of the last email in the inbox."""
    mail.select("inbox")
    status, messages = mail.search(None, "UNSEEN")
    email_ids = messages[0].split()
    
    if not email_ids:
        return None
    
    latest_email_id = email_ids[-1]
    status, msg_data = mail.fetch(latest_email_id, "(RFC822)")
    
    for response_part in msg_data:
        if isinstance(response_part, tuple):
            msg = email.message_from_bytes(response_part[1])
            return msg["Message-ID"]
    return None

# Function to process a new email
def process_email(mail, num, username):
    """Fetch and process an email by its UID."""
    status, msg_data = mail.fetch(num, "(RFC822)")
    
    for response_part in msg_data:
        if isinstance(response_part, tuple):
            msg = email.message_from_bytes(response_part[1])
            
            # Extract Message-ID
            message_id = msg["Message-ID"]
            if not message_id:
                return  # Skip emails without a Message-ID
            
            # Encode Message-ID to make it filename-safe
            encoded_message_id = base64.urlsafe_b64encode(message_id.encode()).decode().rstrip("=")
            
            email_data = {
                "message_id": message_id,
                "from": encrypt_aes256(msg["From"], AES_KEY) if msg["From"] else None,
                "to": encrypt_aes256(msg["To"], AES_KEY) if msg["To"] else None,
                "subject": msg["Subject"],
                "date": msg["Date"],
                "body": "",
            }
            
            # Extract email body
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        email_data["body"] = part.get_payload(decode=True).decode(errors="ignore")
            else:
                email_data["body"] = msg.get_payload(decode=True).decode(errors="ignore")
            
            # Save the email as a JSON file
            email_filename = os.path.join(OUTPUT_DIR, f"{username}_email_{encoded_message_id}.json")
            with open(email_filename, "w", encoding="utf-8") as file:
                json.dump(email_data, file, indent=4)

# Function to check and process emails for an account
def check_emails(account):
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(account["email"], account["password"])
    
    # Get the last email Message-ID at script startup
    last_message_id = get_last_message_id(mail)
    
    print(f"\U0001F4E9 Listening for new emails for {account['email']}... (Press Ctrl+C to stop)")
    try:
        while True:
            time.sleep(10)  # Check for new emails every 10 seconds
            
            mail.select("inbox")
            current_last_message_id = get_last_message_id(mail)

            # If a new email arrives (Message-ID changes), process it
            if current_last_message_id and current_last_message_id != last_message_id:
                status, messages = mail.search(None, "ALL")
                email_ids = messages[0].split()
                
                if email_ids:
                    latest_email_id = email_ids[-1]
                    process_email(mail, latest_email_id, account["username"])
                    last_message_id = current_last_message_id  # Update the last processed Message-ID
    
    except KeyboardInterrupt:
        print(f"\n\U0001F4E9 Stopped listening for emails for {account['email']}.")
    
    # Close connection
    mail.logout()

# Start listening for the account
if __name__ == "__main__":
    for acc in ACCOUNTS:
        check_emails(acc)
