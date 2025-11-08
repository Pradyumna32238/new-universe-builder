import os
from dotenv import load_dotenv
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from email.mime.text import MIMEText
import base64

# Load environment variables from .env file
load_dotenv()

# Scope you requested when generating the token
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def load_credentials():
    """Load credentials from environment variables."""
    creds = Credentials(
        token=os.getenv('TOKEN'),
        refresh_token=os.getenv('REFRESH_TOKEN'),
        token_uri=os.getenv('TOKEN_URI'),
        client_id=os.getenv('CLIENT_ID'),
        client_secret=os.getenv('CLIENT_SECRET'),
        scopes=os.getenv('SCOPES').split(',')
    )

    # Refresh if expired
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())

    return creds

def create_message(sender, to, subject, body_text):
    """Create a MIMEText email and encode it for Gmail API."""
    message = MIMEText(body_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw}

def send_message(service, user_id, message):
    """Send an email message via Gmail API."""
    try:
        sent = service.users().messages().send(userId=user_id, body=message).execute()
        print(f"✅ Message sent! ID: {sent['id']}")
    except Exception as error:
        print(f"❌ An error occurred: {error}")

def main():
    creds = load_credentials()
    if not creds:
        print("❌ No valid credentials found in token.json.")
        return

    service = build('gmail', 'v1', credentials=creds)

    sender = "pradyumna32238@gmail.com"   # replace with your Gmail
    to = "fzcznoruz8@ozsaip.com"     # replace with test recipient
    subject = "Test Email from Gmail API"
    body = "Hello! This is a test email sent using Gmail API and token.json."

    message = create_message(sender, to, subject, body)
    send_message(service, 'me', message)

if __name__ == '__main__':
    main()