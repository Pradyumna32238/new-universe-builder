
import os
import base64
from email.message import EmailMessage

from flask import redirect, url_for, session, request, current_app
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from werkzeug.wrappers import Response
from google.auth.transport.requests import Request
from dotenv import set_key, find_dotenv
 
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
CLIENT_SECRET_FILE = os.path.join(os.path.dirname(__file__), 'client_secret.json')

def get_gmail_service():
    """Gets a Gmail API service object, handling the OAuth 2.0 flow."""
    creds = None
    
    # Load credentials from environment variables
    token = os.environ.get("TOKEN")
    refresh_token = os.environ.get("REFRESH_TOKEN")
    token_uri = os.environ.get("TOKEN_URI")
    client_id = os.environ.get("CLIENT_ID")
    client_secret = os.environ.get("CLIENT_SECRET")
    scopes = [os.environ.get("SCOPES")]

    if all([token, refresh_token, token_uri, client_id, client_secret, scopes]):
        creds = Credentials(
            token=token,
            refresh_token=refresh_token,
            token_uri=token_uri,
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes
        )

    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            # Save the new token to the .env file
            dotenv_path = find_dotenv()
            set_key(dotenv_path, "TOKEN", creds.token)
        else:
            return redirect(url_for('authorize'))

    service = build("gmail", "v1", credentials=creds)
    return service

def send_email(to: str, subject: str, body: str):
    """Sends an email using the Gmail API."""
    try:
        service = get_gmail_service()

        # If get_gmail_service() returned a redirect, pass it along
        if isinstance(service, Response):
            return service

        message = EmailMessage()
        message.set_content(body)
        message["To"] = to
        message["Subject"] = subject

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {"raw": encoded_message}

        # The user_id is 'me' when using OAuth 2.0 credentials
        service.users().messages().send(userId="me", body=create_message).execute()
    except Exception as e:
        current_app.logger.error(f"Failed to send email to {to}: {e}")
        raise e