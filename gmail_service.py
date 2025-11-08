
import os
import base64
from email.message import EmailMessage

from flask import redirect, url_for, session, request, current_app
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from werkzeug.wrappers import Response

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
CLIENT_SECRET_FILE = os.path.join(os.path.dirname(__file__), 'client_secret.json')

def get_gmail_service():
    """Gets a Gmail API service object, handling the OAuth 2.0 flow."""
    creds = None

    # created automatically when the authorization flow completes for the first
    # time.
    if 'credentials' in session:
        creds = Credentials(**session['credentials'])

    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        # If the credentials are not valid, it will return a redirect to the auth URL
        return redirect(url_for('authorize'))

    service = build("gmail", "v1", credentials=creds)
    return service

def send_email(to: str, subject: str, body: str):
    """Sends an email using the Gmail API."""
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