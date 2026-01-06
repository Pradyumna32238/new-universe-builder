
from __future__ import annotations
from dotenv import load_dotenv, set_key
load_dotenv()
from sb_functions import get_user_by_email
import os
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    jsonify,
    current_app,
    send_from_directory,
    abort,
    Response,
    session,
)
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.mime.text import MIMEText
from flask_caching import Cache
from flask_migrate import Migrate
from PIL import Image
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from sqlalchemy import inspect, text, or_
from urllib.parse import urlparse
from config import config_map
from models import db, User, Universe, Character, UniverseCollaboratorRequest, Issue, Notification, NotificationSettings
import re
import random
import string
import secrets
import datetime
from io import BytesIO
import base64
import math
from gmail_service import send_email
import logging
from logging.handlers import RotatingFileHandler
from flask_cors import CORS

cache = Cache(config={'CACHE_TYPE': 'SimpleCache'})

class CustomPagination:
    def __init__(self, items, page, per_page, total):
        self.items = items
        self.page = page
        self.per_page = per_page
        self.total = total
        self.pages = int(math.ceil(total / per_page)) if total > 0 else 0
        self.has_prev = page > 1
        self.has_next = page < self.pages
        self.prev_num = page - 1 if self.has_prev else None
        self.next_num = page + 1 if self.has_next else None

    def iter_pages(self, left_edge=2, left_current=2, right_current=5, right_edge=2):
        last = 0
        for num in range(1, self.pages + 1):
            if (num <= left_edge or
               (self.page - left_current - 1 < num < self.page + right_current) or
               num > self.pages - right_edge):
                if last + 1 != num:
                    yield None
                yield num
                last = num

# --- Gmail API Configuration ---
def get_credentials_from_env():
    return {
        "web": {
            "client_id": os.getenv("client_id"),
            "project_id": os.getenv("project_id"),
            "auth_uri": os.getenv("auth_uri"),
            "token_uri": os.getenv("token_uri"),
            "auth_provider_x509_cert_url": os.getenv("auth_provider_x509_cert_url"),
            "client_secret": os.getenv("client_secret"),
        }
    }

GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.send']
# -----------------------------

def get_gmail_credentials():
    creds = Credentials(
        token=os.getenv('TOKEN'),
        refresh_token=os.getenv('REFRESH_TOKEN'),
        token_uri=os.getenv('TOKEN_URI'),
        client_id=os.getenv('CLIENT_ID'),
        client_secret=os.getenv('CLIENT_SECRET'),
        scopes=os.getenv('SCOPES').split(',')
    )
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    return creds


USERNAME_MAX_LENGTH = 80
ALLOWED_PROFILE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

def allowed_profile_extension(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_PROFILE_EXTENSIONS

def generate_username_suggestion(username: str) -> str:
    """Generate a unique username suggestion based on the provided input."""
    sanitized = re.sub(r"\s+", "", username)
    sanitized = re.sub(r"[^a-zA-Z0-9]+", "", sanitized)
    if not sanitized:
        sanitized = "user"
    sanitized = sanitized[:USERNAME_MAX_LENGTH]

    # Ensure the sanitized username is at least 5 characters long
    while len(sanitized) < 5:
        sanitized += random.choice(string.ascii_lowercase + string.digits)

    candidate = sanitized
    suffix = 1

    while True:
        user = None
        if current_app.config.get("DATABASE") == "sb":
            from sb_functions import get_user_by_username
            user = get_user_by_username(candidate)
        else:
            user = User.query.filter_by(username=candidate).first()

        if not user:
            break

        suffix_str = str(suffix)
        allowed_length = max(1, USERNAME_MAX_LENGTH - len(suffix_str))
        candidate = f"{sanitized[:allowed_length]}{suffix_str}"
        suffix += 1

    return candidate

def process_image(file_storage) -> tuple[bytes | None, str | None, str | None]:
    """Resize, compress, and convert incoming images to WebP for storage."""
    
    # Check file size (e.g., 2MB limit)
    if file_storage.content_length > 2 * 1024 * 1024:
        return None, None, "Image file size should not exceed 2MB."

    filename = secure_filename(file_storage.filename)
    if not filename:
        return None, None, "Invalid file name."

    if not allowed_profile_extension(filename):
        return None, None, "Unsupported image format. Please upload PNG, JPG, JPEG, GIF, or WEBP files."

    try:
        image = Image.open(file_storage.stream)
        image = image.convert("RGB")  # normalize mode for WebP

        # Preserve aspect ratio while limiting the longest side to 512px
        image.thumbnail((512, 512))

        buffer = BytesIO()
        image.save(buffer, format="WEBP", quality=60, method=6)
        buffer.seek(0)

        return buffer.read(), "image/webp", None
    except Exception:
        return None, None, "Could not process the uploaded image. Please try again with a valid image file."

def send_gmail(to, subject, template, **kwargs):
    creds = get_gmail_credentials()

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                raise Exception(f"Failed to refresh credentials: {e}")
        else:
            raise Exception("Credentials not available or invalid. Please authorize.")

    try:
        service = build("gmail", "v1", credentials=creds)
        html_content = render_template(template + '.html', **kwargs)
        message = MIMEText(html_content, 'html')
        message["To"] = to
        message["Subject"] = subject
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {"raw": encoded_message}
        send_message = service.users().messages().send(userId="me", body=create_message).execute()
        return f"Email sent successfully! Message ID: {send_message['id']}"
    except HttpError as error:
        raise Exception(f"An error occurred: {error}")
    except Exception as e:
        raise Exception(f"An error occurred: {e}")

def send_password_reset_email(user: User) -> None:
    """Send a password reset email with an OTP to the user."""
    user.generate_otp()
    if app.config.get("DATABASE") == "sb":
        from sb_functions import update_user
        update_user(user.id, {'otp_code': user.otp_code, 'otp_expiry': user.otp_expiry})
    else:
        db.session.commit()
    send_gmail(
        to=user.email,
        subject="Reset Your Password",
        template='email/reset_password',
        user=user,
        otp=user.otp_code
    )



def create_app(config_name='default'):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_map[config_name])

    # Initialize extensions
    cache.init_app(app)
    CORS(app)

    if app.config.get("DATABASE") == "sb":
        pass
    else:
        db.init_app(app)
        Migrate(app, db)

    # Configure logging
    if not app.debug:
        if not os.path.exists("logs"):
            os.mkdir("logs")
        file_handler = RotatingFileHandler(
            "logs/universe_builder.log", maxBytes=10240, backupCount=10
        )
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
            )
        )
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info("Universe Builder startup")

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "login"

    @login_manager.user_loader
    def load_user(user_id):
        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_user_by_id
            return get_user_by_id(user_id)
        else:
            return User.query.get(int(user_id))

    with app.app_context():
        if app.config.get("DATABASE") == "sb":
            # Create admin user if it doesn't exist
            from sb_functions import add_user
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
            admin_user = get_user_by_email(admin_email)
            if not admin_user:
                admin_password = os.environ.get('ADMIN_PASSWORD', 'password')
                admin = User(username='admin', email=admin_email, is_admin=True)
                admin.set_password(admin_password)
                add_user(admin)
                print("Supabase admin user created.")
        else:
            db.create_all()

            # Create admin user if it doesn't exist
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
            if not User.query.filter_by(email=admin_email).first():
                admin_password = os.environ.get('ADMIN_PASSWORD', 'password')
                admin = User(username='admin', email=admin_email, is_admin=True)
                admin.set_password(admin_password)
                db.session.add(admin)
                db.session.commit()
                print("Local admin user created.")

        register_routes(app)
        register_error_handlers(app)

    return app


def register_routes(app: Flask) -> None:
    """Register route handlers on the provided Flask app instance."""

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            flash("You are already logged in.", "info")
            return redirect(url_for("index"))

        if request.method == "POST":
            login_identifier = request.form.get("login_identifier", "").strip()
            password = request.form.get("password", "")
            
            if app.config.get("DATABASE") == "sb":
                from sb_functions import get_user_by_username, get_user_by_email
                user = get_user_by_username(login_identifier) or get_user_by_email(login_identifier)
            else:
                user = User.query.filter((User.username == login_identifier) | (User.email == login_identifier)).first()

            if user and user.check_password(password):
                login_user(user)
                flash("Logged in successfully.", "success")
                return redirect(url_for("index"))
            else:
                flash("Invalid username or password.", "error")

        return render_template("login.html")

    @app.route('/send-email-otp', methods=['POST'])
    @login_required
    def send_email_otp():
        new_email = request.json.get('email')
        if not new_email or not re.match(r'[^@]+@[^@]+\.[^@]+', new_email):
            return jsonify({'error': 'Invalid email address'}), 400

        existing_user = None
        if app.config.get("DATABASE") == "sb":
            existing_user = get_user_by_email(new_email)
        else:
            existing_user = User.query.filter_by(email=new_email).first()

        if existing_user and existing_user.id != current_user.id:
            return jsonify({'error': 'Email is already registered'}), 400

        try:
            otp = current_user.generate_otp()

            if app.config.get("DATABASE") == "sb":
                from supabase_client import get_supabase_client
                supabase = get_supabase_client()
                update_data = {
                    'otp_code': current_user.otp_code,
                    'otp_expiry': current_user.otp_expiry.isoformat() if current_user.otp_expiry else None,
                    'new_email': new_email
                }
                supabase.table('user').update(update_data).eq('id', current_user.id).execute()
            else:
                current_user.new_email = new_email
                db.session.commit()

            subject = 'Verify Your New Email Address'
            send_gmail(
                to=new_email,
                subject=subject,
                template='email/verify_new_email',
                user=current_user,
                otp=otp
            )

            return jsonify({'message': 'OTP sent to your new email address'}), 200
        except Exception as e:
            app.logger.error(f'Error sending OTP: {e}')
            return jsonify({'error': str(e)}), 500

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            flash("You are already logged in.", "info")
            return redirect(url_for("index"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            password_confirm = request.form.get("password_confirm", "")

            if not all([username, email, password, password_confirm]):
                flash("All fields are required.", "error")




            if password != password_confirm:
                flash("Passwords do not match.", "error")
                return render_template("register.html")

            is_valid_password, password_errors = User.validate_password_rules(password)
            if not is_valid_password:
                for error_message in password_errors:
                    flash(error_message, "error")
                return render_template("register.html")

            if len(username) < 5:
                flash("Username must be at least 5 characters long.", "error")
                return render_template("register.html")

            if not username.isalnum():
                flash("Username must be alphanumeric.", "error")
                return render_template("register.html")

            if app.config.get("DATABASE") == "sb":
                from sb_functions import get_user_by_username, get_user_by_email
                if get_user_by_username(username):
                    flash("That username is already registered.", "error")
                    return render_template("register.html")
                if get_user_by_email(email):
                    flash("That email is already registered.", "error")
                    return render_template("register.html")
            else:
                if User.query.filter((User.username == username) | (User.email == email)).first():
                    flash("That username or email is already registered.", "error")
                    return render_template("register.html")

            new_user = User(username=username, email=email)
            new_user.set_password(password)
            otp = new_user.generate_otp()
            user_data = {
                "username": username,
                "email": email,
                "password": new_user.password_hash,
                "otp": otp,
            }
            cache.set(email, user_data, timeout=600)  # Store for 10 minutes

            try:
                send_email(
                    to=email,
                    subject="Verify Your Email Address",
                    body=render_template('email/verify_email.html', username=username, otp=otp)
                )
                flash("An OTP has been sent to your email. Please use it to verify your account.", "success")
                return redirect(url_for("verify_email", email=email))
            except Exception as e:
                current_app.logger.error(f"Failed to send verification OTP to {email}: {e}")
                flash("Could not send verification email. Please try again later.", "error")

        return render_template("register.html")


    @app.route("/verify-email", methods=["GET", "POST"])
    def verify_email():
        email = request.args.get("email")
        user_data = cache.get(email)

        if not user_data:
            flash("Invalid or expired verification link.", "error")
            return redirect(url_for("register"))

        if request.method == "POST":
            otp_entered = request.form.get("otp")
            if otp_entered == user_data["otp"]:
                if app.config.get("DATABASE") == "sb":
                    from sb_functions import add_user
                    new_user = User(
                        username=user_data["username"],
                        email=user_data["email"],
                        password_hash=user_data["password"],
                        is_verified=True,
                        email_verified=True
                    )
                    add_user(new_user)
                else:
                    new_user = User(
                        username=user_data["username"],
                        email=user_data["email"],
                        password_hash=user_data["password"],
                        is_verified=True,
                        email_verified=True
                    )
                    db.session.add(new_user)
                    db.session.commit()
                cache.delete(email)
                flash("Account created successfully! Please log in.", "success")
                return redirect(url_for("login"))
            else:
                flash("Invalid OTP. Please try again.", "error")

        return render_template("verify_email.html", email=email)

    @app.route("/api/check-email")
    def check_email():
        email = request.args.get("email", "").strip().lower()
        if not email:
            return jsonify({"available": False}), 400

        user_exists = False
        if current_app.config.get("DATABASE") == "sb":
            if get_user_by_email(email):
                user_exists = True
        else:
            if User.query.filter_by(email=email).first():
                user_exists = True

        return jsonify({"available": not user_exists})

    @app.route("/api/check-username")
    def check_username():
        username = request.args.get("username", "").strip()
        if not username:
            return jsonify({"available": False, "message": "Username cannot be empty."}), 400

        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_user_by_username
            user = get_user_by_username(username)
        else:
            user = User.query.filter(User.username.ilike(username)).first()
        if user:
            suggestion = generate_username_suggestion(username)
            return jsonify({
                "available": False,
                "message": "That username is already taken.",
                "suggestion": suggestion
            })
        return jsonify({"available": True})



    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("index"))

    import smtplib, os

    @app.route("/smtp-test")
    def smtp_test():
        try:
            server = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
            server.starttls()
            server.login(os.getenv("MAIL_USERNAME"), os.getenv("MAIL_PASSWORD"))
            server.quit()
            return "✅ SMTP connection successful!"
        except Exception as e:
            return f"❌ SMTP failed: {e}"



    @app.route('/gmail-api-test')
    def gmail_api_test():
        creds = get_gmail_credentials()
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    from google.auth.transport.requests import Request
                    creds.refresh(Request())
                except Exception as e:
                    flash(f'Error refreshing token: {e}. Please re-authorize.')
                    return redirect(url_for('authorize'))
            else:
                return redirect(url_for('authorize'))
            # The credentials are now managed via environment variables.

        try:
            service = build('gmail', 'v1', credentials=creds)
            message = MIMEText("This is a test email sent from the Gmail API within the Flask app.")
            recipient = os.getenv("MAIL_USERNAME", "fzcznoruz8@ozsaip.com")
            message['To'] = recipient
            message['Subject'] = "Gmail API Test from Flask App"
            
            encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
            create_message = {'raw': encoded_message}
            
            send_message = service.users().messages().send(userId="me", body=create_message).execute()
            
            return f"✅ Gmail API test successful! Message ID: {send_message['id']}"
        except HttpError as error:
            return f"❌ An error occurred: {error}"
        except Exception as e:
            return f"❌ Gmail API test failed: {e}. The token may be invalid. Please try again."


    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    @app.route('/authorize')
    def authorize():
            flow = Flow.from_client_secrets_file(
                'client_secret.json',
                scopes=['https://www.googleapis.com/auth/gmail.send'],
                redirect_uri=url_for('oauth2callback', _external=True))
            authorization_url, state = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true')
            session['state'] = state
            return redirect(authorization_url)


    @app.route('/oauth2callback')
    def oauth2callback():
        state = session['state']
        flow = Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=['https://www.googleapis.com/auth/gmail.send'],
            state=state,
            redirect_uri=url_for('oauth2callback', _external=True))
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        if credentials.refresh_token:
            set_key('.env', 'REFRESH_TOKEN', credentials.refresh_token, quote_mode='never')
        return redirect(url_for('index'))
        
    @app.route('/notifications/clear', methods=['POST'])
    @login_required
    def clear_notifications():
        if app.config.get("DATABASE") == "sb":
            from sb_functions import delete_notifications
            delete_notifications(current_user.id)
        else:
            Notification.query.filter_by(user_id=current_user.id).delete()
            db.session.commit()
        return jsonify({"status": "success"})


    @app.route('/notifications/create', methods=['POST'])
    @login_required
    def create_notification():
        data = request.get_json()
        message = data.get('message')
        if not message:
            return jsonify({"status": "error", "message": "Message is required."})

        created = False
        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_notification_by_message, create_notification
            if not get_notification_by_message(current_user.id, message):
                create_notification(current_user.id, message)
                created = True
        else:
            if not Notification.query.filter_by(user_id=current_user.id, message=message).first():
                notification = Notification(user_id=current_user.id, message=message)
                db.session.add(notification)
                db.session.commit()

                notifications_to_keep = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).limit(5).all()
                notifications_to_delete = Notification.query.filter_by(user_id=current_user.id).filter(Notification.id.notin_([n.id for n in notifications_to_keep])).all()

                for n in notifications_to_delete:
                    db.session.delete(n)
                db.session.commit()
                created = True

        return jsonify({"status": "success", "created": created})


    @app.route("/profile/<username>")
    @login_required
    def profile(username: str):
        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_user_by_username
            user = get_user_by_username(username)
        else:
            user = User.query.filter_by(username=username).first_or_404()
        return render_template("profile.html", user=user)

    @app.route("/settings", methods=['GET', 'POST'])
    @login_required
    def account_settings():
        if request.method == "POST":

            if request.form.get("update_target") == "notifications":
                if app.config.get("DATABASE") == "sb":
                    from sb_functions import get_notification_settings, create_notification_settings, update_notification_settings
                    is_enabled = 'email_notifications' in request.form
                    settings = get_notification_settings(current_user.id)
                    if not settings:
                        create_notification_settings(current_user.id, is_enabled)
                    else:
                        update_notification_settings(current_user.id, is_enabled)
                else:
                    if not current_user.notification_settings:
                        current_user.notification_settings = NotificationSettings(user_id=current_user.id)
                        db.session.add(current_user.notification_settings)
                    is_enabled = 'email_notifications' in request.form
                    current_user.notification_settings.email_notifications = is_enabled
                    db.session.commit()
                return jsonify({"status": "success", "message": "Notification settings updated."})


            update_target = request.form.get("update_target", "").strip()

            try:
                if update_target == "profile-details":
                    if current_user.is_admin:
                        flash("Admin profile details cannot be modified.", "error")
                        return redirect(url_for("account_settings"))
                    new_username = request.form.get("username", "").strip()
                    new_email = request.form.get("email", "").strip().lower()

                    if not new_username or not new_email:
                        flash("Username and email cannot be empty.", "error")
                        return redirect(url_for("account_settings"))

                    if new_username != current_user.username:
                        if app.config['DATABASE'] == 'sb':
                            from sb_functions import get_user_by_username
                            if get_user_by_username(new_username):
                                flash("That username is already taken.", "error")
                                return redirect(url_for("account_settings"))
                            from sb_functions import update_user
                            current_user.username = new_username
                            update_user(current_user.id, {'username': new_username})
                        else:
                            if User.query.filter(User.username == new_username).first():
                                flash("That username is already taken.", "error")
                                return redirect(url_for("account_settings"))
                            current_user.username = new_username
                            db.session.commit()
                        flash("Username updated successfully.", "success")

                    if new_email != current_user.email:
                        if app.config.get("DATABASE") == "sb":
                            from sb_functions import get_user_by_email
                            existing_user = get_user_by_email(new_email)
                        else:
                            existing_user = User.query.filter(User.email == new_email).first()
                        if existing_user:
                            flash("That email is already registered.", "error")
                            return redirect(url_for("account_settings"))


                        # Generate and store OTP for the new email
                        current_user.new_email = new_email

                        current_user.generate_otp()
                        if app.config.get("DATABASE") != "sb":
                            db.session.commit()
                        else:
                            from sb_functions import update_user
                            update_user(current_user.id, {'new_email': new_email, 'otp_code': current_user.otp_code, 'otp_timestamp': datetime.datetime.utcnow()})

                        # Send OTP to the new email address
                        try:
                            send_gmail(
                                to=new_email,
                                subject="Confirm Your New Email Address",
                                template='email/verify_new_email',
                                user=current_user,
                                otp=current_user.otp_code
                            )
                            flash("An OTP has been sent to your new email address. Please verify to complete the change.", "info")
                        except Exception as e:
                            current_app.logger.error(f"Failed to send OTP email to {new_email}: {e}")
                            return jsonify({"error": "Could not send OTP. Please try again later."}), 500

                    if app.config.get("DATABASE") != "sb":
                        db.session.commit()
                    return jsonify({"status": "success", "message": "Profile details updated."})

                if update_target == "profile-picture":
                    if "remove_profile_picture" in request.form:
                        current_user.set_profile_image(None, None)
                        message = "Profile picture removed."
                    else:
                        profile_picture_file = request.files.get("profile_picture")
                        if profile_picture_file and profile_picture_file.filename:
                            image_data, mimetype, error = process_image(profile_picture_file)
                            if error:
                                return jsonify({"status": "error", "message": error})
                            current_user.set_profile_image(image_data, mimetype)
                            message = "Profile picture updated."
                        else:
                            return jsonify({"status": "error", "message": "No profile picture file provided."})

                    if app.config.get("DATABASE") == "sb":
                        from sb_functions import update_user
                        update_user(current_user.id, {'profile_image_url': current_user.profile_image_url})
                    else:
                        db.session.commit()

                    return jsonify({"status": "success", "message": message})

                if update_target == "password":
                    if current_user.is_admin:
                        flash("Admin password cannot be modified.", "error")
                        return redirect(url_for("account_settings"))
                    current_password = request.form.get("current_password", "")
                    new_password = request.form.get("new_password", "")
                    new_password_confirm = request.form.get("confirm_password", "")

                    if not current_password:
                        message = "Enter your current password to change it."
                        if app.config.get("DATABASE") == "sb":
                            from sb_functions import get_notification_by_message, create_notification
                            if not get_notification_by_message(current_user.id, message):
                                create_notification(current_user.id, message)
                        else:
                            if not Notification.query.filter_by(user_id=current_user.id, message=message).first():
                                notification = Notification(user_id=current_user.id, message=message)
                                db.session.add(notification)
                                db.session.commit()
                        return jsonify({"status": "error", "message": message})
                    if not current_user.check_password(current_password):
                        message = "Current password is incorrect."
                        if app.config.get("DATABASE") == "sb":
                            from sb_functions import get_notification_by_message, create_notification
                            if not get_notification_by_message(current_user.id, message):
                                create_notification(current_user.id, message)
                        else:
                            if not Notification.query.filter_by(user_id=current_user.id, message=message).first():
                                notification = Notification(user_id=current_user.id, message=message)
                                db.session.add(notification)
                                db.session.commit()
                        return jsonify({"status": "error", "message": message})
                    if current_user.check_password(new_password):
                        message = "New password cannot be the same as the current password."
                        if app.config.get("DATABASE") == "sb":
                            from sb_functions import get_notification_by_message, create_notification
                            if not get_notification_by_message(current_user.id, message):
                                create_notification(current_user.id, message)
                        else:
                            if not Notification.query.filter_by(user_id=current_user.id, message=message).first():
                                notification = Notification(user_id=current_user.id, message=message)
                                db.session.add(notification)
                            db.session.commit()
                        return jsonify({"status": "error_same_password", "message": message})
                    if new_password != new_password_confirm:
                        message = "New passwords do not match."
                        if app.config.get("DATABASE") == "sb":
                            from sb_functions import get_notification_by_message, create_notification
                            if not get_notification_by_message(current_user.id, message):
                                create_notification(current_user.id, message)
                        else:
                            if not Notification.query.filter_by(user_id=current_user.id, message=message).first():
                                notification = Notification(user_id=current_user.id, message=message)
                                db.session.add(notification)
                                db.session.commit()
                        return jsonify({"status": "error", "message": message})
                    is_valid_password, password_errors = User.validate_password_rules(new_password)
                    if not is_valid_password:
                        for error in password_errors:
                            if app.config.get("DATABASE") == "sb":
                                from sb_functions import get_notification_by_message, create_notification
                                if not get_notification_by_message(current_user.id, error):
                                    create_notification(current_user.id, error)
                            else:
                                if not Notification.query.filter_by(user_id=current_user.id, message=error).first():
                                    notification = Notification(user_id=current_user.id, message=error)
                                    db.session.add(notification)
                        if app.config.get("DATABASE") != "sb":
                            db.session.commit()
                        return jsonify({"status": "error", "message": "\n".join(password_errors)})
                    current_user.set_password(new_password)
                    if app.config.get("DATABASE") != "sb":
                        db.session.commit()
                    else:
                        from sb_functions import update_user
                        update_user(current_user.id, {'password_hash': current_user.password_hash})
                    flash("Password updated.", "success")
                    return jsonify({"status": "success", "message": "Password updated successfully."})


                if update_target == "issue":
                    if current_user.is_admin:
                        flash("Admins cannot submit issues through this form.", "error")
                        return redirect(url_for("account_settings"))
                    issue_title = request.form.get("issue_title")
                    issue_description = request.form.get("issue_description")
                    issue_type = request.form.get("issue_type")
                    if issue_title and issue_description and issue_type:
                        if app.config.get("DATABASE") == "sb":
                            from sb_functions import create_issue
                            create_issue(current_user.id, issue_title, issue_description, issue_type)
                        else:
                            new_issue = Issue(
                                user_id=current_user.id,
                                title=issue_title,
                                description=issue_description,
                                issue_type=issue_type,
                            )
                            db.session.add(new_issue)
                            db.session.commit()
                        flash(f"Your {issue_type} has been submitted successfully.", "success")
                        return redirect(url_for("account_settings"))

                flash("Choose a settings section to update.", "error")
                return redirect(url_for("account_settings"))
            except Exception:
                db.session.rollback()
                flash("Unable to update your settings right now. Please try again.", "error")
                return redirect(url_for("account_settings"))

        profile_pictures_path = os.path.join(current_app.root_path, 'static', 'profile_pictures')
        random_picture = ''
        try:
            if os.path.isdir(profile_pictures_path):
                profile_pictures = os.listdir(profile_pictures_path)
                if profile_pictures:
                    random_picture = random.choice(profile_pictures)
        except FileNotFoundError:
            current_app.logger.warning(f"Directory '{profile_pictures_path}' not found.")

        return render_template("settings.html", user=current_user, random_picture=random_picture)



    @app.route("/verify-email-change", methods=["POST"])
    @login_required
    def verify_email_change():
        otp_code = request.form.get("otp", "").strip()
        if not current_user.new_email or not current_user.otp_code:
            flash("No email change pending.", "error")
            return redirect(url_for('account_settings'))

        if not current_user.verify_otp(otp_code):
            flash("Invalid or expired OTP. Please try again.", "error")
            return render_template('verify_email_change.html', email=current_user.new_email)

        new_email = current_user.new_email

        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_user_by_email, update_user
            if get_user_by_email(new_email):
                flash("This email is already in use.", "error")
                return redirect(url_for('account_settings'))
            update_user(current_user.id, {'email': new_email, 'new_email': None, 'otp_code': None, 'otp_expiry': None})
        else:
            if User.query.filter_by(email=new_email).first():
                flash("This email is already in use.", "error")
                return redirect(url_for('account_settings'))

            current_user.email = new_email
            current_user.new_email = None
            current_user.otp_code = None
            current_user.otp_expiry = None
            db.session.commit()

        flash("Your email address has been updated successfully.", "success")
        return redirect(url_for('account_settings'))


    @app.route("/profile/picture")
    @login_required
    def profile_picture():
        if app.config.get("DATABASE") != "sb":
            # Re-fetch the user to ensure the latest profile picture is loaded
            user = db.session.get(User, current_user.id)
        else:
            user = current_user

        if app.config.get("DATABASE") == "sb" and user.profile_image_url:
            return redirect(user.profile_image_url)
        elif user.profile_picture_data and user.profile_picture_mimetype:
            return Response(user.profile_picture_data, mimetype=user.profile_picture_mimetype)
        else:
            # Optionally, return a default image if no profile picture is set
            try:
                with open(os.path.join(current_app.root_path, 'static', 'profile_pictures', 'default.png'), 'rb') as f:
                    default_image = f.read()
                return Response(default_image, mimetype='image/png')
            except FileNotFoundError:
                abort(404)

    @app.route("/")
    def index():
        search_query = request.args.get("q", "").strip()
        page = request.args.get("page", 1, type=int)
        per_page = 10

        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_all_universes
            all_universes, total = get_all_universes(page=page, per_page=per_page, search_query=search_query)

            universes = CustomPagination(all_universes, page, per_page, total)
        else:
            query = Universe.query
            if search_query:
                query = query.filter(Universe.title.ilike(f"%{search_query}%"))
            universes = query.order_by(Universe.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
        return render_template("index.html", universes=universes, search_query=search_query)

    @app.route("/live-search")
    def live_search():
        search_query = request.args.get("q", "").strip()
        if app.config.get("DATABASE") == "sb":
            from sb_functions import search_universes
            universes = search_universes(search_query)
        else:
            query = Universe.query
            if search_query:
                query = query.filter(Universe.title.ilike(f"%{search_query}%"))
            universes = query.order_by(Universe.created_at.desc()).all()
        return render_template("_universe_list.html", universes=universes)

    @app.route("/character/<int:character_id>")
    def character_detail(character_id):
        if app.config['DATABASE'] == 'sb':
            from sb_functions import get_character_by_id
            character = get_character_by_id(character_id)
            if not character:
                abort(404)
        else:
            character = Character.query.get_or_404(character_id)
        return render_template("character_detail.html", character=character)


    @app.route("/live-search-characters/<int:universe_id>")
    def live_search_characters(universe_id):
        search_query = request.args.get("q", "").strip()
        if app.config.get("DATABASE") == "sb":
            from sb_functions import search_characters
            characters = search_characters(universe_id, search_query)
        else:
            query = Character.query.filter_by(universe_id=universe_id)
            if search_query:
                query = query.filter(Character.name.ilike(f"%{search_query}%"))
            characters = query.order_by(Character.name.asc()).all()
        return render_template("_character_list.html", characters=characters, universe_id=universe_id)


    @app.route("/universe/<int:universe_id>")
    def universe_detail(universe_id: int):
        search_query = request.args.get("q", "").strip()
        page = request.args.get("page", 1, type=int)
        per_page = 10

        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_universe_by_id, get_characters_by_universe_id
            
            class SimplePagination:
                def __init__(self, items, page, per_page, total):
                    self.items = items
                    self.page = page
                    self.per_page = per_page
                    self.total = total
                    self.pages = (total + per_page - 1) // per_page if per_page > 0 else 0
                    self.has_next = self.page < self.pages
                    self.has_prev = self.page > 1
                    self.next_num = self.page + 1 if self.has_next else None
                    self.prev_num = self.page - 1 if self.has_prev else None

            universe = get_universe_by_id(universe_id)
            if not universe:
                abort(404)

            all_characters = get_characters_by_universe_id(universe_id)

            if search_query:
                all_characters = [c for c in all_characters if search_query.lower() in c.get('name', '').lower()]

            # Sort characters by name ascending
            all_characters.sort(key=lambda c: c.get('name', ''))

            total = len(all_characters)
            start = (page - 1) * per_page
            end = start + per_page
            characters_on_page = all_characters[start:end]

            characters = SimplePagination(characters_on_page, page, per_page, total)

            from sb_functions import get_collaboration_requests_by_universe, get_collaboration_requests_by_user, get_user_by_id
            pending_requests = []
            user_requests = []
            if current_user.is_authenticated:
                if str(universe.get('owner_id')) == str(current_user.id):
                    requests_as_dicts = get_collaboration_requests_by_universe(universe_id)
                    for req_dict in requests_as_dicts:
                        requester = get_user_by_id(req_dict['requester_id'])
                        if requester:
                            req_dict['requester'] = requester
                            pending_requests.append(req_dict)
                else:
                    user_requests = get_collaboration_requests_by_user(universe_id, current_user.id)
        else:
            universe = Universe.query.get_or_404(universe_id)
            characters_query = Character.query.filter_by(universe_id=universe_id)
            if search_query:
                characters_query = characters_query.filter(
                    Character.name.ilike(f"%{search_query}%")
                )

            characters = characters_query.order_by(Character.name.asc()).paginate(
                page=page, per_page=per_page, error_out=False
            )

            pending_requests = []
            user_requests = []

            if current_user.is_authenticated:
                if universe.owner_id == current_user.id:
                    pending_requests = (
                        UniverseCollaboratorRequest.query.filter_by(
                            universe_id=universe.id, status="pending"
                        )
                        .order_by(UniverseCollaboratorRequest.created_at.desc())
                        .all()
                    )
                else:
                    user_requests = (
                        UniverseCollaboratorRequest.query.filter_by(
                            universe_id=universe.id, requester_id=current_user.id
                        )
                        .order_by(UniverseCollaboratorRequest.created_at.desc())
                        .all()
                    )

        return render_template(
            "universe.html",
            universe=universe,
            characters=characters,
            search_query=search_query,
            pending_requests=pending_requests,
            user_requests=user_requests,
        )

    @app.route("/add-universe", methods=["GET", "POST"])
    @login_required
    def add_universe():
        if current_user.is_admin:
            flash("Admins are not allowed to create universes.", "error")
            return redirect(url_for('admin'))
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()

            if not title:
                flash("Universe title is required.", "error")
                return render_template("add_universe.html")

            if app.config.get("DATABASE") == "sb":
                from sb_functions import create_universe
                new_universe = create_universe(title, description, current_user.id)
                if new_universe and 'id' in new_universe:
                    flash("Your new universe has been created!", "success")
                    return redirect(url_for("universe_detail", universe_id=new_universe['id']))
                else:
                    flash("Error creating universe. Please try again.", "error")
                    return render_template("add_universe.html")
            else:
                new_universe = Universe(
                    title=title, description=description, owner_id=current_user.id
                )
                db.session.add(new_universe)
                db.session.commit()

                flash("Your new universe has been created!", "success")
                return redirect(url_for("universe_detail", universe_id=new_universe.id))

        return render_template("add_universe.html")

    @app.route("/universe/<int:universe_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_universe(universe_id):
        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_universe_by_id, update_universe
            universe = get_universe_by_id(universe_id)
            if not universe:
                abort(404)
            
            owner_id = str(universe.get('owner_id'))
            
            if owner_id != str(current_user.id) or current_user.is_admin:
                flash("You don't have permission to edit this universe.", "error")
                return redirect(url_for('universe_detail', universe_id=universe_id))
        else:
            universe = Universe.query.get_or_404(universe_id)
            if universe.owner_id != current_user.id or current_user.is_admin:
                flash("You don't have permission to edit this universe.", "error")
                return redirect(url_for('universe_detail', universe_id=universe.id))

        if request.method == "POST":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()

            if not title:
                flash("Universe title is required.", "error")
                return render_template("edit_universe.html", universe=universe)

            if app.config.get("DATABASE") == "sb":
                updated_universe = update_universe(universe_id, title, description)
                if updated_universe:
                    flash("Universe updated successfully.", "success")
                    return redirect(url_for("universe_detail", universe_id=universe_id))
                else:
                    flash("Error updating universe.", "error")
                    return render_template("edit_universe.html", universe=universe)
            else:
                universe.title = title
                universe.description = description
                db.session.commit()

                flash("Universe updated successfully.", "success")
                return redirect(url_for("universe_detail", universe_id=universe.id))

        return render_template("edit_universe.html", universe=universe)


    @app.route("/universe/<int:universe_id>/add_character", methods=["POST"])
    @login_required
    def add_character(universe_id: int):
        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_universe_by_id, create_character, create_collaboration_request, get_pending_collaboration_request
            universe = get_universe_by_id(universe_id)
            if not universe:
                abort(404)
            owner_id = str(universe.get('owner_id'))
        else:
            universe = Universe.query.get_or_404(universe_id)
            owner_id = str(universe.owner_id)

        # This route is for owners to add characters directly.
        # Non-owners should use the request_character route.
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()

        if not name:
            flash("Character name is required.", "error")
            return redirect(url_for("universe_detail", universe_id=universe_id))

        if owner_id != str(current_user.id):
            if current_user.is_admin:
                flash("Admins cannot request characters.", "error")
                return redirect(url_for("universe_detail", universe_id=universe_id))
            if get_pending_collaboration_request(universe_id, current_user.id, name):
                flash("You have already requested to add this character.", "info")
            else:
                create_collaboration_request(universe_id, current_user.id, name, description)
                flash("Your request to add a character has been sent to the universe owner.", "success")
            return redirect(url_for("universe_detail", universe_id=universe_id))


        if len(name) > 120:
            flash("Character name must be 120 characters or less.", "error")
            return redirect(url_for("universe_detail", universe_id=universe_id))

        if app.config.get("DATABASE") == "sb":
            new_character = create_character(name, description, universe_id, current_user.id)
            if new_character:
                flash("Character added successfully!", "success")
            else:
                flash("Error adding character. Please try again.", "error")
        else:
            try:
                character = Character(
                    name=name,
                    description=description,
                    universe_id=universe_id,
                    creator_id=current_user.id,
                )
                db.session.add(character)
                db.session.commit()
                flash("Character added successfully!", "success")
            except Exception:
                db.session.rollback()
                flash("Error adding character. Please try again.", "error")

        return redirect(url_for("universe_detail", universe_id=universe_id))

    @app.route("/universe/<int:universe_id>/request-character", methods=["POST"])
    @login_required
    def request_character(universe_id: int):
        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_universe_by_id, get_pending_collaboration_request, create_collaboration_request
            universe = get_universe_by_id(universe_id)
            if not universe:
                abort(404)
            owner_id = str(universe.get('owner_id'))
        else:
            universe = Universe.query.get_or_404(universe_id)
            owner_id = str(universe.owner_id)

        if owner_id == str(current_user.id):
            flash("You already own this universe. Add characters directly instead of requesting.", "info")
            return redirect(url_for("universe_detail", universe_id=universe_id))

        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()

        if not name:
            flash("Character name is required.", "error")
            return redirect(url_for("universe_detail", universe_id=universe_id))

        if len(name) > 120:
            flash("Character name must be 120 characters or less.", "error")
            return redirect(url_for("universe_detail", universe_id=universe_id))

        if app.config.get("DATABASE") == "sb":
            existing_pending = get_pending_collaboration_request(universe_id, current_user.id, name)
            if existing_pending:
                flash("You already have a pending request with that name.", "info")
                return redirect(url_for("universe_detail", universe_id=universe_id))
            
            if create_collaboration_request(universe_id, current_user.id, name, description):
                flash("Request sent to the universe owner.", "success")
            else:
                flash("Unable to submit your request right now. Please try again.", "error")
        else:
            existing_pending = UniverseCollaboratorRequest.query.filter_by(
                universe_id=universe_id,
                requester_id=current_user.id,
                character_name=name,
                status="pending",
            ).first()
            if existing_pending:
                flash("You already have a pending request with that name.", "info")
                return redirect(url_for("universe_detail", universe_id=universe_id))

            try:
                collaboration_request = UniverseCollaboratorRequest(
                    universe_id=universe_id,
                    requester_id=current_user.id,
                    character_name=name,
                    character_description=description,
                )
                db.session.add(collaboration_request)
                db.session.commit()
                flash("Request sent to the universe owner.", "success")
            except Exception:
                db.session.rollback()
                flash("Unable to submit your request right now. Please try again.", "error")

        return redirect(url_for("universe_detail", universe_id=universe_id))

    @app.route("/universe/<int:universe_id>/requests/<int:request_id>/approve", methods=["POST"])
    @login_required
    def approve_collaboration_request(universe_id: int, request_id: int):
        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_universe_by_id, get_collaboration_request_by_id, update_collaboration_request_status, create_character
            universe = get_universe_by_id(universe_id)
            if not universe:
                abort(404)
            owner_id = str(universe.get('owner_id'))
        else:
            universe = Universe.query.get_or_404(universe_id)
            owner_id = str(universe.owner_id)

        if owner_id != str(current_user.id):
            flash("You do not have permission to manage requests for this universe.", "error")
            return redirect(url_for("universe_detail", universe_id=universe_id))

        if app.config.get("DATABASE") == "sb":
            collaboration_request = get_collaboration_request_by_id(request_id)
            if not collaboration_request:
                abort(404)
        else:
            collaboration_request = UniverseCollaboratorRequest.query.filter_by(
                id=request_id, universe_id=universe_id
            ).first_or_404()

        if collaboration_request.get('status') != "pending":
            flash("This request has already been processed.", "info")
            return redirect(url_for("universe_detail", universe_id=universe_id))

        if app.config.get("DATABASE") == "sb":
            character = create_character(
                name=collaboration_request.get('character_name'),
                description=collaboration_request.get('character_description'),
                universe_id=universe_id,
                creator_id=collaboration_request.get('requester_id'),
            )
            if character:
                update_collaboration_request_status(request_id, "approved")
                flash(f"Character '{collaboration_request.get('character_name')}' added from the collaboration request.", "success")
            else:
                flash("Unable to approve the request right now. Please try again.", "error")
        else:
            try:
                character = Character(
                    name=collaboration_request.character_name,
                    description=collaboration_request.character_description,
                    universe_id=universe.id,
                    creator_id=collaboration_request.requester_id,
                )
                db.session.add(character)
                collaboration_request.approve()
                db.session.commit()
                flash(f"Character '{character.name}' added from the collaboration request.", "success")
            except Exception:
                db.session.rollback()
                flash("Unable to approve the request right now. Please try again.", "error")

        return redirect(url_for("universe_detail", universe_id=universe_id))

    @app.route("/universe/<int:universe_id>/requests/<int:request_id>/reject", methods=["POST"])
    @login_required
    def reject_collaboration_request(universe_id: int, request_id: int):
        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_universe_by_id, get_collaboration_request_by_id, update_collaboration_request_status
            universe = get_universe_by_id(universe_id)
            if not universe:
                abort(404)
            owner_id = str(universe.get('owner_id'))
        else:
            universe = Universe.query.get_or_404(universe_id)
            owner_id = str(universe.owner_id)

        if owner_id != str(current_user.id):
            flash("You do not have permission to manage requests for this universe.", "error")
            return redirect(url_for("universe_detail", universe_id=universe_id))

        if app.config.get("DATABASE") == "sb":
            collaboration_request = get_collaboration_request_by_id(request_id)
            if not collaboration_request:
                abort(404)
        else:
            collaboration_request = UniverseCollaboratorRequest.query.filter_by(
                id=request_id, universe_id=universe_id
            ).first_or_404()

        if collaboration_request.get('status') != "pending":
            flash("This request has already been processed.", "info")
            return redirect(url_for("universe_detail", universe_id=universe_id))

        if app.config.get("DATABASE") == "sb":
            if update_collaboration_request_status(request_id, "rejected"):
                flash("Request rejected.", "info")
            else:
                flash("Unable to reject the request right now. Please try again.", "error")
        else:
            try:
                collaboration_request.reject()
                db.session.commit()
                flash("Request rejected.", "info")
            except Exception:
                db.session.rollback()
                flash("Unable to reject the request right now. Please try again.", "error")

        return redirect(url_for("universe_detail", universe_id=universe_id))




    @app.route("/universe/<int:universe_id>/delete", methods=["POST"])
    @login_required
    def delete_universe(universe_id: int):
        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_universe_by_id, delete_universe as sb_delete_universe
            universe = get_universe_by_id(universe_id)
            if not universe:
                abort(404)

            owner_id = str(universe.get('owner_id'))

            if owner_id != str(current_user.id):
                flash("You do not have permission to delete this universe.", "error")
                return redirect(url_for("universe_detail", universe_id=universe_id))

            universe_title = universe.get('title', 'Untitled')
            if sb_delete_universe(universe_id):
                flash(f"Universe '{universe_title}' deleted successfully!", "success")
                return redirect(url_for("index"))
            else:
                flash("Error deleting universe. Please try again.", "error")
                return redirect(url_for("universe_detail", universe_id=universe_id))
        else:
            universe = Universe.query.get_or_404(universe_id)

            if universe.owner_id != current_user.id:
                flash("You do not have permission to delete this universe.", "error")
                return redirect(url_for("universe_detail", universe_id=universe.id))

            try:
                db.session.delete(universe)
                db.session.commit()
                flash(f"Universe '{universe.title}' deleted successfully!", "success")
            except Exception:
                db.session.rollback()
                flash("Error deleting universe. Please try again.", "error")
            return redirect(url_for("index"))

    @app.route("/character/<int:character_id>/delete", methods=["POST"])
    @login_required
    def delete_character(character_id: int):
        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_character_by_id, get_universe_by_id, delete_character as sb_delete_character
            character = get_character_by_id(character_id)
            if not character:
                abort(404)

            universe_id = character.get('universe_id')
            universe = get_universe_by_id(universe_id)

            is_creator = str(character.get('creator_id')) == str(current_user.id)
            is_universe_owner = universe and str(universe.get('owner_id')) == str(current_user.id)

            if not (is_creator or is_universe_owner or current_user.is_admin):
                flash("You do not have permission to delete this character.", "error")
                return redirect(url_for("universe_detail", universe_id=universe_id))

            character_name = character.get('name', 'Untitled')
            if sb_delete_character(character_id):
                flash(f"Character {character_name} deleted successfully!", "success")
            else:
                flash("Error deleting character. Please try again.", "error")
            return redirect(url_for("universe_detail", universe_id=universe_id))
        else:
            character = Character.query.get_or_404(character_id)
            universe_id = character.universe_id

            if character.creator_id != current_user.id and character.universe.owner_id != current_user.id and not current_user.is_admin:
                flash("You do not have permission to delete this character.", "error")
                return redirect(url_for("universe_detail", universe_id=universe_id))

            try:
                db.session.delete(character)
                db.session.commit()
                flash(f"Character '{character.name}' deleted successfully!", "success")
            except Exception:
                db.session.rollback()
                flash("Error deleting character. Please try again.", "error")
            return redirect(url_for("universe_detail", universe_id=universe_id))

    @app.route("/character/<int:character_id>/edit", methods=["POST"])
    @login_required
    def edit_character(character_id: int):
        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_character_by_id, update_character
            character = get_character_by_id(character_id)
            if not character:
                abort(404)
            
            universe_id = character.get('universe_id')

            if str(character.get('creator_id')) != str(current_user.id):
                flash("You do not have permission to edit this character.", "error")
                return redirect(url_for("universe_detail", universe_id=universe_id))

            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()

            if not name:
                flash("Character name is required.", "error")
                return redirect(url_for("universe_detail", universe_id=universe_id))

            if len(name) > 120:
                flash("Character name must be 120 characters or less.", "error")
                return redirect(url_for("universe_detail", universe_id=universe_id))

            if update_character(character_id, name, description):
                flash("Character updated successfully!", "success")
            else:
                flash("Error updating character. Please try again.", "error")

            return redirect(url_for("universe_detail", universe_id=universe_id))
        else:
            character = Character.query.get_or_404(character_id)

            if character.creator_id != current_user.id:
                flash("You do not have permission to edit this character.", "error")
                return redirect(url_for("universe_detail", universe_id=character.universe_id))

            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()

            if not name:
                flash("Character name is required.", "error")
                return redirect(url_for("universe_detail", universe_id=character.universe_id))

            if len(name) > 120:
                flash("Character name must be 120 characters or less.", "error")
                return redirect(url_for("universe_detail", universe_id=character.universe_id))

            try:
                character.name = name
                character.description = description
                db.session.commit()
                flash("Character updated successfully!", "success")
            except Exception:
                db.session.rollback()
                flash("Error updating character. Please try again.", "error")

            return redirect(url_for("universe_detail", universe_id=character.universe_id))

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            if request.is_json:
                email = request.json.get("email", "").strip().lower()
                if app.config.get("DATABASE") == "sb":
                    from sb_functions import get_user_by_email
                    user = get_user_by_email(email)
                else:
                    user = User.query.filter_by(email=email).first()

                if not user:
                    return jsonify({"success": False, "message": "No user found with that email address."}), 404

                try:
                    send_password_reset_email(user)
                    return jsonify({"success": True, "message": "An OTP has been sent to your email."})
                except Exception as e:
                    current_app.logger.error(f"Error sending OTP for password reset: {e}")
                    db.session.rollback()
                    return jsonify({"success": False, "message": "Could not send OTP. Please try again."}), 500

            email = request.form.get("email", "").strip().lower()
            otp_code = request.form.get("otp", "").strip()
            new_password = request.form.get("new_password", "")
            new_password_confirm = request.form.get("new_password_confirm", "")

            if not new_password:
                flash("Password cannot be empty.", "error")
                return redirect(url_for("forgot_password", email=email))

            if app.config.get("DATABASE") == "sb":
                from sb_functions import get_user_by_email
                user = get_user_by_email(email)
            else:
                user = User.query.filter_by(email=email).first()

            if not user:
                flash("Invalid request.", "error")
                return redirect(url_for("forgot_password"))

            if new_password != new_password_confirm:
                flash("Passwords do not match.", "error")
                return redirect(url_for("forgot_password", email=email))

            is_valid_password, password_errors = User.validate_password_rules(new_password)
            if not is_valid_password:
                for error_message in password_errors:
                    flash(error_message, "error")
                return redirect(url_for("forgot_password", email=email))

            import datetime
            if not user.verify_otp(otp_code):
                flash("Invalid or expired OTP.", "error")
                return redirect(url_for("forgot_password", email=email))

            if app.config.get("DATABASE") == "sb":
                from sb_functions import update_user
                user.set_password(new_password)
                update_user(user.id, {'password_hash': user.password_hash, 'otp_code': None, 'otp_expiry': None})
            else:
                user.set_password(new_password)
                user.otp_code = None
                user.otp_expiry = None
                db.session.commit()

            flash("Your password has been reset successfully. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("forgot_password.html")

    @app.route("/issues")
    @login_required
    def issues():
        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_all_issues
            issues = get_all_issues()
        else:
            issues = Issue.query.order_by(Issue.timestamp.desc()).all()
        return render_template("issues.html", issues=issues)

    @app.route("/search")
    def search_route():
        query = request.args.get("query", "")
        if not query:
            return redirect(url_for("index"))

        if app.config.get("DATABASE") == "sb":
            from sb_functions import search
            universe_results, character_results = search(query)
        else:
            universe_results = Universe.query.filter(Universe.title.ilike(f"%{query}%")).all()
            character_results = Character.query.filter(Character.name.ilike(f"%{query}%")).all()

        return render_template("search_results.html", query=query, universes=universe_results, characters=character_results)




    @app.route('/notifications')
    @login_required
    def notifications():
        app.logger.info(f'User {current_user.id} fetched notifications')
        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_notifications_by_user
            notifications_list = get_notifications_by_user(current_user.id)
        else:
            notifications_list = [notification.to_dict() for notification in Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).limit(5).all()]
        app.logger.info(f'Returning {len(notifications_list)} notifications for user {current_user.id}')
        return jsonify(notifications_list)


    @app.route('/notifications/mark-all-read', methods=['POST'])
    @login_required
    def mark_all_read():
        if app.config.get("DATABASE") == "sb":
            from sb_functions import mark_all_notifications_as_read
            mark_all_notifications_as_read(current_user.id)
        else:
            for notification in current_user.notifications:
                notification.read = True
            db.session.commit()
        return jsonify({'success': True})


    @app.route("/admin")
    @login_required
    def admin():
        if not current_user.is_admin:
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for("index"))

        active_tab = request.args.get("tab", "dashboard")
        page_users = request.args.get("page_users", 1, type=int)
        page_universes = request.args.get("page_universes", 1, type=int)
        page_issues = request.args.get("page_issues", 1, type=int)

        search_users = request.args.get("search_users", "")
        search_universes = request.args.get("search_universes", "")
        search_issues = request.args.get("search_issues", "")

        if app.config.get("DATABASE") == "sb":
            from sb_functions import get_all_users, get_all_universes, get_all_characters, get_all_issues

            all_users, total_users = get_all_users(page=page_users, per_page=10, search_query=search_users)
            users = CustomPagination(all_users, page_users, 10, total_users)

            all_universes, total_universes = get_all_universes(page=page_universes, per_page=10, search_query=search_universes)
            universes = CustomPagination(all_universes, page_universes, 10, total_universes)

            all_issues, total_issues = get_all_issues(page=page_issues, per_page=10, search_query=search_issues)
            issues = CustomPagination(all_issues, page_issues, 10, total_issues)

            characters = get_all_characters()
        else:
            if search_users:
                users_query = User.query.filter(
                    User.is_admin == False,
                    or_(User.username.contains(search_users), User.email.contains(search_users), User.id.contains(search_users))
                )
            else:
                users_query = User.query.filter(User.is_admin == False)

            if search_universes:
                universes_query = Universe.query.filter(
                    or_(Universe.title.contains(search_universes), Universe.id.contains(search_universes))
                )
            else:
                universes_query = Universe.query

            if search_issues:
                issues_query = Issue.query.filter(Issue.id.contains(search_issues))
            else:
                issues_query = Issue.query

            users = users_query.paginate(page=page_users, per_page=10)
            universes = universes_query.paginate(page=page_universes, per_page=10)
            issues = issues_query.paginate(page=page_issues, per_page=10)
            characters = Character.query.all()

        return render_template(
            "admin.html",
            users=users,
            universes=universes,
            characters=characters,
            issues=issues,
            active_tab=active_tab,
        )

    @app.route('/admin/delete_character/<int:character_id>', methods=['POST'])
    @login_required
    def admin_delete_character(character_id):
        if not current_user.is_admin:
            flash('You are not authorized to perform this action.', 'error')
            return redirect(url_for('admin'))
        if app.config.get("DATABASE") == "sb":
            from sb_functions import delete_character
            delete_character(character_id)
        else:
            character = Character.query.get_or_404(character_id)
            db.session.delete(character)
            db.session.commit()
        flash('Character deleted successfully.', 'success')
        return redirect(url_for('admin'))

    @app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
    @login_required
    def admin_delete_user(user_id):
        if not current_user.is_admin:
            flash('You are not authorized to perform this action.', 'error')
            return redirect(url_for('admin'))

        if app.config.get("DATABASE") == "sb":
            from sb_functions import delete_user
            delete_user(user_id)
        else:
            user_to_delete = User.query.get_or_404(user_id)
            db.session.delete(user_to_delete)
            db.session.commit()
        flash('User deleted successfully.', 'success')
        return redirect(url_for('admin', tab='users'))

    @app.route('/admin/delete_universe/<int:universe_id>', methods=['POST'])
    @login_required
    def admin_delete_universe(universe_id):
        if not current_user.is_admin:
            flash('You are not authorized to perform this action.', 'error')
            return redirect(url_for('admin'))
        if app.config.get("DATABASE") == "sb":
            from sb_functions import delete_universe
            delete_universe(universe_id)
        else:
            universe = Universe.query.get_or_404(universe_id)
            db.session.delete(universe)
            db.session.commit()
        flash('Universe deleted successfully.', 'success')
        return redirect(url_for('admin'))

    @app.route('/admin/delete_issue/<int:issue_id>', methods=['POST'])
    @login_required
    def admin_delete_issue(issue_id):
        if not current_user.is_admin:
            flash('You are not authorized to perform this action.', 'error')
            return redirect(url_for('admin'))
        if app.config.get("DATABASE") == "sb":
            from sb_functions import delete_issue
            delete_issue(issue_id)
        else:
            issue = Issue.query.get_or_404(issue_id)
            db.session.delete(issue)
            db.session.commit()
        flash('Issue/Suggestion deleted successfully.', 'success')
        return redirect(url_for('admin', tab='issues'))

    return app


def register_error_handlers(app: Flask) -> None:
    """Register error handlers for the application."""

    @app.errorhandler(404)
    def not_found(error):
        return render_template('error.html',
                             error_code=404,
                             error_message="The page you're looking for doesn't exist."), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('error.html',
                             error_code=500,
                             error_message="Something went wrong on our end."), 500

    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(error):
        flash("That file is too large. Please upload an image under 8 MB.", "error")
        return redirect(url_for("account_settings")), 413


app = create_app(os.getenv('FLASK_CONFIG') or 'default')


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))