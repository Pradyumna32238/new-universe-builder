# Force reload
"""Flask application entry point for the Universe Builder app."""
from __future__ import annotations
from dotenv import load_dotenv

load_dotenv()

import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
import re
import base64
import datetime
import random
import string
from io import BytesIO

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

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

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

cache = Cache(config={'CACHE_TYPE': 'SimpleCache'})
from models import db, User, Universe, Character, UniverseCollaboratorRequest, Issue, Notification, NotificationSettings

def allowed_profile_extension(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_PROFILE_EXTENSIONS

from config import config_map


USERNAME_MAX_LENGTH = 80
ALLOWED_PROFILE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


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

    while User.query.filter_by(username=candidate).first():
        suffix_str = str(suffix)
        allowed_length = max(1, USERNAME_MAX_LENGTH - len(suffix_str))
        candidate = f"{sanitized[:allowed_length]}{suffix_str}"
        suffix += 1

    return candidate


def process_image(file_storage) -> tuple[bytes | None, str | None, str | None]:
    """Resize, compress, and convert incoming images to WebP for storage."""
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
    db.session.commit()
    send_gmail(
         to=user.email,
         subject="Reset Your Password",
         template='email/reset_password',
         user=user,
         otp=user.otp_code
     )




def create_app(config_name: str = None) -> Flask:
    """Create and configure the Flask application."""
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "default")

    app = Flask(__name__)
    app.config.from_object(config_map[config_name])
    app.config['SECRET_KEY'] = 'a-very-secret-key'



    
    db.init_app(app)
    cache.init_app(app)

    migrate = Migrate(app, db)

    with app.app_context():
        if not inspect(db.engine).has_table('user'):
            db.create_all()

        admin_username = os.environ.get("ADMIN_USERNAME", "admin")
        admin_password = os.environ.get("ADMIN_PASSWORD", "admin")
        admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")

        if not User.query.filter_by(username=admin_username).first():
            admin_user = User(
                username=admin_username,
                email=admin_email,
                is_admin=True,
                is_verified=True,
                email_verified=True
            )
            admin_user.set_password(admin_password)
            db.session.add(admin_user)
            db.session.commit()

    login_manager = LoginManager(app)
    login_manager.login_view = "login"

    @login_manager.user_loader
    def load_user(user_id: str):
        return User.query.get(int(user_id))

    with app.app_context():
        # Register Blueprints, if any
        # from .main import main as main_blueprint
        # app.register_blueprint(main_blueprint)

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

        if User.query.filter_by(email=new_email).first():
            return jsonify({'error': 'Email is already registered'}), 400

        try:
            otp = current_user.generate_otp()
            db.session.commit()  # Commit the OTP to the database before sending
            subject = 'Verify Your New Email Address'
            send_gmail(
                to=new_email,
                subject=subject,
                template='email/verify_new_email',
                user=current_user,
                otp=otp
            )
            current_user.new_email = new_email
            db.session.commit()
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
                send_gmail(
                    to=email,
                    subject="Verify Your Email Address",
                    template='email/verify_email',
                    username=username,
                    otp=otp
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

        user = User.query.filter_by(email=email).first()
        return jsonify({"available": not user})

    @app.route("/api/check-username")
    def check_username():
        username = request.args.get("username", "").strip()
        if not username:
            return jsonify({"available": False, "message": "Username cannot be empty."}), 400

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


    @app.route('/authorize')
    def authorize():
        flow = Flow.from_client_config(
            get_credentials_from_env(),
            scopes=GMAIL_SCOPES,
            redirect_uri=url_for('oauth2callback', _external=True))
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            prompt='consent',
            include_granted_scopes='true')
        session['state'] = state
        return redirect(authorization_url)


    @app.route('/oauth2callback')
    def oauth2callback():
        state = session.get('state')
        if not state:
            return "The authorization state is missing from the session.", 400

        flow = Flow.from_client_config(
            get_credentials_from_env(),
            scopes=GMAIL_SCOPES,
            state=state,
            redirect_uri=url_for('oauth2callback', _external=True))
        
        try:
            flow.fetch_token(authorization_response=request.url)
        except Exception as e:
            return f"Failed to fetch token: {e}", 400
        
        credentials = flow.credentials
        # The application now uses environment variables for credentials.
        # After the initial authorization, you may need to manually update your
        # environment with the new token details from the 'credentials' object.
            
        return redirect(url_for('gmail_api_test'))
        
    @app.route('/notifications/clear', methods=['POST'])
    @login_required
    def clear_notifications():
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
        if not Notification.query.filter_by(user_id=current_user.id, message=message).first():
            notification = Notification(user_id=current_user.id, message=message)
            db.session.add(notification)
            db.session.commit()
            created = True

        return jsonify({"status": "success", "created": created})


    @app.route("/profile/<username>")
    @login_required
    def profile(username: str):
        user = User.query.filter_by(username=username).first_or_404()
        return render_template("profile.html", user=user)

    @app.route("/settings", methods=['GET', 'POST'])
    @login_required
    def account_settings():
        if request.method == "POST":
            if current_user.is_admin:
                flash("Admin details cannot be modified.", "error")
                return redirect(url_for("account_settings"))
            if request.form.get("update_target") == "notifications":
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
                    new_username = request.form.get("username", "").strip()
                    new_email = request.form.get("email", "").strip().lower()

                    if not new_username or not new_email:
                        flash("Username and email cannot be empty.", "error")
                        return redirect(url_for("account_settings"))

                    if new_username != current_user.username:
                        existing_user = User.query.filter(User.username == new_username).first()
                        if existing_user:
                            flash("That username is already taken.", "error")
                            return redirect(url_for("account_settings"))
                        current_user.username = new_username
                        db.session.commit()
                        flash("Username updated successfully.", "success")

                    if new_email != current_user.email:
                        existing_user = User.query.filter(User.email == new_email).first()
                        if existing_user:
                            flash("That email is already registered.", "error")
                            return redirect(url_for("account_settings"))


                        # Generate and store OTP for the new email
                        current_user.new_email = new_email

                        current_user.generate_otp()
                        db.session.commit()

                        # Send OTP to the new email address
                        try:
                            send_gmail(
                             to=new_email,
                             subject="Confirm Your New Email Address",
                             template='email/verify_new_email',
                             otp=current_user.otp_code
                         )
                            flash("An OTP has been sent to your new email address. Please verify to complete the change.", "info")
                        except Exception as e:
                            current_app.logger.error(f"Failed to send OTP email to {new_email}: {e}")
                            return jsonify({"error": "Could not send OTP. Please try again later."}), 500

                    db.session.commit()
                    return jsonify({"status": "success", "message": "Profile details updated."})

                if update_target == "profile-picture":
                    if "remove_profile_picture" in request.form:
                        current_user.set_profile_image(None, None)
                        db.session.commit()
                        flash("Profile picture removed.", "success")
                        return jsonify({"status": "success", "message": "Profile picture removed."})

                    profile_picture_file = request.files.get("profile_picture")
                    if profile_picture_file and profile_picture_file.filename:
                        image_data, mimetype, error = process_image(profile_picture_file)
                        if error:
                            flash(error, "error")
                            return jsonify({"status": "error", "message": error})

                        current_user.set_profile_image(image_data, mimetype)
                        db.session.commit()
                        flash("Profile picture updated.", "success")
                        return jsonify({"status": "success", "message": "Profile picture updated."})

                if update_target == "password":
                    current_password = request.form.get("current_password", "")
                    new_password = request.form.get("new_password", "")
                    new_password_confirm = request.form.get("confirm_password", "")

                    if not current_password:
                        message = "Enter your current password to change it."
                        if not Notification.query.filter_by(user_id=current_user.id, message=message).first():
                            notification = Notification(user_id=current_user.id, message=message)
                            db.session.add(notification)
                            db.session.commit()
                        return jsonify({"status": "error", "message": message})
                    if not current_user.check_password(current_password):
                        message = "Current password is incorrect."
                        if not Notification.query.filter_by(user_id=current_user.id, message=message).first():
                            notification = Notification(user_id=current_user.id, message=message)
                            db.session.add(notification)
                            db.session.commit()
                        return jsonify({"status": "error", "message": message})
                    if current_user.check_password(new_password):
                        message = "New password cannot be the same as the current password."
                        if not Notification.query.filter_by(user_id=current_user.id, message=message).first():
                            notification = Notification(user_id=current_user.id, message=message)
                            db.session.add(notification)
                        db.session.commit()
                        return jsonify({"status": "error_same_password", "message": message})
                    if new_password != new_password_confirm:
                        message = "New passwords do not match."
                        if not Notification.query.filter_by(user_id=current_user.id, message=message).first():
                            notification = Notification(user_id=current_user.id, message=message)
                            db.session.add(notification)
                            db.session.commit()
                        return jsonify({"status": "error", "message": message})
                    is_valid_password, password_errors = User.validate_password_rules(new_password)
                    if not is_valid_password:
                        for error in password_errors:
                            if not Notification.query.filter_by(user_id=current_user.id, message=error).first():
                                notification = Notification(user_id=current_user.id, message=error)
                                db.session.add(notification)
                        db.session.commit()
                        return jsonify({"status": "error", "message": "\n".join(password_errors)})
                    current_user.set_password(new_password)
                    db.session.commit()
                    flash("Password updated.", "success")
                    return jsonify({"status": "success", "message": "Password updated successfully."})


                if update_target == "issue":
                    issue_title = request.form.get("issue_title")
                    issue_description = request.form.get("issue_description")
                    issue_type = request.form.get("issue_type")
                    if issue_title and issue_description and issue_type:
                        new_issue = Issue(
                            user_id=current_user.id,
                            title=issue_title,
                            description=issue_description,
                            issue_type=issue_type,
                        )
                        db.session.add(new_issue)
                        db.session.commit()
                        flash("Your issue has been submitted successfully.", "success")
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
            flash("Invalid or expired OTP.", "error")
            return redirect(url_for('account_settings'))

        current_user.email = current_user.new_email
        current_user.new_email = None
        current_user.otp_code = None
        current_user.otp_expiry = None
        db.session.commit()
        flash("Your email address has been updated successfully.", "success")
        return redirect(url_for('account_settings'))


    @app.route("/profile/picture")
    @login_required
    def profile_picture():
        if current_user.profile_picture_data and current_user.profile_picture_mimetype:
            return Response(current_user.profile_picture_data, mimetype=current_user.profile_picture_mimetype)
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
        query = Universe.query
        if search_query:
            query = query.filter(Universe.title.ilike(f"%{search_query}%"))
        universes = query.order_by(Universe.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
        return render_template("index.html", universes=universes, search_query=search_query)

    @app.route("/live-search")
    def live_search():
        search_query = request.args.get("q", "").strip()
        query = Universe.query
        if search_query:
            query = query.filter(Universe.title.ilike(f"%{search_query}%"))
        universes = query.order_by(Universe.created_at.desc()).all()
        return render_template("_universe_list.html", universes=universes)

    @app.route("/character/<int:character_id>")
    def character_detail(character_id):
        character = Character.query.get_or_404(character_id)
        return render_template("character_detail.html", character=character)


    @app.route("/live-search-characters/<int:universe_id>")
    def live_search_characters(universe_id):
        search_query = request.args.get("q", "").strip()
        query = Character.query.filter_by(universe_id=universe_id)
        if search_query:
            query = query.filter(Character.name.ilike(f"%{search_query}%"))
        characters = query.order_by(Character.name.asc()).all()
        return render_template("_character_list.html", characters=characters, universe_id=universe_id)


    @app.route("/universe/<int:universe_id>")
    def universe_detail(universe_id: int):
        universe = Universe.query.get_or_404(universe_id)
        search_query = request.args.get("q", "").strip()
        page = request.args.get("page", 1, type=int)
        per_page = 10

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

            universe.title = title
            universe.description = description
            db.session.commit()

            flash("Universe updated successfully.", "success")
            return redirect(url_for("universe_detail", universe_id=universe.id))

        return render_template("edit_universe.html", universe=universe)


    @app.route("/universe/<int:universe_id>/add_character", methods=["POST"])
    @login_required
    def add_character(universe_id: int):
        universe = Universe.query.get_or_404(universe_id)

        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()

        # Input validation
        if not name:
            flash("Character name is required.", "error")
            return redirect(url_for("universe_detail", universe_id=universe.id))

        if len(name) > 120:
            flash("Character name must be 120 characters or less.", "error")
            return redirect(url_for("universe_detail", universe_id=universe.id))

        if universe.owner_id != current_user.id:
            # If the user is not the owner, create a character request
            try:
                collaboration_request = UniverseCollaboratorRequest(
                    universe_id=universe.id,
                    requester_id=current_user.id,
                    character_name=name,
                    character_description=description,
                )
                db.session.add(collaboration_request)
                db.session.commit()
                flash("Request sent to the universe owner.", "success")
                return redirect(url_for("universe_detail", universe_id=universe.id))
            except Exception:
                db.session.rollback()
                flash("Unable to submit your request right now. Please try again.", "error")
                return redirect(url_for("universe_detail", universe_id=universe.id))


        try:
            character = Character(
                name=name,
                description=description,
                universe_id=universe.id,
                creator_id=current_user.id,
            )
            db.session.add(character)
            db.session.commit()
            flash("Character added successfully!", "success")
        except Exception:
            db.session.rollback()
            flash("Error adding character. Please try again.", "error")

        return redirect(url_for("universe_detail", universe_id=universe.id))

    @app.route("/universe/<int:universe_id>/request-character", methods=["POST"])
    @login_required
    def request_character(universe_id: int):
        universe = Universe.query.get_or_404(universe_id)

        if universe.owner_id == current_user.id:
            flash("You already own this universe. Add characters directly instead of requesting.", "info")
            return redirect(url_for("universe_detail", universe_id=universe.id))

        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()

        if not name:
            flash("Character name is required.", "error")
            return redirect(url_for("universe_detail", universe_id=universe.id))

        if len(name) > 120:
            flash("Character name must be 120 characters or less.", "error")
            return redirect(url_for("universe_detail", universe_id=universe.id))

        existing_pending = UniverseCollaboratorRequest.query.filter_by(
            universe_id=universe.id,
            requester_id=current_user.id,
            character_name=name,
            status="pending",
        ).first()
        if existing_pending:
            flash("You already have a pending request with that name.", "info")
            return redirect(url_for("universe_detail", universe_id=universe.id))

        try:
            collaboration_request = UniverseCollaboratorRequest(
                universe_id=universe.id,
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

        return redirect(url_for("universe_detail", universe_id=universe.id))

    @app.route("/universe/<int:universe_id>/requests/<int:request_id>/approve", methods=["POST"])
    @login_required
    def approve_collaboration_request(universe_id: int, request_id: int):
        universe = Universe.query.get_or_404(universe_id)

        if universe.owner_id != current_user.id:
            flash("You do not have permission to manage requests for this universe.", "error")
            return redirect(url_for("universe_detail", universe_id=universe.id))

        collaboration_request = UniverseCollaboratorRequest.query.filter_by(
            id=request_id, universe_id=universe.id
        ).first_or_404()

        if collaboration_request.status != "pending":
            flash("This request has already been processed.", "info")
            return redirect(url_for("universe_detail", universe_id=universe.id))

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

        return redirect(url_for("universe_detail", universe_id=universe.id))

    @app.route("/universe/<int:universe_id>/requests/<int:request_id>/reject", methods=["POST"])
    @login_required
    def reject_collaboration_request(universe_id: int, request_id: int):
        universe = Universe.query.get_or_404(universe_id)

        if universe.owner_id != current_user.id:
            flash("You do not have permission to manage requests for this universe.", "error")
            return redirect(url_for("universe_detail", universe_id=universe.id))

        collaboration_request = UniverseCollaboratorRequest.query.filter_by(
            id=request_id, universe_id=universe.id
        ).first_or_404()

        if collaboration_request.status != "pending":
            flash("This request has already been processed.", "info")
            return redirect(url_for("universe_detail", universe_id=universe.id))

        try:
            collaboration_request.reject()
            db.session.commit()
            flash("Request rejected.", "info")
        except Exception:
            db.session.rollback()
            flash("Unable to reject the request right now. Please try again.", "error")

        return redirect(url_for("universe_detail", universe_id=universe.id))




    @app.route("/universe/<int:universe_id>/delete", methods=["POST"])
    @login_required
    def delete_universe(universe_id: int):
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
        issues = Issue.query.order_by(Issue.timestamp.desc()).all()
        return render_template("issues.html", issues=issues)

    @app.route("/search")
    def search():
        query = request.args.get("query", "")
        if not query:
            return redirect(url_for("index"))

        universe_results = Universe.query.filter(Universe.title.ilike(f"%{query}%")).all()
        character_results = Character.query.filter(Character.name.ilike(f"%{query}%")).all()

        return render_template(
            "search.html",
            query=query,
            universe_results=universe_results,
            character_results=character_results,
        )




    @app.route('/notifications')
    @login_required
    def notifications():
        app.logger.info(f'User {current_user.id} fetched notifications')
        notifications = [notification.to_dict() for notification in Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all()]
        app.logger.info(f'Returning {len(notifications)} notifications for user {current_user.id}')
        return jsonify(notifications)


    @app.route('/notifications/mark-all-read', methods=['POST'])
    @login_required
    def mark_all_read():
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
        user_to_delete = User.query.get_or_404(user_id)
        if user_to_delete.is_admin:
            flash('Admin users cannot be deleted.', 'error')
            return redirect(url_for('admin', tab='users'))
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
        issue = Issue.query.get_or_404(issue_id)
        db.session.delete(issue)
        db.session.commit()
        flash('Issue deleted successfully.', 'success')
        return redirect(url_for('admin', tab='issues'))


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


app = create_app()


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))