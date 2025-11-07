from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re
import base64
from flask import url_for
db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    otp_code = db.Column(db.String(6))
    otp_expiry = db.Column(db.DateTime)
    new_email = db.Column(db.String(150))
    profile_picture_data = db.Column(db.LargeBinary)
    profile_picture_mimetype = db.Column(db.String(50))
    notifications = db.relationship('Notification', backref='user', lazy='dynamic', cascade="all, delete-orphan")


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_otp(self):
        import random
        import datetime
        self.otp_code = "".join([str(random.randint(0, 9)) for _ in range(6)])
        self.otp_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)

    def verify_otp(self, otp_code):
        return self.otp_code == otp_code and self.otp_expiry > datetime.utcnow()

    def set_random_profile_image(self):
        from PIL import Image, ImageDraw, ImageFont
        from io import BytesIO
        import random

        width, height = 200, 200
        bg_color = (random.randint(100, 200), random.randint(100, 200), random.randint(100, 200))
        image = Image.new('RGB', (width, height), color=bg_color)
        draw = ImageDraw.Draw(image)
        
        try:
            font = ImageFont.truetype("arial.ttf", 80)
        except IOError:
            font = ImageFont.load_default()

        initial = self.username[0].upper()
        bbox = draw.textbbox((0, 0), initial, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        text_position = ((width - text_width) / 2, (height - text_height) / 2 - 10)
        draw.text(text_position, initial, fill=(255, 255, 255), font=font)

        buffer = BytesIO()
        image.save(buffer, format="WEBP", quality=80)
        self.profile_picture_data = buffer.getvalue()
        self.profile_picture_mimetype = "image/webp"

    def set_profile_image(self, image_data, mimetype):
        self.profile_picture_data = image_data
        self.profile_picture_mimetype = mimetype

    @staticmethod
    def validate_password_rules(password):
        errors = []
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")
        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter.")
        if not re.search(r"[0-9]", password):
            errors.append("Password must contain at least one number.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append("Password must contain at least one special character.")
        
        return not errors, errors




class Universe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', backref=db.backref('universes', lazy=True, cascade="all, delete-orphan"))

class Character(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    universe_id = db.Column(db.Integer, db.ForeignKey('universe.id'), nullable=False)
    universe = db.relationship('Universe', backref=db.backref('characters', lazy=True))
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref=db.backref('characters', lazy=True, cascade="all, delete-orphan"))

class UniverseCollaboratorRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    universe_id = db.Column(db.Integer, db.ForeignKey('universe.id'), nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    character_name = db.Column(db.String(120), nullable=False)
    character_description = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    universe = db.relationship('Universe', backref='collaboration_requests')
    requester = db.relationship('User', backref=db.backref('collaboration_requests', cascade="all, delete-orphan"))

    def approve(self):
        self.status = "approved"

    def reject(self):
        self.status = "rejected"

class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    issue_type = db.Column(db.String(50), nullable=False, default='issue')  # 'issue' or 'suggestion'
    status = db.Column(db.String(50), default='Open')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('issues', cascade="all, delete-orphan"))

class NotificationSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    user = db.relationship('User', backref=db.backref('notification_settings', uselist=False, cascade="all, delete-orphan"))
    email_on_collaboration_request = db.Column(db.Boolean, default=True)
    email_on_issue_update = db.Column(db.Boolean, default=True)


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    link = db.Column(db.String(255))

    def to_dict(self):
        return {
            'id': self.id,
            'message': self.message,
            'read': self.read,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'link': self.link
        }