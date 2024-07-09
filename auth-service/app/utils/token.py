from itsdangerous import URLSafeTimedSerializer
from flask import current_app as app
from flask_mail import Message
from app import mail
import jwt
import pyotp
from datetime import datetime, timedelta
from app.models import User


def create_token(user):
    payload = {
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(minutes=30)  # Token expiration time
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def create_reset_token(user):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return s.dumps(user.email, salt=app.config['SECURITY_PASSWORD_SALT'])

def verify_reset_token(token, expiration=3600):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except:
        return None
    return User.query.filter_by(email=email).first()

def verify_mfa_token(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

def refresh_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        new_payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }
        new_token = jwt.encode(new_payload, app.config['SECRET_KEY'], algorithm='HS256')
        return new_token
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def send_reset_email(user):
    # Placeholder for sending reset email
    pass

def verify_reset_token(token):
    # Placeholder for verifying reset token
    return None

def verify_mfa_token(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)
