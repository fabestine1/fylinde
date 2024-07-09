# auth-service/app/routes/auth.py

from flask import Blueprint, jsonify, request, session
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from ..extensions import db, oauth
from ..models.user import User
import logging
import jwt
import pyotp
from jwt import PyJWKClient
import datetime
from functools import wraps
from ..utils.decorators import login_required, role_required
from ..utils.token import create_token, refresh_token, send_reset_email, verify_reset_token, verify_mfa_token
from ..utils.oidc import  verify_token

auth_bp = Blueprint('auth_bp', __name__)

logger = logging.getLogger(__name__)

# Secret key for JWT encoding/decoding
SECRET_KEY = 'DbSLoIREJtu6z3CVnpTd_DdFeMMRoteCU0UjJcNreZI='

# Keycloak settings
KEYCLOAK_URL = 'http://keycloak:8080'
REALM_NAME = 'fylinde_ecommerce'
CLIENT_ID = 'auth-service'
CLIENT_SECRET = 'G7591pgXLIA7EJyiHx0dqipaPNp7EcCW'
REDIRECT_URI = 'http://localhost:5004/authorize'


@auth_bp.route('/')
def home():
    logger.debug("Home route accessed")
    return jsonify(message="Auth Service Home in routes auth")

# Function to create JWT token
def create_token(user):
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, SECRET_KEY, algorithm='HS256')
    return token

# Decorator to verify JWT token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'error': 'Token is invalid!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


@auth_bp.route('/login', methods=['POST'])
def login():
    logger.debug("Login route accessed")
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing credentials!'}), 400

    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        token = create_token(user)
        return jsonify({'token': token}), 200
    else:
        return jsonify({'error': 'Invalid credentials!'}), 401

@auth_bp.route('/register', methods=['POST'])
def register():
    logger.debug("Register route accessed")
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        logger.error("Missing username, email, or password")
        return jsonify({"error": "Missing username, email or password"}), 400

    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        logger.error("User with this username or email already exists")
        return jsonify({"error": "User with this username or email already exists"}), 400

    password_hash = generate_password_hash(password)
    new_user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(new_user)
    db.session.commit()

    logger.debug("User registered successfully")
    return jsonify({"message": "User registered successfully"}), 201

@auth_bp.route('/authorize', methods=['GET'])
def authorize():
    logger.debug("Authorize route accessed")
    code = request.args.get('code')
    if not code:
        return jsonify({"error": "Authorization code is missing!"}), 400

    token_url = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token"
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    token_response = requests.post(token_url, data=data, headers=headers)

    if token_response.status_code != 200:
        return jsonify({"error": "Failed to get tokens from Keycloak"}), token_response.status_code

    tokens = token_response.json()
    id_token = tokens.get('id_token')

    # Decode the ID token
    payload = jwt.decode(id_token, options={"verify_signature": False})
    user_info = {
        "username": payload['preferred_username'],
        "email": payload['email']
    }

    # Here, you can create the user in your database if it doesn't exist
    user = User.query.filter_by(username=user_info["username"]).first()
    if not user:
        user = User(username=user_info["username"], email=user_info["email"], password_hash="")
        db.session.add(user)
        db.session.commit()

    # Create a session token for the user
    session_token = create_token(user)

    return jsonify({"user": user_info, "session_token": session_token}), 200

@auth_bp.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    logger.debug("Protected route accessed")
    return jsonify({"message": f"Access granted, {current_user.username}!"}), 200

@auth_bp.route('/admin')
@login_required
@role_required('admin')
def admin():
    user = session.get('user')
    if 'admin' not in user.get('roles', []):
        return jsonify(message="You do not have access to this resource"), 403
    return jsonify(message="Welcome, admin!")

@auth_bp.route('/request-password-reset', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if user:
        send_reset_email(user)
    return jsonify({"message": "If the email is registered, you will receive a password reset link"}), 200

@auth_bp.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    user = verify_reset_token(token)
    if not user:
        return jsonify({"error": "Invalid or expired token"}), 400

    data = request.get_json()
    password = data.get('password')
    user.password_hash = generate_password_hash(password)
    db.session.commit()
    return jsonify({"message": "Password has been reset"}), 200

def get_current_user():
    auth_header = request.headers.get('Authorization')
    if auth_header:
        token = auth_header.split(" ")[1]
        payload = verify_token(token)
        if payload:
            return User.query.get(payload['user_id'])
    return None

@auth_bp.route('/enable-mfa', methods=['POST'])
def enable_mfa():
    user = get_current_user()
    mfa_secret = pyotp.random_base32()
    user.mfa_secret = mfa_secret
    user.mfa_enabled = True
    db.session.commit()
    return jsonify({"mfa_secret": mfa_secret}), 200

@auth_bp.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    data = request.get_json()
    token = data.get('token')
    user = get_current_user()
    if verify_mfa_token(user.mfa_secret, token):
        return jsonify({"message": "MFA verified"}), 200
    else:
        return jsonify({"error": "Invalid MFA token"}), 400

@auth_bp.route('/profile', methods=['GET'])
def get_profile():
    user = get_current_user()
    return jsonify({
        "username": user.username,
        "email": user.email
    })

@auth_bp.route('/profile', methods=['PUT'])
def update_profile():
    user = get_current_user()
    data = request.get_json()
    user.email = data.get('email', user.email)
    if 'password' in data:
        user.password_hash = generate_password_hash(data['password'])
    db.session.commit()
    return jsonify({"message": "Profile updated"}), 200

@auth_bp.route('/logout', methods=['POST'])
def logout():
    return jsonify({"message": "Logged out"}), 200

@auth_bp.route('/refresh-token', methods=['POST'])
def refresh_token_route():
    token = request.headers.get('Authorization').split(' ')[1]
    new_token = refresh_token(token)
    if new_token:
        return jsonify({"token": new_token}), 200
    else:
        return jsonify({"error": "Invalid token"}), 401

def verify_token(token):
    url = "http://keycloak:8080/realms/fylinde_ecommerce/protocol/openid-connect/certs"
    jwks_client = jwt.PyJWKClient(url)
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    try:
        payload = jwt.decode(token, signing_key.key, algorithms=["RS256"], audience="auth-service")
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None