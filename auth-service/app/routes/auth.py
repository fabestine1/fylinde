# app/routes/auth.py

from flask import Blueprint, request, jsonify, session, redirect, url_for
from models.user import User, db
from utils.token import generate_token
from services.email_service import send_email
from services.mfa_service import generate_mfa_token, verify_mfa_token
import pyotp

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if User.query.filter_by(email=email).first():
        return jsonify({"message": "User already exists"}), 400
    
    new_user = User(username=username, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    
    send_email(email, "Welcome to Our Service", "Thank you for registering!")
    
    return jsonify({"message": "User registered successfully"}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    
    if user and user.check_password(password):
        if user.mfa_enabled:
            mfa_token = generate_mfa_token(user.mfa_secret)
            send_email(email, "Your MFA Code", f"Your MFA code is {mfa_token}")
            return jsonify({"message": "MFA required"}), 206
        
        token = generate_token(user)
        return jsonify({"token": token}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@auth_bp.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    data = request.get_json()
    email = data.get('email')
    mfa_code = data.get('mfa_code')
    
    user = User.query.filter_by(email=email).first()
    
    if user and verify_mfa_token(user.mfa_secret, mfa_code):
        token = generate_token(user)
        return jsonify({"token": token}), 200
    return jsonify({"message": "Invalid MFA code"}), 401

@auth_bp.route('/enable-mfa', methods=['POST'])
def enable_mfa():
    data = request.get_json()
    email = data.get('email')
    
    user = User.query.filter_by(email=email).first()
    
    if user:
        mfa_secret = pyotp.random_base32()
        user.mfa_secret = mfa_secret
        user.mfa_enabled = True
        db.session.commit()
        return jsonify({"message": "MFA enabled", "mfa_secret": mfa_secret}), 200
    return jsonify({"message": "User not found"}), 404

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth_bp.login'))