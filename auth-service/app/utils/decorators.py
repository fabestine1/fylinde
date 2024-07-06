from functools import wraps
from flask import request, jsonify
from utils.oidc import verify_token

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": "Authorization header missing"}), 401

        token = auth_header.split(" ")[1]
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({"error": "Authorization header missing"}), 401

            token = auth_header.split(" ")[1]
            payload = verify_token(token)
            if not payload or role not in payload.get('roles', []):
                return jsonify({"error": "Access denied"}), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator
