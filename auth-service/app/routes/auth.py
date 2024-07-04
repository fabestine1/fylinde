from flask import Blueprint, jsonify, request, redirect, url_for, session, Response
from werkzeug.security import generate_password_hash
from app import db, oauth
from app.models.user import User
import logging
import jwt
from jwt import PyJWKClient


auth_bp = Blueprint('auth_bp', __name__)


logger = logging.getLogger(__name__)


def verify_user(request):
    headers = dict(request.headers)
    auth = headers.get("Authorization")
    if not auth:
        return None, {"status_code": 401, "message": "Authorization header missing"}


    token = auth.replace("Bearer", "").strip()
    url = "http://keycloak:8080/realms/fylinde_ecommerce/protocol/openid-connect/certs"
    jwks_client = PyJWKClient(url)
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    try:
        data = jwt.decode(
            token,
            signing_key.key,
            audience="account",
            algorithms=["RS256"]
        )
        return data, None
    except jwt.ExpiredSignatureError:
        return None, {"status_code": 401, "message": "Expired Token"}
    except jwt.InvalidTokenError:
        return None, {"status_code": 401, "message": "Invalid Token"}


@auth_bp.route('/')
def home():
    logger.debug("Home route accessed")
    return jsonify(message="Auth Service Home in routes auth")


@auth_bp.route('/login')
def login():
    logger.debug("Login route accessed")
    try:
        redirect_uri = url_for('auth_bp.callback', _external=True)
        logger.debug(f"Redirect URI: {redirect_uri}")
        authorize_url = oauth.keycloak.authorize_redirect(redirect_uri)
        logger.debug(f"Authorize URL: {authorize_url}")
        return authorize_url
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@auth_bp.route('/callback')
def callback():
    logger.debug("Callback route accessed")
    try:
        token = oauth.keycloak.authorize_access_token()
        user = oauth.keycloak.parse_id_token(token)
        session['user'] = user
        logger.debug(f"User {user} logged in")
        return redirect(url_for('auth_bp.home'))
    except Exception as e:
        logger.error(f"Callback error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@auth_bp.route('/logout')
def logout():
    logger.debug("Logout route accessed")
    session.pop('user', None)
    return redirect(url_for('auth_bp.home'))


@auth_bp.route('/user')
def user():
    logger.debug("User route accessed")
    user = session.get('user')
    if user:
        return jsonify(user)
    return jsonify(message="User not logged in"), 401


@auth_bp.route('/authorize')
def authorize():
    logger.debug("Authorize route accessed")
    try:
        token = oauth.keycloak.authorize_access_token()
        user = oauth.keycloak.parse_id_token(token)
        return jsonify(user=user)
    except Exception as e:
        logger.error(f"Authorization error: {str(e)}")
        return jsonify({"error": "Authorization failed"}), 500


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


@auth_bp.route('/api/protected')
def protected_route():
    logger.debug("Protected route accessed")
    token_data, error = verify_user(request)
    if error:
        return jsonify(error), error["status_code"]
    return jsonify({"Result": "Success", "request_token": token_data})
