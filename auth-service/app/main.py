import logging
from flask import Flask, jsonify, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app and config
app = Flask(__name__)
app.config.from_object('app.config.Config')  # Adjusted import path

# Initialize database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize OAuth
oauth = OAuth(app)
oauth.register(
    name='keycloak',
    client_id=app.config['OIDC_CLIENT_ID'],
    client_secret=app.config['OIDC_CLIENT_SECRET'],
    server_metadata_url=app.config['OIDC_DISCOVERY_URL'],
    client_kwargs={
        'scope': 'openid email profile',
    }
)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

@app.route('/')
def home():
    logger.debug("Home route accessed")
    return jsonify(message="Auth Service Home")

@app.route('/login')
def login():
    logger.debug("Login route accessed")
    redirect_uri = url_for('authorize', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    logger.debug("Authorize route accessed")
    token = oauth.keycloak.authorize_access_token()
    user = oauth.keycloak.parse_id_token(token)
    return jsonify(user=user)

@app.route('/register', methods=['POST'])
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

if __name__ == '__main__':
    logger.debug("Starting Flask application")
    app.run(host='0.0.0.0', port=5000)
