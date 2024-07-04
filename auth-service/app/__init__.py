from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth
import logging


db = SQLAlchemy()
oauth = OAuth()
migrate = Migrate()  # Initialize the Migrate object


def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')


    # Set up logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)


    # Log the configuration values to ensure they are loaded correctly
    logger.debug(f"OIDC_CLIENT_ID: {app.config['OIDC_CLIENT_ID']}")
    logger.debug(f"OIDC_CLIENT_SECRET: {app.config['OIDC_CLIENT_SECRET']}")
    logger.debug(f"OIDC_DISCOVERY_URL: {app.config['OIDC_DISCOVERY_URL']}")


    db.init_app(app)
    oauth.init_app(app)
    migrate.init_app(app, db)
   
    limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])


    oauth.register(
        name='keycloak',
        client_id=app.config['OIDC_CLIENT_ID'],
        client_secret=app.config['OIDC_CLIENT_SECRET'],
        server_metadata_url=app.config['OIDC_DISCOVERY_URL'],
        client_kwargs={
            'scope': 'openid email profile',
        }
    )


    with app.app_context():
        from .models import user
        from .routes import auth_bp
        db.create_all()
        
        app.register_blueprint(auth_bp, url_prefix='/auth')


    return app
