# auth-service/app/__init__.py

from flask import Flask
import logging
from .config import Config
from .extensions import db, oauth, migrate, limiter
from .routes.auth import auth_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Set up logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    # Log the configuration values to ensure they are loaded correctly
    logger.debug(f"OIDC_CLIENT_ID: {app.config['OIDC_CLIENT_ID']}")
    logger.debug(f"OIDC_CLIENT_SECRET: {app.config['OIDC_CLIENT_SECRET']}")
    logger.debug(f"OIDC_DISCOVERY_URL: {app.config['OIDC_DISCOVERY_URL']}")

    # Initialize extensions
    db.init_app(app)
    oauth.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)

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
        from .models.user import User  # Ensure User is imported from the correct location
        db.create_all()

        app.register_blueprint(auth_bp, url_prefix='/auth')
        logger.debug("Blueprint auth_bp registered with url_prefix '/auth'")

        # Log all routes
        for rule in app.url_map.iter_rules():
            logger.debug(f"Endpoint: {rule.endpoint}, URL: {rule}")

    return app
