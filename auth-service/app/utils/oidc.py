# app/utils/oidc.py

from authlib.integrations.flask_client import OAuth
from flask import current_app

oauth = OAuth()

def configure_oauth(app):
    oauth.init_app(app)
    oauth.register(
        name='keycloak',
        client_id=current_app.config['OIDC_CLIENT_ID'],
        client_secret=current_app.config['OIDC_CLIENT_SECRET'],
        server_metadata_url=current_app.config['OIDC_DISCOVERY_URL'],
        client_kwargs={
            'scope': 'openid profile email'
        }
    )
