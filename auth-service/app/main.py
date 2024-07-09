# auth-service/app/main.py

from flask import Flask
from .extensions import db, oauth
from .routes.auth import auth_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    db.init_app(app)
    oauth.init_app(app)

    app.register_blueprint(auth_bp, url_prefix='/auth')

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5004)
