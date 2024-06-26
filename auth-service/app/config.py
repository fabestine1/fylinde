import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'DbSLoIREJtu6z3CVnpTd_DdFeMMRoteCU0UjJcNreZI=')
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI', 'mysql+pymysql://fylinde:Sylvian@db:3307/auth_service_db')
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MFA_SECRET = os.environ.get('MFA_SECRET', '7wjkQT6NVz4a0IoycB1U-1iIwsV7aIbq6GZRHUXu39w=')
    OIDC_CLIENT_ID = os.environ.get('OIDC_CLIENT_ID', 'auth-service')
    OIDC_CLIENT_SECRET = os.environ.get('OIDC_CLIENT_SECRET', 'BtLWa5CI3neQDhentMZFnzOmETKjdXOS')
    OIDC_DISCOVERY_URL = os.environ.get('OIDC_DISCOVERY_URL', 'https://your-keycloak-url/auth/realms/your-realm/.well-known/openid-configuration')
