from jwt import PyJWKClient
from flask import requests, jsonify
import jwt


def get_public_key():
    url = "http://keycloak:8080/realms/fylinde_ecommerce/protocol/openid-connect/certs"
    response = requests.get(url)
    jwks = response.json()
    return jwks

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
def verify_token(token):
    url = "http://keycloak:8080/realms/fylinde_ecommerce/protocol/openid-connect/certs"
    jwks_client = PyJWKClient(url)
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    try:
        payload = jwt.decode(token, signing_key.key, algorithms=["RS256"], audience="auth-service")
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None