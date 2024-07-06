from jwt import PyJWKClient
from flask import request, jsonify
import jwt


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
