# app/services/mfa_service.py

import pyotp

def generate_mfa_token(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()

def verify_mfa_token(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)
