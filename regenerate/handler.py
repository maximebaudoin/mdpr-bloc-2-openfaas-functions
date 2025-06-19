import json
import os
import datetime
import string
import secrets
import qrcode
import io
from base64 import b64encode
from flask import make_response

import pyotp
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import psycopg2
import jwt

bcrypt = Bcrypt()

def verify_token(headers):
    secret_key = os.getenv('SECRET_KEY')
    auth_header = headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, make_response(json.dumps({'message': 'Token is missing!'}), 401)
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, make_response(json.dumps({'message': 'Token expired'}), 401)
    except jwt.InvalidTokenError:
        return None, make_response(json.dumps({'message': 'Invalid token'}), 401)

def get_user_by_id(user_id):
    db_url = os.getenv('DATABASE_URL')
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, gendate, expired FROM \"user\" WHERE id = %s", (user_id,)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if row:
        class UserObj:
            def __init__(self, id, username, gendate, expired):
                self.id = id
                self.username = username
                self.gendate = gendate
                self.expired = expired
        return UserObj(row[0], row[1], row[2], row[3])
    return None

def generate_strong_password(length=24):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def handle(req):
    # On suppose que les headers sont passés dans req sous forme JSON avec 'headers' et 'body'
    try:
        event = json.loads(req)
        headers = event.get('headers', {})
        body = event.get('body', '{}')
    except Exception:
        headers = {}
        body = req

    payload, error_response = verify_token(headers)
    if error_response:
        return error_response

    user_id = payload['sub']
    current_user = get_user_by_id(user_id)
    if not current_user:
        response = make_response(json.dumps({'message': 'User not found'}), 404)
        response.headers['Content-Type'] = 'application/json'
        return response

    if not current_user.expired:
        response = make_response(json.dumps({'message': 'Account is not expired'}), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

    new_password = generate_strong_password()
    hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')

    # Nouveau secret MFA
    new_secret = pyotp.random_base32()
    fernet_key = os.environ["ENCRYPTION_KEY"].encode()
    fernet = Fernet(fernet_key)
    encrypted_mfa = fernet.encrypt(new_secret.encode()).decode()

    # QR codes
    totp = pyotp.TOTP(new_secret)
    uri_mfa = totp.provisioning_uri(name=current_user.username, issuer_name="MonApp")
    
    buf_mfa = io.BytesIO()
    qrcode.make(uri_mfa).save(buf_mfa)
    buf_mfa.seek(0)
    qr_mfa_base64 = b64encode(buf_mfa.read()).decode('utf-8')

    buf_pw = io.BytesIO()
    qrcode.make(new_password).save(buf_pw)
    buf_pw.seek(0)
    qr_pw_base64 = b64encode(buf_pw.read()).decode('utf-8')

    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"])
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE "user"
            SET password = %s, mfa = %s, gendate = %s, expired = %s
            WHERE id = %s
        """, (hashed_pw, encrypted_mfa, datetime.datetime.utcnow(), False, current_user.id))
        conn.commit()
        print(f"Generated password for {current_user.username}: {new_password}")
    except Exception as e:
        response = make_response(json.dumps({"error": str(e)}), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    finally:
        if 'cursor' in locals(): cursor.close()
        if 'conn' in locals(): conn.close()

    response = make_response(json.dumps({
        'message': 'Credentials regenerated',
        'new_password': new_password,
        'password_qr_base64': qr_pw_base64,
        'mfa_secret': new_secret,
        'mfa_qr_base64': qr_mfa_base64
    }), 200)
    response.headers['Content-Type'] = 'application/json'
    return response