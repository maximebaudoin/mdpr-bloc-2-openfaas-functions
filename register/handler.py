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

bcrypt = Bcrypt()

def generate_strong_password(length=24):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def handle(req):
    data = json.loads(req)
    username = data.get('username')

    if not username:
        return json.dumps({'message': 'Username is required'}), 400

    password = generate_strong_password()

    # === Hash + chiffrement ===
    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

    # === Générer secret MFA ===
    secret = pyotp.random_base32()
    fernet_key = os.environ["ENCRYPTION_KEY"].encode()
    fernet = Fernet(fernet_key)
    encrypted_mfa = fernet.encrypt(secret.encode()).decode()

    # === QR Code MFA ===
    totp = pyotp.TOTP(secret)
    uri_mfa = totp.provisioning_uri(name=username, issuer_name="MonApp")
    img_mfa = qrcode.make(uri_mfa)
    buf_mfa = io.BytesIO()
    img_mfa.save(buf_mfa)
    buf_mfa.seek(0)
    qr_mfa_base64 = b64encode(buf_mfa.read()).decode('utf-8')

    # === QR Code du mot de passe ===
    img_pw = qrcode.make(password)
    buf_pw = io.BytesIO()
    img_pw.save(buf_pw)
    buf_pw.seek(0)
    qr_pw_base64 = b64encode(buf_pw.read()).decode('utf-8')

    # === Créer et enregistrer l'utilisateur ===
    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"])
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, password, mfa, gendate, expired)
            VALUES (%s, %s, %s, %s, %s)
        """, (username, hashed_pw, encrypted_mfa, datetime.datetime.utcnow(), False))
        conn.commit()
        print(f"Generated password for {username}: {password}")
    except Exception as e:
        response = make_response(json.dumps({"error": str(e)}), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

    response = make_response(json.dumps({
        'message': 'User registered',
        'user_id': cursor.lastrowid,
        'password': password,
        'password_qr_base64': qr_pw_base64,
        'mfa_secret': secret,
        'mfa_qr_base64': qr_mfa_base64
    }), 201)
    response.headers['Content-Type'] = 'application/json'
    return response