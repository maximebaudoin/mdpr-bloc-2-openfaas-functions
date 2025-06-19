import json
import os
import datetime
from flask import make_response
import jwt
import pyotp
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import psycopg2

bcrypt = Bcrypt()

def handle(req):
    data = json.loads(req)

    username = data.get('username')

    if not username:
        response = make_response(json.dumps({'message': 'Username is required'}), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

    try:
        conn = psycopg2.connect(os.environ["DATABASE_URL"])
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s LIMIT 1", (username,))
        user = cursor.fetchone()
    except Exception as e:
        response = make_response(json.dumps({"error": str(e)}), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

    print(f"Login attempt for {data['username']} with password: {data['password']}")

    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        response = make_response(json.dumps({"message": 'Invalid credentials'}), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if user.mfa:
        mfa_code = data.get('mfa_code')
        if not mfa_code:
            response = make_response(json.dumps({"message": 'MFA code required'}), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        totp = pyotp.TOTP(user.mfa)
        try:
            fernet_key = os.environ["ENCRYPTION_KEY"].encode()
            fernet = Fernet(fernet_key)
            decrypted_secret = fernet.decrypt(user.mfa.encode()).decode()
            totp = pyotp.TOTP(decrypted_secret)
            if not totp.verify(mfa_code, valid_window=1):
                response = make_response(json.dumps({"message": 'Invalid MFA code'}), 401)
                response.headers['Content-Type'] = 'application/json'
                return response
        except Exception as e:
            print("Erreur déchiffrement MFA :", str(e))
            response = make_response(json.dumps({"message": 'MFA verification error'}), 400)
            response.headers['Content-Type'] = 'application/json'
            return response

        mfa_code = data.get('mfa_code')

        if not mfa_code:
            response = make_response(json.dumps({"message": 'MFA code required'}), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

    token = jwt.encode(
        {
            'sub': str(user.id),
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        },
        os.environ["SECRET_KEY"],
        algorithm='HS256'
    )

    if isinstance(token, bytes):
        token = token.decode('utf-8')

    six_months_ago = datetime.datetime.utcnow() - datetime.timedelta(days=180)
    if user.gendate < six_months_ago:
        user.expired = True
        response = make_response(json.dumps({'token': token, 'status': "expired"}), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    response = make_response(json.dumps({'token': token, 'status': "authentified"}), 200)
    response.headers['Content-Type'] = 'application/json'
    return response