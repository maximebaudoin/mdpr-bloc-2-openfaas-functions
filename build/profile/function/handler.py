import json
import os
import datetime
from flask import make_response
from flask import request
import jwt
import pyotp
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import psycopg2

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
    # Connexion à la base PostgreSQL
    db_url = os.getenv('DATABASE_URL')
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, gendate, expired FROM \"users\" WHERE id = %s", (user_id,)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if row:
        return {
            'id': row[0],
            'username': row[1],
            'registered_on': row[2].isoformat() if row[2] else None,
            'expired': row[3]
        }
    return None

def handle(req):
    # req est une string, mais OpenFaaS permet de passer les headers via context (non standard)
    # On suppose ici que les headers sont passés dans req sous forme JSON avec 'headers' et 'body'
    try:
        event = json.loads(req)
        headers = request.headers
        body = event.get('body', '{}')
    except Exception:
        # fallback si req est juste le body
        headers = {}
        body = req

    payload, error_response = verify_token(headers)
    if error_response:
        return error_response

    user_id = payload['sub']
    user_data = get_user_by_id(user_id)
    if not user_data:
        response = make_response(json.dumps({'message': 'User not found'}), 404)
        response.headers['Content-Type'] = 'application/json'
        return response

    response = make_response(json.dumps(user_data), 200)
    response.headers['Content-Type'] = 'application/json'
    return response