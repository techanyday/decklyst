import sqlite3
from flask import g
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
import logging

DATABASE = 'users.db'
logger = logging.getLogger(__name__)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    with open('schema.sql', 'r') as f:
        db.executescript(f.read())

def create_user(email, password, verified=True):
    db = get_db()
    try:
        db.execute(
            'INSERT INTO users (email, password, verified, tier) VALUES (?, ?, ?, ?)',
            (email, password, verified, 'free')
        )
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        return False

def get_user_by_email(email):
    db = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE email = ?', (email,)
    ).fetchone()
    if user:
        return {
            'email': user[1],
            'password': user[2],
            'verified': user[3],
            'tier': user[4]
        }
    return None

def is_user_pro(email):
    user = get_user_by_email(email)
    return user and user['tier'] == 'paid'

def set_user_pro(email):
    db = get_db()
    try:
        db.execute(
            'UPDATE users SET tier = ? WHERE email = ?',
            ('paid', email)
        )
        db.commit()
        return True
    except Exception as e:
        logger.error(f"Error upgrading user: {str(e)}")
        return False

def add_presentation_credit(email, credits=1):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        UPDATE users 
        SET single_credits = single_credits + ? 
        WHERE email=?
    ''', (credits, email))
    db.commit()

def use_presentation_credit(email):
    db = get_db()
    cursor = db.cursor()
    
    # First check if user has credits
    user = get_user_by_email(email)
    if not user['single_credits'] > 0:
        return False
        
    cursor.execute('''
        UPDATE users 
        SET single_credits = single_credits - 1 
        WHERE email=? AND single_credits > 0
    ''', (email,))
    db.commit()
    return True

def record_payment(email, amount, payment_type, reference, status='success'):
    db = get_db()
    cursor = db.cursor()
    
    # Get user id
    cursor.execute('SELECT id FROM users WHERE email=?', (email,))
    user = cursor.fetchone()
    if not user:
        return False
        
    cursor.execute('''
        INSERT INTO payments (user_id, amount, payment_type, reference, status)
        VALUES (?, ?, ?, ?, ?)
    ''', (user['id'], amount, payment_type, reference, status))
    db.commit()
    return True

def create_payment(user_id, amount, payment_type, reference, status, channel=None, mobile_number=None):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO payments (
            user_id, 
            amount, 
            payment_type, 
            reference, 
            status, 
            channel,
            mobile_number
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, amount, payment_type, reference, status, channel, mobile_number))
    db.commit()

def update_payment_status(reference, status, transaction_data=None):
    db = get_db()
    cursor = db.cursor()
    
    # Update payment status
    cursor.execute('''
        UPDATE payments 
        SET status = ?,
            transaction_data = ?
        WHERE reference = ?
    ''', (status, transaction_data, reference))
    
    # If payment is successful, update user benefits
    if status == 'success':
        cursor.execute('SELECT user_id, payment_type FROM payments WHERE reference = ?', (reference,))
        payment = cursor.fetchone()
        if payment:
            if payment['payment_type'] == 'subscription':
                cursor.execute('''
                    UPDATE users 
                    SET tier = 'paid'
                    WHERE id = ?
                ''', (payment['user_id'],))
            else:
                cursor.execute('''
                    UPDATE users 
                    SET single_credits = single_credits + 1
                    WHERE id = ?
                ''', (payment['user_id'],))
    
    db.commit()
    return True

def get_payment_by_reference(reference):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT p.*, u.email 
        FROM payments p
        JOIN users u ON p.user_id = u.id
        WHERE p.reference = ?
    ''', (reference,))
    return cursor.fetchone()
