import sqlite3
from flask import g
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer

DATABASE = 'users.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    cursor = db.cursor()
    
    # Users table with subscription info and email verification
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_pro INTEGER DEFAULT 0,
            subscription_active INTEGER DEFAULT 0,
            subscription_end_date TIMESTAMP,
            single_credits INTEGER DEFAULT 0,
            email_verified INTEGER DEFAULT 0,
            verification_token TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Payment history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount DECIMAL(10,2) NOT NULL,
            payment_type TEXT NOT NULL,
            reference TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL,
            channel TEXT,
            mobile_number TEXT,
            transaction_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    db.commit()

def add_user(email, password):
    db = get_db()
    cursor = db.cursor()
    password_hash = generate_password_hash(password)
    
    # Generate verification token
    s = URLSafeTimedSerializer('your-secret-key')  # Use app.config['SECRET_KEY'] in production
    verification_token = s.dumps(email, salt='email-verify')
    
    cursor.execute('''
        INSERT INTO users (email, password_hash, verification_token) 
        VALUES (?, ?, ?)
    ''', (email, password_hash, verification_token))
    db.commit()
    return verification_token

def verify_email(token):
    s = URLSafeTimedSerializer('your-secret-key')  # Use app.config['SECRET_KEY'] in production
    try:
        email = s.loads(token, salt='email-verify', max_age=86400)  # Token valid for 24 hours
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            UPDATE users 
            SET email_verified = 1, verification_token = NULL 
            WHERE email = ? AND verification_token = ?
        ''', (email, token))
        db.commit()
        return True
    except:
        return False

def get_user_by_email(email):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users WHERE email=?', (email,))
    return cursor.fetchone()

def is_email_verified(email):
    user = get_user_by_email(email)
    return user and user['email_verified'] == 1

def set_user_pro(email, subscription=False):
    db = get_db()
    cursor = db.cursor()
    
    if subscription:
        # Set subscription end date to 30 days from now
        sub_end = datetime.now() + timedelta(days=30)
        cursor.execute('''
            UPDATE users 
            SET is_pro=1, 
                subscription_active=1, 
                subscription_end_date=? 
            WHERE email=?
        ''', (sub_end, email))
    else:
        # Just update is_pro status
        cursor.execute('UPDATE users SET is_pro=1 WHERE email=?', (email,))
    
    db.commit()

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

def is_user_pro(email):
    user = get_user_by_email(email)
    if not user:
        return False
        
    # Check if user has an active subscription
    if user['subscription_active'] and user['subscription_end_date']:
        end_date = datetime.strptime(user['subscription_end_date'], '%Y-%m-%d %H:%M:%S')
        if end_date > datetime.now():
            return True
            
    # Check if user has single presentation credits
    if user['single_credits'] > 0:
        return True
        
    return False

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

def cancel_subscription(email):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        UPDATE users 
        SET subscription_active=0,
            subscription_end_date=NULL
        WHERE email=?
    ''', (email,))
    db.commit()

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
                    SET is_pro = 1,
                        subscription_active = 1,
                        subscription_end_date = datetime('now', '+30 days')
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
