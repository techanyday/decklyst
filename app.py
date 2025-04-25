from flask import Flask, render_template, request, send_from_directory, redirect, url_for, flash, session, g, jsonify
from flask_mail import Mail, Message
from utils import generate_slides_content, generate_slide_images, create_pptx
from models import get_db, init_db, add_user, get_user_by_email, set_user_pro, is_user_pro, create_user, get_payment_by_reference, update_payment_status
import os
from datetime import datetime
from dotenv import load_dotenv
import requests
from werkzeug.security import check_password_hash, generate_password_hash
import logging
import hmac
import hashlib
import json
from functools import wraps
from flask_dance.contrib.google import make_google_blueprint, google
from oauthlib.oauth2.rfc6749.errors import TokenExpiredError

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev')

# Google OAuth configuration
app.config['GOOGLE_OAUTH_CLIENT_ID'] = os.getenv('GOOGLE_OAUTH_CLIENT_ID')
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = os.getenv('GOOGLE_OAUTH_CLIENT_SECRET')

google_bp = make_google_blueprint(
    client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
    client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
    scope=['profile', 'email']
)
app.register_blueprint(google_bp, url_prefix='/login')

# Email configuration for Bluehost
app.config['MAIL_SERVER'] = 'mail.decklyst.com'  # Your Bluehost domain's mail server
app.config['MAIL_PORT'] = 465  # SSL port
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # full email e.g. noreply@decklyst.com
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Bluehost email password
app.config['MAIL_DEFAULT_SENDER'] = ('decklyst', os.getenv('MAIL_USERNAME'))
app.config['MAIL_MAX_EMAILS'] = 10
app.config['MAIL_ASCII_ATTACHMENTS'] = False
app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_DEBUG'] = True

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('flask.app')

mail = Mail(app)

# Ensure presentations directory exists
os.makedirs('static/presentations', exist_ok=True)

# Initialize database on startup
with app.app_context():
    init_db()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not google.authorized:
            return redirect(url_for('google.login'))
        try:
            resp = google.get('/oauth2/v2/userinfo')
            assert resp.ok, resp.text
        except (TokenExpiredError, AssertionError) as e:
            logger.error(f"OAuth error: {str(e)}")
            return redirect(url_for('google.login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def before_request():
    g.user = None
    if google.authorized:
        try:
            resp = google.get('/oauth2/v2/userinfo')
            if resp.ok:
                user_info = resp.json()
                email = user_info['email']
                g.user = email
                
                # Create user if they don't exist
                if not get_user_by_email(email):
                    create_user(
                        email=email,
                        password=generate_password_hash('not-used'),  # Password not used with OAuth
                        verified=True  # Auto-verified through Google
                    )
        except Exception as e:
            logger.error(f"Error getting user info: {str(e)}")

@app.route('/login')
def login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/')
def index():
    user_tier = 'free'
    if g.user:
        user = get_user_by_email(g.user)
        if user:
            user_tier = user['tier']
    return render_template('index.html', appname='decklyst', user_tier=user_tier)

@app.route('/dashboard')
@login_required
def dashboard():
    email = g.user
    is_pro = is_user_pro(email)
    return render_template('dashboard.html', email=email, is_pro=is_pro)

@app.route('/pay')
@login_required
def pay():
    try:
        return render_template('pay.html',
            user_email=g.user,
            public_key=os.getenv('PAYSTACK_PUBLIC_KEY'),
            monthly_plan=os.getenv('PAYSTACK_MONTHLY_PLAN')
        )
    except Exception as e:
        logging.error(f"Error in pay route: {str(e)}")
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('index'))

@app.route('/payment/verify')
def payment_verify():
    ref = request.args.get('reference')
    payment_type = request.args.get('type')
    
    if not ref:
        return redirect(url_for('pay', status='error', message='No payment reference provided.'))
        
    headers = {
        'Authorization': f'Bearer {os.getenv("PAYSTACK_SECRET_KEY")}',
        'Content-Type': 'application/json',
    }
    
    try:
        response = requests.get(f'https://api.paystack.co/transaction/verify/{ref}', headers=headers)
        data = response.json()
        
        if data['status'] and data['data']['status'] == 'success':
            if g.user:
                if payment_type == 'subscription':
                    # For monthly subscription
                    set_user_pro(g.user, subscription=True)
                    session['subscription'] = True
                    return redirect(url_for('index', status='success', 
                        message='Welcome to Pro! You now have unlimited access.'))
                else:
                    # For single presentation
                    session['single_presentation_credits'] = session.get('single_presentation_credits', 0) + 1
                    return redirect(url_for('index', status='success', 
                        message='Payment successful! You can now generate one premium presentation.'))
                
                session['paid_user'] = True
            return redirect(url_for('index', status='success', 
                message='Payment successful but user session expired. Please log in again.'))
        else:
            return redirect(url_for('pay', status='error', 
                message='Payment verification failed. Please try again or contact support.'))
            
    except Exception as e:
        logging.error(f"Payment verification error: {str(e)}")
        return redirect(url_for('pay', status='error', 
            message='An error occurred during payment verification. Please try again.'))

@app.route('/webhook/paystack', methods=['POST'])
def paystack_webhook():
    # Verify webhook signature
    signature = request.headers.get('x-paystack-signature')
    if not signature:
        return '', 400

    # Get the request body as bytes and compute the hash
    payload = request.get_data()
    hash_value = hmac.new(
        os.getenv('PAYSTACK_SECRET_KEY').encode('utf-8'),
        payload,
        hashlib.sha512
    ).hexdigest()
    
    # Compare signatures
    if hash_value != signature:
        return '', 400

    # Parse the payload
    event_data = request.get_json()
    
    # Get the event type
    event = event_data.get('event')
    
    # Get the payment data
    data = event_data.get('data', {})
    reference = data.get('reference')
    
    if not reference:
        return '', 400
        
    # Get existing payment record
    payment = get_payment_by_reference(reference)
    if not payment:
        return '', 404

    if event == 'charge.success':
        # Extract payment details
        channel = data.get('channel')  # card, mobile_money, bank, etc.
        mobile_number = None
        if channel == 'mobile_money':
            authorization = data.get('authorization', {})
            mobile_number = authorization.get('receiver_bank_account_number')
            
        # Update payment status
        update_payment_status(
            reference=reference,
            status='success',
            transaction_data=json.dumps(data)
        )
        
        # Send SMS notification for mobile money payments
        if channel == 'mobile_money' and mobile_number:
            try:
                # You would integrate with an SMS service here
                # For example, using Twilio or a local SMS gateway
                message = f"Your payment of GH₵{data.get('amount')/100:.2f} for decklyst has been confirmed. Thank you!"
                logging.info(f"Would send SMS to {mobile_number}: {message}")
            except Exception as e:
                logging.error(f"Failed to send SMS: {str(e)}")
                
    elif event == 'charge.failed':
        update_payment_status(
            reference=reference,
            status='failed',
            transaction_data=json.dumps(data)
        )
        
    elif event == 'transfer.failed':
        update_payment_status(
            reference=reference,
            status='transfer_failed',
            transaction_data=json.dumps(data)
        )
        
    return '', 200

@app.route('/payment/status/<reference>')
def check_payment_status(reference):
    if not g.user:
        return jsonify({'error': 'Unauthorized'}), 401
        
    payment = get_payment_by_reference(reference)
    if not payment:
        return jsonify({'error': 'Payment not found'}), 404
        
    return jsonify({
        'status': payment['status'],
        'channel': payment['channel'],
        'amount': payment['amount']
    })

@app.route('/static/presentations/<filename>')
def download_presentation(filename):
    return send_from_directory('static/presentations', filename, as_attachment=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    return redirect(url_for('login'))

@app.route('/verify/<token>')
def verify_email_route(token):
    return redirect(url_for('login'))

@app.route('/send_verification_email')
def send_verification_email():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
