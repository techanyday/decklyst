import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from models import init_db, create_user, get_user_by_email, is_user_pro, set_user_pro
from flask_dance.contrib.google import make_google_blueprint, google
import logging
from datetime import timedelta
import requests
import hmac
import hashlib
import json
from flask_session import Session
from flask import jsonify
from flask import send_from_directory

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv('SECRET_KEY', 'dev')

    # Session configuration
    app.config.update(
        SESSION_TYPE='filesystem',
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
        SESSION_COOKIE_SECURE=os.getenv('FLASK_ENV') == 'production',
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        # Google OAuth configuration
        GOOGLE_OAUTH_CLIENT_ID=os.getenv('GOOGLE_OAUTH_CLIENT_ID'),
        GOOGLE_OAUTH_CLIENT_SECRET=os.getenv('GOOGLE_OAUTH_CLIENT_SECRET'),
        OAUTHLIB_INSECURE_TRANSPORT=os.getenv('FLASK_ENV') != 'production',
        OAUTHLIB_RELAX_TOKEN_SCOPE=True,
        OAUTHLIB_PRESERVE_CSRF_TOKEN=True,
    )

    # Initialize Flask-Session
    Session(app)

    # Initialize database
    with app.app_context():
        init_db()

    # Create and register Google OAuth blueprint
    blueprint = make_google_blueprint(
        client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
        client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
        scope=[
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile'
        ]
    )
    app.register_blueprint(blueprint, url_prefix='/login')

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/login')
    def login():
        # Clear any existing session data
        session.clear()
        if google.authorized:
            return redirect(url_for('dashboard'))
        return render_template('login.html')

    @app.route('/logout')
    def logout():
        # Clear token and user data
        token = blueprint.token
        if token:
            resp = google.post(
                'https://accounts.google.com/o/oauth2/revoke',
                params={'token': token['access_token']},
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
        
        # Clear session
        session.clear()
        return redirect(url_for('login'))

    @app.route('/dashboard')
    def dashboard():
        email = session.get('user_email')
        if not email:
            return redirect(url_for('login'))
        is_pro = is_user_pro(email)
        return render_template('dashboard.html', email=email, is_pro=is_pro)

    @app.route('/pay')
    def pay():
        try:
            return render_template('pay.html',
                user_email=session.get('user_email'),
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
            'Authorization': f"Bearer {os.getenv('PAYSTACK_SECRET_KEY')}",
            'Content-Type': 'application/json'
        }
        
        try:
            # Verify the payment
            response = requests.get(
                f'https://api.paystack.co/transaction/verify/{ref}',
                headers=headers
            )
            
            if response.status_code == 200:
                # Payment verified
                data = response.json()['data']
                
                if data['status'] == 'success':
                    # Update user's pro status
                    email = session.get('user_email')
                    if email:
                        set_user_pro(email, True)
                        flash('Payment successful! You now have access to pro features.', 'success')
                        return redirect(url_for('dashboard'))
                    else:
                        return redirect(url_for('login'))
                else:
                    return redirect(url_for('pay', status='error',
                        message='Payment was not successful. Please try again.'))
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
        if not session.get('user_email'):
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

    if os.getenv('FLASK_ENV') == 'production':
        from flask_talisman import Talisman
        Talisman(app, force_https=True)

    return app

def init_application():
    app = create_app()
    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
