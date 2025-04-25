from flask import Flask, render_template, request, send_from_directory, redirect, url_for, flash, session, g, jsonify
from flask_mail import Mail, Message
from utils import generate_slides_content, generate_slide_images, create_pptx
from models import get_db, init_db, add_user, get_user_by_email, set_user_pro, is_user_pro, verify_email, is_email_verified, get_payment_by_reference, update_payment_status
import os
from datetime import datetime
from dotenv import load_dotenv
import requests
from werkzeug.security import check_password_hash
import logging
import hmac
import hashlib
import json

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev')

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.bluehost.com'  # Bluehost SMTP server
app.config['MAIL_PORT'] = 465  # Use 465 for SSL
app.config['MAIL_USE_TLS'] = False  # Disable TLS since we're using SSL
app.config['MAIL_USE_SSL'] = True  # Enable SSL
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Your full Bluehost email address
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Your Bluehost email password
app.config['MAIL_DEFAULT_SENDER'] = ('decklyst', os.getenv('MAIL_USERNAME'))
app.config['MAIL_MAX_EMAILS'] = 10
app.config['MAIL_ASCII_ATTACHMENTS'] = False
app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_DEBUG'] = True

# Configure logging for email issues
logging.basicConfig(level=logging.INFO)
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

@app.before_request
def before_request():
    g.user = None
    if 'user_email' in session:
        g.user = session['user_email']

def send_verification_email(email, token):
    verify_url = url_for('verify_email_route', token=token, _external=True)
    
    # HTML version of the email
    html_content = f'''
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .button {{ 
                display: inline-block;
                padding: 10px 20px;
                background-color: #007bff;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                margin: 20px 0;
            }}
            .footer {{ font-size: 12px; color: #666; margin-top: 30px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Welcome to decklyst!</h2>
            <p>Thank you for signing up. Please verify your email address to get started.</p>
            <a href="{verify_url}" class="button">Verify Email Address</a>
            <p>Or copy and paste this link in your browser:</p>
            <p>{verify_url}</p>
            <div class="footer">
                <p>This link will expire in 24 hours.</p>
                <p>If you did not create an account, please ignore this email.</p>
                <p> 2025 decklyst. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    '''
    
    # Plain text version of the email
    text_content = f'''Welcome to decklyst!

Thank you for signing up. Please verify your email address to get started.

Please click the link below or copy it into your browser:
{verify_url}

This link will expire in 24 hours.

If you did not create an account, please ignore this email.

 2025 decklyst'''

    msg = Message(
        subject='Welcome to decklyst - Verify your email',
        sender=('decklyst', app.config['MAIL_USERNAME']),
        recipients=[email]
    )
    msg.body = text_content
    msg.html = html_content
    
    # Add headers to improve deliverability
    msg.extra_headers = {
        'List-Unsubscribe': f'<mailto:{app.config["MAIL_USERNAME"]}?subject=unsubscribe>',
        'Precedence': 'bulk',
        'X-Auto-Response-Suppress': 'OOF, AutoReply',
        'Auto-Submitted': 'auto-generated'
    }
    
    try:
        mail.send(msg)
    except Exception as e:
        logging.error(f"Failed to send verification email: {str(e)}")
        raise

@app.route('/verify/<token>')
def verify_email_route(token):
    if verify_email(token):
        flash('Email verified successfully! You can now log in.', 'success')
    else:
        flash('Invalid or expired verification link.', 'error')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if get_user_by_email(email):
            flash('Email already registered.', 'danger')
            return render_template('register.html')
            
        try:
            verification_token = add_user(email, password)
            send_verification_email(email, verification_token)
            flash('Registration successful! Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('An error occurred. Please try again.', 'error')
            return render_template('register.html')
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = get_user_by_email(email)
        
        if user and check_password_hash(user[2], password):
            if not is_email_verified(email):
                flash('Please verify your email before logging in.', 'error')
                return render_template('login.html')
                
            session['user_email'] = email
            session['paid_user'] = bool(user[3])
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
            
        flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    session.pop('paid_user', None)
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def index():
    user_tier = 'free'
    if g.user and is_user_pro(g.user):
        user_tier = 'paid'
    if request.method == 'POST':
        try:
            topic = request.form.get('topic', '')
            num_slides = int(request.form.get('num_slides', 3))
            color_theme = request.form.get('color_theme', 'blue')
            user_tier = request.form.get('user_tier', 'free')

            if not topic:
                flash('Please enter a topic', 'error')
                return render_template('index.html')

            if user_tier == 'free' and num_slides > 3:
                flash('Upgrade to Pro for more than 3 slides!', 'warning')
                return redirect(url_for('pay'))
            if user_tier == 'paid' and num_slides > 30:
                flash('Paid users can generate up to 30 slides only.')
                return redirect(url_for('index'))

            slides = generate_slides_content(topic, num_slides)
            images = generate_slide_images(slides, user_tier)
            
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            filename = f"decklyst_{timestamp}.pptx"
            output_path = os.path.join('static/presentations', filename)
            create_pptx(slides, images, color_theme, output_path, user_tier)
            
            slide_img_pairs = list(zip(slides, images))

            # Always allow download, watermark for free users is handled in PPTX
            return render_template('preview.html', slide_img_pairs=slide_img_pairs, watermark=(user_tier=='free'), appname='decklyst', pptx_filename=filename)

        except Exception as e:
            error_message = str(e) if str(e) else "An unexpected error occurred. Please try again later."
            flash(error_message, 'error')
            logging.error(f"Error processing request: {str(e)}")
            return render_template('index.html'), 500

    return render_template('index.html', appname='decklyst', user_tier=user_tier)

@app.route('/dashboard')
def dashboard():
    if not g.user:
        flash('Please log in to access your dashboard.', 'warning')
        return redirect(url_for('login'))
    email = g.user
    is_pro = is_user_pro(email)
    return render_template('dashboard.html', email=email, is_pro=is_pro)

@app.route('/pay')
def pay():
    if not g.user:
        return redirect(url_for('login'))
        
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

if __name__ == '__main__':
    app.run(debug=True)
