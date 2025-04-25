from flask import Flask, render_template, request, send_from_directory, redirect, url_for, flash, session, g
from flask_mail import Mail, Message
from utils import generate_slides_content, generate_slide_images, create_pptx
from models import get_db, init_db, add_user, get_user_by_email, set_user_pro, is_user_pro, verify_email, is_email_verified
import os
from datetime import datetime
from dotenv import load_dotenv
import requests
from werkzeug.security import check_password_hash
import logging

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev')

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

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
    msg = Message('Verify your email',
                 recipients=[email])
    msg.body = f'''Please click the link below to verify your email address:
{verify_url}

This link will expire in 24 hours.

If you did not create an account, please ignore this email.
'''
    mail.send(msg)

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
            return render_template('preview.html', slide_img_pairs=slide_img_pairs, watermark=(user_tier=='free'), appname='Decklyst', pptx_filename=filename)

        except Exception as e:
            error_message = str(e) if str(e) else "An unexpected error occurred. Please try again later."
            flash(error_message, 'error')
            logging.error(f"Error processing request: {str(e)}")
            return render_template('index.html'), 500

    return render_template('index.html', appname='Decklyst', user_tier=user_tier)

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
        flash('Please log in to access premium features.', 'warning')
        return redirect(url_for('login'))
    return render_template('pay.html', 
                         paystack_public_key=os.getenv('PAYSTACK_PUBLIC_KEY'),
                         monthly_plan_code=os.getenv('PAYSTACK_MONTHLY_PLAN'),
                         user_email=g.user)

@app.route('/payment/verify')
def payment_verify():
    ref = request.args.get('reference')
    payment_type = request.args.get('type')
    
    if not ref:
        flash('No payment reference provided.', 'danger')
        return redirect(url_for('pay'))
        
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
                    flash('Welcome to Pro! You now have unlimited access.', 'success')
                else:
                    # For single presentation
                    session['single_presentation_credits'] = session.get('single_presentation_credits', 0) + 1
                    flash('Payment successful! You can now generate one premium presentation.', 'success')
                
                session['paid_user'] = True
            return redirect(url_for('index'))
        else:
            flash('Payment verification failed.', 'danger')
            return redirect(url_for('pay'))
            
    except Exception as e:
        logging.error(f"Payment verification error: {str(e)}")
        flash('An error occurred during payment verification.', 'danger')
        return redirect(url_for('pay'))

@app.route('/webhook/paystack', methods=['POST'])
def paystack_webhook():
    # Verify webhook signature
    signature = request.headers.get('x-paystack-signature')
    if not signature:
        return '', 400
        
    # Get the request body
    payload = request.get_json()
    
    # Handle different event types
    event = payload.get('event')
    if event == 'charge.success':
        data = payload['data']
        email = data['customer']['email']
        metadata = data.get('metadata', {})
        payment_type = metadata.get('payment_type')
        
        if payment_type == 'subscription':
            set_user_pro(email, subscription=True)
        else:
            # Add single presentation credit
            with app.app_context():
                user = get_user_by_email(email)
                if user:
                    credits = user.get('presentation_credits', 0)
                    user['presentation_credits'] = credits + 1
                    
    elif event == 'subscription.disable':
        email = payload['data']['customer']['email']
        set_user_pro(email, subscription=False)
        
    return '', 200

@app.route('/static/presentations/<filename>')
def download_presentation(filename):
    return send_from_directory('static/presentations', filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
