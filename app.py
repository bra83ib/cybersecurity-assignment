from flask import Flask, render_template, url_for, flash, redirect, request, session, send_from_directory, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, TextAreaField, FileField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Regexp, NumberRange
from cryptography.fernet import Fernet
import os
import logging
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import bleach
import hashlib
import secrets
import re
import html

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fintech.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['SESSION_TIMEOUT'] = 300  # 5 minutes in seconds
app.config['MAX_LOGIN_ATTEMPTS'] = 5
app.config['MAX_INPUT_LENGTH'] = 5000  # Maximum input length for text fields

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Setup logging
logging.basicConfig(filename='audit.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Generate encryption key for the app (store securely in production)
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

# Enhanced input sanitization function
def sanitize_input(text, max_length=None):
    """Enhanced input sanitization with length validation and XSS protection"""
    if not isinstance(text, str):
        return text
    
    # Length validation
    if max_length and len(text) > max_length:
        raise ValidationError(f'Input too long (max {max_length} characters)')
    
    # Remove dangerous characters and HTML tags
    sanitized = bleach.clean(text, tags=[], attributes={}, strip=True)
    
    # Additional HTML encoding for safety
    sanitized = html.escape(sanitized)
    
    return sanitized

# SQL Injection detection
def detect_sql_injection(text):
    """Detect potential SQL injection patterns"""
    if not isinstance(text, str):
        return False
    
    sql_patterns = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b)",
        r"(\b(UNION|OR)\s+\d+\s*=\s*\d+)",
        r"(--|;|/\*|\*/)",
        r"(\bOR\s+1\s*=\s*1)",
        r"(\bAND\s+1\s*=\s*1)",
        r"(\'\s*(OR|AND)\s*\'\w+\'\s*=\s*\'\w+)",
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

# Session timeout check
@app.before_request
def check_session_timeout():
    # Skip timeout check for static files and certain endpoints
    if request.endpoint and (request.endpoint.startswith('static') or request.endpoint in ['login', 'register', 'home']):
        return
        
    if current_user.is_authenticated:
        last_activity = session.get('last_activity')
        if last_activity:
            try:
                last_time = datetime.fromisoformat(last_activity)
                if datetime.now() - last_time > timedelta(seconds=app.config['SESSION_TIMEOUT']):
                    audit_log(current_user.id, 'Session Timeout', f'User {current_user.username} session expired')
                    logout_user()
                    session.clear()
                    flash('Session expired. Please log in again.', 'warning')
                    return redirect(url_for('login'))
            except (ValueError, TypeError):
                # Invalid session data, clear it
                session.clear()
                logout_user()
                return redirect(url_for('login'))
        session['last_activity'] = datetime.now().isoformat()

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    balance = db.Column(db.Float, nullable=False, default=1000.0)  # Starting balance
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    
    def is_account_locked(self):
        if self.account_locked_until and datetime.utcnow() < self.account_locked_until:
            return True
        return False
    
    def lock_account(self):
        self.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
        self.failed_login_attempts = 0

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # deposit, withdraw, transfer
    recipient = db.Column(db.String(20), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    encrypted_details = db.Column(db.Text, nullable=True)  # Encrypted sensitive data

    def __repr__(self):
        return f"Transaction('{self.type}', {self.amount})"

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

# Enhanced audit logging function
def audit_log(user_id, action, details):
    try:
        log = AuditLog(
            user_id=user_id, 
            action=action, 
            details=sanitize_input(str(details), 1000),  # Limit details length
            ip_address=request.remote_addr if request else 'unknown',
            user_agent=request.headers.get('User-Agent', 'unknown')[:255] if request else 'unknown'  # Limit user agent length
        )
        db.session.add(log)
        db.session.commit()
        logging.info(f'User {user_id}: {action} - {details}')
    except Exception as e:
        logging.error(f'Failed to create audit log: {str(e)}')

# Forms with enhanced validation
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=20, message="Username must be between 3 and 20 characters"),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Username must contain only letters, numbers, and underscores")
    ])
    email = StringField('Email', validators=[
        DataRequired(), 
        Email(message="Please enter a valid email address"),
        Length(max=120, message="Email too long")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, max=128, message="Password must be at least 8 characters long"),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$', 
               message="Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match")
    ])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        if not username.data or not username.data.strip():
            raise ValidationError('Username is required.')
        
        # Check for SQL injection
        if detect_sql_injection(username.data):
            audit_log(None, 'SQL Injection Attempt', f'Registration username: {username.data}')
            raise ValidationError('Invalid characters detected.')
        
        # Check for XSS attempts
        if '<' in username.data or '>' in username.data or 'script' in username.data.lower():
            audit_log(None, 'XSS Attempt', f'Registration username: {username.data}')
            raise ValidationError('Invalid characters detected.')
        
        try:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')
        except Exception:
            pass

    def validate_email(self, email):
        if not email.data or not email.data.strip():
            raise ValidationError('Email is required.')
        
        # Enhanced email validation
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email.data):
            raise ValidationError('Please enter a valid email address.')
        
        # Check for SQL injection in email
        if detect_sql_injection(email.data):
            audit_log(None, 'SQL Injection Attempt', f'Registration email: {email.data}')
            raise ValidationError('Invalid email format.')
        
        try:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')
        except Exception:
            pass

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(), 
        Email(),
        Length(max=120, message="Email too long")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(max=128, message="Password too long")
    ])
    submit = SubmitField('Login')

    def validate_email(self, email):
        # Check for SQL injection attempts
        if detect_sql_injection(email.data):
            audit_log(None, 'SQL Injection Attempt', f'Login email: {email.data}')
            raise ValidationError('Invalid email format.')

    def validate_password(self, password):
        # Check for SQL injection attempts
        if detect_sql_injection(password.data):
            audit_log(None, 'SQL Injection Attempt', 'Login password field')
            raise ValidationError('Invalid input detected.')

class TransferForm(FlaskForm):
    recipient = StringField('Recipient Email', validators=[
        DataRequired(),
        Email(message="Please enter a valid email address"),
        Length(max=120, message="Email too long")
    ])
    amount = FloatField('Amount', validators=[
        DataRequired(),
        NumberRange(min=0.01, max=100000, message="Amount must be between $0.01 and $100,000")
    ])
    submit = SubmitField('Transfer')

    def validate_recipient(self, recipient):
        if detect_sql_injection(recipient.data):
            audit_log(current_user.id if current_user.is_authenticated else None, 
                     'SQL Injection Attempt', f'Transfer recipient: {recipient.data}')
            raise ValidationError('Invalid recipient format.')

# Enhanced EncryptDecryptForm with action selection
class EncryptDecryptForm(FlaskForm):
    text = TextAreaField('Text', validators=[
        DataRequired(),
        Length(max=app.config['MAX_INPUT_LENGTH'], message=f"Text too long (max {app.config['MAX_INPUT_LENGTH']} characters)")
    ])
    action = SelectField('Action', choices=[('encrypt', 'Encrypt'), ('decrypt', 'Decrypt')], validators=[DataRequired()])
    submit = SubmitField('Process')

    def validate_text(self, text):
        # Check for extremely long input (potential DoS)
        if len(text.data) > app.config['MAX_INPUT_LENGTH']:
            audit_log(current_user.id if current_user.is_authenticated else None, 
                     'Input Length Attack', f'Text length: {len(text.data)}')
            raise ValidationError(f'Input too long (max {app.config["MAX_INPUT_LENGTH"]} characters)')

# Add validation for upload form
class UploadForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])
    submit = SubmitField('Upload')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=20),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Username must contain only letters, numbers, and underscores")
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update Profile')
    
    def validate_username(self, username):
        if current_user.is_authenticated:
            sanitized = sanitize_input(username.data)
            if sanitized != username.data:
                raise ValidationError('Username contains invalid characters.')

class DepositForm(FlaskForm):
    amount = FloatField('Amount', validators=[
        DataRequired(),
        NumberRange(min=0.01, max=50000, message="Amount must be between $0.01 and $50,000")
    ])
    submit = SubmitField('Deposit Money')

class WithdrawForm(FlaskForm):
    amount = FloatField('Amount', validators=[
        DataRequired(),
        NumberRange(min=0.01, max=50000, message="Amount must be between $0.01 and $50,000")
    ])
    submit = SubmitField('Withdraw Money')

# Enhanced error handlers with better security
@app.errorhandler(400)
def bad_request(error):
    audit_log(current_user.id if current_user.is_authenticated else None, 'Bad Request', 'HTTP 400 error')
    return render_template('error.html', error_code=400, error_message="Bad request. Please check your input."), 400

@app.errorhandler(403)
def forbidden(error):
    audit_log(current_user.id if current_user.is_authenticated else None, 'Forbidden Access', 'HTTP 403 error')
    return render_template('error.html', error_code=403, error_message="Access forbidden. You don't have permission to access this resource."), 403

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error_code=404, error_message="The requested page was not found."), 404

@app.errorhandler(413)
def request_entity_too_large(error):
    audit_log(current_user.id if current_user.is_authenticated else None, 'File Too Large', 'HTTP 413 error')
    return render_template('error.html', error_code=413, error_message="File too large. Maximum size is 16MB."), 413

@app.errorhandler(500)
def internal_error(error):
    try:
        db.session.rollback()
        audit_log(current_user.id if current_user.is_authenticated else None, 'Internal Error', 'HTTP 500 error')
    except:
        pass
    return render_template('error.html', error_code=500, error_message="An internal error occurred. Please try again later."), 500

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        try:
            # Enhanced input validation and sanitization
            username = sanitize_input(form.username.data.strip(), 20)
            email = sanitize_input(form.email.data.strip().lower(), 120)
            
            # Additional security checks
            if detect_sql_injection(username) or detect_sql_injection(email):
                audit_log(None, 'SQL Injection Attempt', f'Registration: {username}, {email}')
                flash('Invalid input detected. Registration failed.', 'danger')
                return render_template('register.html', title='Register', form=form)
            
            # Check for existing users
            try:
                existing_user = User.query.filter_by(username=username).first()
                existing_email = User.query.filter_by(email=email).first()
                
                if existing_user:
                    flash('Username already exists. Please choose a different one.', 'danger')
                    return render_template('register.html', title='Register', form=form)
                
                if existing_email:
                    flash('Email already registered. Please use a different email.', 'danger')
                    return render_template('register.html', title='Register', form=form)
            except Exception as e:
                audit_log(None, 'Database Error', f'Registration query failed: {str(e)}')
                flash('Registration failed. Please try again.', 'danger')
                return render_template('register.html', title='Register', form=form)
            
            # Create new user with enhanced password hashing
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=username, email=email, password_hash=hashed_password)
            
            db.session.add(user)
            db.session.commit()
            
            audit_log(user.id, 'User Registration', f'New user {user.username} registered successfully')
            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            error_msg = f'Registration failed: {str(e)}'
            audit_log(None, 'Registration Error', error_msg)
            flash('Registration failed. Please try again.', 'danger')
    
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        try:
            # Enhanced input validation
            email = sanitize_input(form.email.data.strip().lower(), 120)
            
            # Check for SQL injection
            if detect_sql_injection(email) or detect_sql_injection(form.password.data):
                audit_log(None, 'SQL Injection Attempt', f'Login attempt with malicious input')
                flash('Invalid input detected.', 'danger')
                return render_template('login.html', title='Login', form=form)
            
            user = User.query.filter_by(email=email).first()
            
            # Enhanced account lockout check
            if user:
                try:
                    if user.is_account_locked():
                        audit_log(user.id, 'Login Attempt Blocked', 'Account is locked')
                        flash('Account is temporarily locked. Please try again later.', 'danger')
                        return render_template('login.html', title='Login', form=form)
                except AttributeError:
                    # Handle users without lockout fields
                    user.failed_login_attempts = 0
                    user.account_locked_until = None
                    db.session.commit()
            
            if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
                # Reset failed attempts on successful login
                user.failed_login_attempts = 0
                user.account_locked_until = None
                db.session.commit()
                
                login_user(user, remember=True)
                session['last_activity'] = datetime.now().isoformat()
                session.permanent = True
                
                audit_log(user.id, 'Login Success', f'User {user.username} logged in successfully')
                
                # Secure redirect handling
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('dashboard'))
            else:
                # Enhanced failed login handling
                if user:
                    user.failed_login_attempts = getattr(user, 'failed_login_attempts', 0) + 1
                    if user.failed_login_attempts >= app.config['MAX_LOGIN_ATTEMPTS']:
                        user.lock_account()
                        audit_log(user.id, 'Account Locked', f'Account locked after {app.config["MAX_LOGIN_ATTEMPTS"]} failed attempts')
                        flash('Account locked due to too many failed login attempts. Try again in 30 minutes.', 'danger')
                    else:
                        remaining = app.config['MAX_LOGIN_ATTEMPTS'] - user.failed_login_attempts
                        audit_log(user.id, 'Login Failed', f'Failed login attempt. {remaining} attempts remaining')
                        flash(f'Login failed. {remaining} attempts remaining.', 'danger')
                    db.session.commit()
                else:
                    audit_log(None, 'Login Attempt Failed', f'Failed login attempt for non-existent user: {email}')
                    flash('Login unsuccessful. Please check your credentials.', 'danger')
                    
        except Exception as e:
            audit_log(None, 'Login Error', f'Login error: {str(e)}')
            flash('Login failed. Please try again.', 'danger')
    
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    audit_log(current_user.id, 'Logout', f'User {current_user.username} logged out from {request.remote_addr}')
    session.pop('last_activity', None)
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Simple and robust transaction loading
        transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).limit(10).all()
        return render_template('dashboard.html', transactions=transactions)
    except Exception as e:
        audit_log(current_user.id, 'Dashboard Error', f'Dashboard access error for user {current_user.username}')
        flash('Unable to load dashboard. Please try again.', 'danger')
        return redirect(url_for('home'))

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    form = TransferForm()
    if form.validate_on_submit():
        try:
            recipient_email = sanitize_input(form.recipient.data.strip().lower())
            recipient = User.query.filter_by(email=recipient_email).first()
            
            if not recipient:
                flash('Recipient not found. Please check the email address.', 'danger')
            elif recipient.id == current_user.id:
                flash('Cannot transfer to yourself', 'danger')
            elif current_user.balance < form.amount.data:
                flash('Insufficient balance', 'danger')
            else:
                # Deduct from sender
                current_user.balance -= form.amount.data
                # Add to recipient
                recipient.balance += form.amount.data
                
                # Encrypt transaction details
                details = f"Transfer from {current_user.email} to {recipient_email}"
                encrypted_details = cipher_suite.encrypt(details.encode()).decode()
                
                # Create transactions
                transaction_send = Transaction(
                    user_id=current_user.id, 
                    amount=-form.amount.data, 
                    type='transfer', 
                    recipient=recipient.username,  # Store username for display
                    encrypted_details=encrypted_details
                )
                transaction_recv = Transaction(
                    user_id=recipient.id, 
                    amount=form.amount.data, 
                    type='transfer', 
                    recipient=current_user.username,  # Store username for display
                    encrypted_details=encrypted_details
                )
                db.session.add(transaction_send)
                db.session.add(transaction_recv)
                db.session.commit()
                
                audit_log(current_user.id, 'Transfer', f'Transferred ${form.amount.data} to {recipient.username} ({recipient_email})')
                flash(f'Transfer of ${form.amount.data:.2f} to {recipient.username} successful!', 'success')
                return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            audit_log(current_user.id, 'Transfer Error', f'Transfer failed for user {current_user.username}')
            flash('Transfer failed. Please try again.', 'danger')
    return render_template('transfer.html', title='Transfer Money', form=form)

@app.route('/transactions')
@app.route('/transactions/<int:page>')
@login_required
def transactions(page=1):
    try:
        # Validate page parameter
        if page < 1:
            page = 1
        
        transactions = Transaction.query.filter_by(user_id=current_user.id)\
                                      .order_by(Transaction.timestamp.desc())\
                                      .paginate(page=page, per_page=10, error_out=False)
        
        # Prevent access to other users' transactions via URL manipulation
        for transaction in transactions.items:
            if transaction.user_id != current_user.id:
                audit_log(current_user.id, 'Unauthorized Access Attempt', 
                         f'Attempted to access transaction {transaction.id}')
                abort(403)
        
        return render_template('transactions.html', transactions=transactions)
    except Exception as e:
        audit_log(current_user.id, 'Transaction View Error', f'Error viewing transactions: {str(e)}')
        flash('Unable to load transactions. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    if form.validate_on_submit():
        try:
            # Check for duplicate username/email (excluding current user)
            existing_user = User.query.filter(
                User.username == form.username.data,
                User.id != current_user.id
            ).first()
            
            existing_email = User.query.filter(
                User.email == form.email.data,
                User.id != current_user.id
            ).first()
            
            if existing_user:
                flash('Username already taken', 'danger')
            elif existing_email:
                flash('Email already registered', 'danger')
            else:
                old_username = current_user.username
                old_email = current_user.email
                
                current_user.username = sanitize_input(form.username.data)
                current_user.email = sanitize_input(form.email.data)
                db.session.commit()
                
                audit_log(current_user.id, 'Profile Update', 
                         f'Updated profile: username from {old_username} to {form.username.data}, email from {old_email} to {form.email.data}')
                flash('Your profile has been updated!', 'success')
                return redirect(url_for('profile'))
        except Exception as e:
            db.session.rollback()
            audit_log(current_user.id, 'Profile Update Error', f'Profile update failed for user {current_user.username}')
            flash('Profile update failed. Please try again.', 'danger')
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('profile.html', title='Profile', form=form)

@app.route('/encrypt_decrypt', methods=['GET', 'POST'])
@login_required
def encrypt_decrypt():
    form = EncryptDecryptForm()
    result = None
    if form.validate_on_submit():
        try:
            text = sanitize_input(form.text.data)
            if form.action.data == 'encrypt':
                encrypted = cipher_suite.encrypt(text.encode())
                result = encrypted.decode()
                audit_log(current_user.id, 'Encryption', 'Text encrypted successfully')
            elif form.action.data == 'decrypt':
                try:
                    decrypted = cipher_suite.decrypt(text.encode())
                    result = decrypted.decode()
                    audit_log(current_user.id, 'Decryption', 'Text decrypted successfully')
                except Exception:
                    flash('Invalid encrypted text or wrong key', 'danger')
                    audit_log(current_user.id, 'Decryption Failed', 'Invalid decryption attempt')
            else:
                flash('Invalid action specified', 'danger')
        except Exception as e:
            audit_log(current_user.id, 'Encryption Error', f'Encryption/decryption error for user {current_user.username}')
            flash('Operation failed. Please try again.', 'danger')
    return render_template('encrypt_decrypt.html', title='Encrypt/Decrypt', form=form, result=result)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        try:
            file = form.file.data
            if file and file.filename:
                # Enhanced file validation
                if not allowed_file(file.filename):
                    audit_log(current_user.id, 'Invalid File Upload', f'Attempted to upload: {file.filename}')
                    flash('Invalid file type. Allowed types: txt, pdf, png, jpg, jpeg, gif', 'danger')
                    return render_template('upload.html', title='Upload File', form=form)
                
                # Check file size
                file_content = file.read()
                file.seek(0)  # Reset file pointer
                
                if len(file_content) > app.config['MAX_CONTENT_LENGTH']:
                    audit_log(current_user.id, 'File Too Large', f'File size: {len(file_content)} bytes')
                    flash('File too large. Maximum size is 16MB.', 'danger')
                    return render_template('upload.html', title='Upload File', form=form)
                
                # Secure filename handling
                filename = secure_filename(file.filename)
                if not filename:
                    flash('Invalid filename.', 'danger')
                    return render_template('upload.html', title='Upload File', form=form)
                
                # Add timestamp and user ID to prevent conflicts
                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                filename = f"{current_user.id}_{timestamp}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                file.save(file_path)
                audit_log(current_user.id, 'File Upload', f'Uploaded file: {filename}')
                flash('File uploaded successfully', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Please select a file to upload.', 'danger')
        except Exception as e:
            audit_log(current_user.id, 'Upload Error', f'File upload failed: {str(e)}')
            flash('File upload failed. Please try again.', 'danger')
    
    return render_template('upload.html', title='Upload File', form=form)

@app.route('/deposit', methods=['GET', 'POST'])
@login_required
def deposit():
    form = DepositForm()
    if form.validate_on_submit():
        try:
            current_user.balance += form.amount.data
            transaction = Transaction(user_id=current_user.id, amount=form.amount.data, type='deposit')
            db.session.add(transaction)
            db.session.commit()
            audit_log(current_user.id, 'Deposit', f'Deposited ${form.amount.data}')
            flash(f'Deposit of ${form.amount.data:.2f} successful', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            audit_log(current_user.id, 'Deposit Error', f'Deposit failed for user {current_user.username}')
            flash('Deposit failed. Please try again.', 'danger')
    return render_template('deposit.html', title='Deposit Money', form=form)

@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    form = WithdrawForm()
    if form.validate_on_submit():
        try:
            if current_user.balance >= form.amount.data:
                current_user.balance -= form.amount.data
                transaction = Transaction(user_id=current_user.id, amount=-form.amount.data, type='withdraw')
                db.session.add(transaction)
                db.session.commit()
                audit_log(current_user.id, 'Withdraw', f'Withdrew ${form.amount.data}')
                flash(f'Withdrawal of ${form.amount.data:.2f} successful', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Insufficient balance', 'danger')
        except Exception as e:
            db.session.rollback()
            audit_log(current_user.id, 'Withdraw Error', f'Withdrawal failed for user {current_user.username}')
            flash('Withdrawal failed. Please try again.', 'danger')
    return render_template('withdraw.html', title='Withdraw Money', form=form)

# Enhanced file type validation
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
    DANGEROUS_EXTENSIONS = {'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js', 'jar', 'php', 'asp', 'aspx'}
    
    if '.' not in filename:
        return False
    
    extension = filename.rsplit('.', 1)[1].lower()
    
    # Block dangerous extensions
    if extension in DANGEROUS_EXTENSIONS:
        return False
    
    return extension in ALLOWED_EXTENSIONS

# Test route for error handling
@app.route('/test_error')
@login_required
def test_error():
    """Test route to trigger controlled errors for testing"""
    error_type = request.args.get('type', 'generic')
    
    audit_log(current_user.id, 'Test Error Triggered', f'Error type: {error_type}')
    
    if error_type == 'divide_zero':
        try:
            result = 1 / 0
        except ZeroDivisionError:
            flash('A controlled error occurred for testing purposes.', 'info')
            return redirect(url_for('dashboard'))
    elif error_type == 'db_error':
        try:
            # Intentional database error
            db.session.execute('SELECT * FROM non_existent_table')
        except Exception:
            flash('Database error handled gracefully.', 'info')
            return redirect(url_for('dashboard'))
    else:
        flash('Generic test error handled.', 'info')
        return redirect(url_for('dashboard'))

@app.route('/debug_user')
@login_required
def debug_user():
    """Debug route to check user data"""
    try:
        user_info = {
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'balance': current_user.balance,
            'has_failed_attempts': hasattr(current_user, 'failed_login_attempts'),
            'has_locked_until': hasattr(current_user, 'account_locked_until')
        }
        return f"<pre>{user_info}</pre><br><a href='/dashboard'>Back to Dashboard</a>"
    except Exception as e:
        return f"Error: {str(e)}<br><a href='/'>Home</a>"

# Create database tables with error handling
def create_tables():
    """Create database tables with proper error handling"""
    try:
        # Simple approach - just create all tables
        db.create_all()
        print("Database tables created successfully")
        return True
    except Exception as e:
        print(f"Error creating database tables: {e}")
        return False

@app.route('/audit_logs')
@login_required
def audit_logs():
    """View audit logs for the current user"""
    try:
        page = request.args.get('page', 1, type=int)
        
        # Only show logs for current user for privacy
        logs = AuditLog.query.filter_by(user_id=current_user.id)\
                            .order_by(AuditLog.timestamp.desc())\
                            .paginate(page=page, per_page=20, error_out=False)
        
        audit_log(current_user.id, 'Audit Logs Viewed', 'User accessed their audit logs')
        return render_template('audit_logs.html', logs=logs)
    except Exception as e:
        audit_log(current_user.id, 'Audit Logs Error', f'Error viewing audit logs: {str(e)}')
        flash('Unable to load audit logs. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/system_logs')
@login_required 
def system_logs():
    """View system-wide audit logs (admin functionality)"""
    try:
        # For demo purposes, any logged-in user can view system logs
        # In production, this should be restricted to admin users only
        page = request.args.get('page', 1, type=int)
        action_filter = request.args.get('action', '')
        
        query = AuditLog.query
        
        if action_filter:
            query = query.filter(AuditLog.action.contains(action_filter))
        
        logs = query.order_by(AuditLog.timestamp.desc())\
                   .paginate(page=page, per_page=50, error_out=False)
        
        # Get unique actions for filter dropdown
        actions = db.session.query(AuditLog.action).distinct().all()
        action_list = [action[0] for action in actions]
        
        audit_log(current_user.id, 'System Logs Viewed', f'User accessed system logs with filter: {action_filter}')
        return render_template('system_logs.html', logs=logs, actions=action_list, current_filter=action_filter)
    except Exception as e:
        audit_log(current_user.id, 'System Logs Error', f'Error viewing system logs: {str(e)}')
        flash('Unable to load system logs. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/download_logs')
@login_required
def download_logs():
    """Download user's audit logs as CSV"""
    try:
        import csv
        import io
        
        # Get user's logs
        logs = AuditLog.query.filter_by(user_id=current_user.id)\
                            .order_by(AuditLog.timestamp.desc()).all()
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'Action', 'Details', 'IP Address', 'User Agent'])
        
        for log in logs:
            writer.writerow([
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.action,
                log.details,
                log.ip_address,
                log.user_agent[:50] + '...' if len(log.user_agent) > 50 else log.user_agent
            ])
        
        output.seek(0)
        
        from flask import Response
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=audit_logs_{current_user.username}_{datetime.now().strftime("%Y%m%d")}.csv'}
        )
    except Exception as e:
        audit_log(current_user.id, 'Download Logs Error', f'Error downloading logs: {str(e)}')
        flash('Unable to download logs. Please try again.', 'danger')
        return redirect(url_for('audit_logs'))

if __name__ == '__main__':
    with app.app_context():
        try:
            # Simple database creation
            db.create_all()
            print("Database tables created successfully")
        except Exception as e:
            print(f"Error creating database tables: {e}")
    
    app.run(debug=True, use_reloader=False)