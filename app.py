# Send reminder for individual submission (admin)
# ...existing code...

# Place this route after app and role_required are defined
# ...existing code...
import os
from urllib.parse import urlparse
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread
import schedule
import time
import secrets
import uuid
from dotenv import load_dotenv
import logging

app = Flask(__name__)
# load environment variables from a .env file if present (convenience for local dev)
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Development mode settings
if os.environ.get('FLASK_ENV') == 'development':
    app.config['DEBUG'] = True

# ...existing code...


# ...existing code...

# Add manage_questions route at the end, after all dependencies
import os
from urllib.parse import urlparse
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread
import schedule
import time
import secrets
import uuid
from dotenv import load_dotenv
import logging

app = Flask(__name__)
# load environment variables from a .env file if present (convenience for local dev)
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Development mode settings
if os.environ.get('FLASK_ENV') == 'development':
    app.config['DEBUG'] = True
    app.config['ALLOW_ALL_EMAILS'] = True
    app.logger.info("Running in development mode")

app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET', 'dev-secret-key')
# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(basedir, 'instance')
os.makedirs(instance_path, exist_ok=True)

db_path = os.path.join(instance_path, 'quest_reviewer.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Log database location
app.logger.info(f"Using database at: {db_path}")

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'sahmedkhan8@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'rarg kfbf ebyh susu')  # Gmail App Password
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'sahmedkhan8@gmail.com')
# Restrict outbound emails to a specific domain
app.config['ALLOWED_EMAIL_DOMAIN'] = os.environ.get('ALLOWED_EMAIL_DOMAIN', '10pearls.com')
# Allow overriding domain restriction in development or via env var
app.config['ALLOW_ALL_EMAILS'] = os.environ.get('ALLOW_ALL_EMAILS', 'false').lower() in ['true', '1', 'yes']

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    submissions = db.relationship('Submission', backref='user', lazy=True, cascade='all, delete-orphan')
    # Many-to-many relationship for review leads
    review_lead_projects = db.relationship(
        'Project',
        secondary='review_leads_projects',
        back_populates='review_leads'
    )

class Question(db.Model):
    __tablename__ = 'questions'
    
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(20), nullable=False, default='text')
    options = db.Column(db.Text)
    required = db.Column(db.Boolean, default=True)
    order = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    answers = db.relationship('Answer', backref='question', lazy=True, cascade='all, delete-orphan')
    
    def get_options_list(self):
        if self.options:
            return [opt.strip() for opt in self.options.split('\n') if opt.strip()]
        return []

class Project(db.Model):
    __tablename__ = 'projects'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    description = db.Column(db.Text)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    secondary_reviewer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    submissions = db.relationship('Submission', backref='project', lazy=True, cascade='all, delete-orphan')
    reviewer = db.relationship('User', backref='primary_projects', foreign_keys=[reviewer_id])
    secondary_reviewer = db.relationship('User', backref='secondary_projects', foreign_keys=[secondary_reviewer_id])
    # Many-to-many relationship for review leads
    review_leads = db.relationship(
        'User',
        secondary='review_leads_projects',
        back_populates='review_lead_projects'
    )
# Association table for many-to-many relationship between projects and review leads
review_leads_projects = db.Table(
    'review_leads_projects',
    db.Column('project_id', db.Integer, db.ForeignKey('projects.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True)
)

class ReviewReminder(db.Model):
    __tablename__ = 'review_reminders'
    
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    reviewer_email = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    scheduled_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, scheduled, expired
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Submission(db.Model):
    __tablename__ = 'submissions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    month = db.Column(db.String(7), nullable=False)
    scheduled_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='scheduled')
    
    answers = db.relationship('Answer', backref='submission', lazy=True, cascade='all, delete-orphan')

class Answer(db.Model):
    __tablename__ = 'answers'
    
    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer, db.ForeignKey('submissions.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    answer_text = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Invitation(db.Model):
    __tablename__ = 'invitations'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    invited_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(100), nullable=False, unique=True)
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, accepted, expired
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    inviter = db.relationship('User', backref='sent_invitations', foreign_keys=[invited_by])

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Log In')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class QuestionForm(FlaskForm):
    text = TextAreaField('Question Text', validators=[DataRequired(), Length(min=5, max=500)])
    question_type = SelectField('Question Type', 
                               choices=[('text', 'Short Text'), 
                                       ('textarea', 'Long Text'),
                                       ('number', 'Number'),
                                       ('date', 'Date'),
                                       ('radio', 'Radio Buttons'),
                                       ('checkbox', 'Checkboxes (Multiple Choice)')],
                               validators=[DataRequired()])
    options = TextAreaField('Options (one per line, required for Radio/Checkbox)')
    required = BooleanField('Required', default=True)
    submit = SubmitField('Save Question')

class ProjectForm(FlaskForm):
    name = StringField('Project Name', validators=[DataRequired(), Length(min=2, max=200)])
    description = TextAreaField('Description')
    reviewer_id = SelectField('Primary Reviewer', coerce=int, choices=[])
    secondary_reviewer_id = SelectField('Secondary Reviewer', coerce=int, choices=[])
    review_leads = SelectField('Review Leads', coerce=int, choices=[], render_kw={"multiple": True})
    submit = SubmitField('Save Project')

class InviteForm(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    message = TextAreaField('Personal Message (Optional)')
    submit = SubmitField('Send Invitation')

class DomainEmailForm(FlaskForm):
    domain = StringField('Domain (e.g., company.com)', validators=[DataRequired(), Length(min=3, max=100)])
    subject = StringField('Subject', validators=[DataRequired(), Length(min=3, max=200)])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=10, max=2000)])
    recipient_emails = TextAreaField('Recipient Emails (one per line, optional)', 
                                   description='Leave empty to send to all @10pearls.com users, or specify individual emails')
    submit = SubmitField('Send to Domain Users')

# Form for scheduling a review
class ReviewScheduleForm(FlaskForm):
    review_month = StringField('Review Month', validators=[DataRequired()])
    scheduled_date = StringField('Scheduled Date', validators=[DataRequired()])
    submit = SubmitField('Schedule Review')
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(role):
    def decorator(f):
        @login_required
        def decorated_function(*args, **kwargs):
            if current_user.role != role and current_user.role != 'admin':
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

def send_email(to, subject, body):
    """Send email synchronously"""
    try:
        # Enforce allowed domain for recipients
        allowed = app.config.get('ALLOWED_EMAIL_DOMAIN')
        allow_all = app.config.get('ALLOW_ALL_EMAILS') or os.environ.get('FLASK_ENV') == 'development'
        if not allow_all and allowed and not to.lower().endswith(f"@{allowed}"):
            app.logger.warning(f"Blocked email to non-allowed domain: {to}")
            return False
            
        # Check if email is configured
        if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            app.logger.warning(f"Email not configured. Would send to {to}: {subject}")
            app.logger.debug(f"Email body: {body}")
            return False
        
        app.logger.info(f"Using email credentials - Username: {app.config['MAIL_USERNAME']}")
        app.logger.info(f"SMTP Server: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
        
        # Create email message
        msg = MIMEMultipart()
        msg['From'] = app.config.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])
        msg['To'] = to
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        app.logger.info(f"Sending email to: {to}")
        app.logger.info(f"Subject: {subject}")
        
        app.logger.info(f"Attempting to send email to {to}")
        
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        app.logger.info("SMTP connection established")
        
        server.starttls()
        app.logger.info("TLS started")
        
        app.logger.info("Attempting login...")
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        
        app.logger.info(f"Email sent successfully to {to}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        app.logger.error(f"SMTP Authentication Error: {str(e)}")
        app.logger.error("Please check your email and App Password are correct")
        return False
    except Exception as e:
        app.logger.error(f"Failed to send email to {to}: {str(e)}")
        app.logger.error(f"Error type: {type(e).__name__}")
        return False

def send_review_reminder_email(reviewer_email, reviewer_name, project_name, project_id):
    """Send monthly review reminder email with scheduling link"""
    # Generate a unique token for this reminder
    token = secrets.token_urlsafe(32)
    
    # Save the reminder token
    reminder = ReviewReminder(
        project_id=project_id,
        reviewer_email=reviewer_email,
        token=token,
        expires_at=datetime.utcnow() + timedelta(days=7)  # Token expires in 7 days
    )
    db.session.add(reminder)
    db.session.commit()
    
    current_month = datetime.now().strftime('%B %Y')
    schedule_url = url_for('schedule_review', project_id=project_id, _external=True)
    subject = f"Schedule Your QA Review - {project_name}"
    
    body = f"""
    Dear {reviewer_name},
    
    This is a reminder to schedule your QA review for the project: {project_name}
    
    Please click the link below to schedule your review for {current_month}:
    {schedule_url}
    
    This scheduling link will expire in 7 days. After scheduling, you'll receive a confirmation email with your chosen review date.
    
    If you have any questions, please contact the admin.
    
    Best regards,
    QuestReviewer System
    """
    
    success = send_email(reviewer_email, subject, body)
    if not success:
        app.logger.error(f"Failed to send review reminder to {reviewer_email}")
        reminder.status = 'failed'
        db.session.commit()
    return success

def send_invitation_email(invitee_email, inviter_name, invitation_token, personal_message=""):
    """Send user invitation email"""
    msg = MIMEMultipart()
    msg['From'] = app.config['MAIL_DEFAULT_SENDER']
    msg['To'] = invitee_email
    msg['Subject'] = f"Invitation to join QuestReviewer - {inviter_name}"
    
    invitation_url = url_for('accept_invitation', token=invitation_token, _external=True)
    
    body = f"""
    Hello,
    
    You have been invited by {inviter_name} to join QuestReviewer, a quality assurance review system.
    
    {personal_message}
    
    To accept this invitation and create your account, please click the link below:
    {invitation_url}
    
    This invitation will expire in 7 days.
    
    If you have any questions, please contact the admin.
    
    Best regards,
    QuestReviewer System
    """
    
    return send_email(invitee_email, msg['Subject'], body)
    
    msg.attach(MIMEText(body, 'plain'))
    
    # Send email in background
    Thread(target=send_email_async, args=(app, msg)).start()

def send_domain_email(domain, subject, message, recipient_emails=None):
    """Send email to users from a specific domain or specific recipients"""
    if recipient_emails:
        # Send to specific recipients
        email_list = [email.strip().lower() for email in recipient_emails.split('\n') if email.strip()]
        # Filter to only @10pearls.com emails
        allowed_domain = app.config.get('ALLOWED_EMAIL_DOMAIN', '10pearls.com')
        email_list = [email for email in email_list if email.endswith(f'@{allowed_domain}')]
        
        if not email_list:
            return 0, f"No valid @{allowed_domain} emails provided"
        
        # Find users by email
        users = User.query.filter(User.email.in_(email_list)).all()
        found_emails = [user.email for user in users]
        not_found = [email for email in email_list if email not in found_emails]
        
        if not_found:
            print(f"Users not found for emails: {', '.join(not_found)}")
    else:
        # Send to all users from domain
        users = User.query.filter(User.email.like(f'%@{domain}')).all()
        not_found = []
    
    if not users:
        return 0, f"No users found with @{domain} email addresses"
    
    sent_count = 0
    failed_emails = []
    
    for user in users:
        try:
            msg = MIMEMultipart()
            msg['From'] = app.config['MAIL_DEFAULT_SENDER']
            msg['To'] = user.email
            msg['Subject'] = subject
            
            # Personalize the message
            personalized_message = message.replace('{name}', user.name)
            personalized_message = personalized_message.replace('{email}', user.email)
            
            body = f"""
            Dear {user.name},
            
            {personalized_message}
            
            Best regards,
            QuestReviewer Admin Team
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email in background
            Thread(target=send_email_async, args=(app, msg)).start()
            sent_count += 1
            
        except Exception as e:
            failed_emails.append(user.email)
            print(f"Failed to send email to {user.email}: {str(e)}")
    
    result = failed_emails
    if not_found:
        result = failed_emails + not_found
    
    return sent_count, result

def send_monthly_reminders():
    """Send monthly reminders to all assigned reviewers"""
    with app.app_context():
        projects = Project.query.filter(Project.reviewer_id.isnot(None)).all()
        allowed = app.config.get('ALLOWED_EMAIL_DOMAIN')
        for project in projects:
            if project.reviewer:
                # Skip if reviewer email not in allowed domain
                if allowed and not project.reviewer.email.lower().endswith(f"@{allowed}"):
                    continue
                send_review_reminder_email(
                    project.reviewer.email,
                    project.reviewer.name,
                    project.name,
                    project.id
                )
        print(f"Sent reminders for {len(projects)} projects (filtered by domain if configured)")

def run_scheduler():
    """Run the email scheduler in background"""
    # Schedule to run daily and check if it's the 1st of the month
    schedule.every().day.at("09:00").do(check_and_send_monthly_reminders)
    while True:
        schedule.run_pending()
        time.sleep(3600)  # Check every hour

@app.route('/schedule-review/<token>', methods=['GET', 'POST'])
def process_review_invite(token):
    """Handle review scheduling from email link"""
    reminder = ReviewReminder.query.filter_by(token=token, status='pending').first()
    
    if not reminder or reminder.expires_at < datetime.utcnow():
        if reminder:
            reminder.status = 'expired'
            db.session.commit()
        flash('This scheduling link has expired or is invalid. Please contact the administrator.', 'danger')
        return redirect(url_for('login'))
    
    project = Project.query.get_or_404(reminder.project_id)
    
    if request.method == 'POST':
        scheduled_date = request.form.get('scheduled_date')
        if scheduled_date:
            # Convert string to datetime
            scheduled_date = datetime.fromisoformat(scheduled_date.replace('Z', '+00:00'))
            
            # Update reminder status
            reminder.status = 'scheduled'
            reminder.scheduled_date = scheduled_date
            db.session.commit()
            
            # Send confirmation email
            msg = MIMEMultipart()
            msg['From'] = app.config['MAIL_DEFAULT_SENDER']
            msg['To'] = reminder.reviewer_email
            msg['Subject'] = f"Review Scheduled - {project.name}"
            
            review_url = url_for('submit_review', project_id=project.id, _external=True)
            scheduled_date_str = scheduled_date.strftime('%B %d, %Y at %I:%M %p')
            
            body = f"""
            Your QA review for {project.name} has been scheduled for {scheduled_date_str}.
            
            You can submit your review at any time by visiting:
            {review_url}
            
            A reminder will be sent on the scheduled date.
            
            Best regards,
            QuestReviewer System
            """
            
            msg.attach(MIMEText(body, 'plain'))
            send_email_async(msg)
            
            flash('Review has been successfully scheduled!', 'success')
            return redirect(url_for('login'))
    
    # Get current date info
    now = datetime.utcnow()
    current_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    # Set min date as current time
    min_date = now.strftime('%Y-%m-%dT%H:%M')
    # Allow scheduling for any future date
    max_date = (now + timedelta(days=365)).strftime('%Y-%m-%dT%H:%M')
    
    return render_template('schedule_review.html', 
                         project=project,
                         min_date=min_date,
                         max_date=max_date,
                         current_month=now.strftime('%B %Y'))

def check_and_send_monthly_reminders():
    """Check if it's the 1st of the month and send reminders"""
    if datetime.now().day == 1:
        send_monthly_reminders()

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        app.logger.info(f"Login attempt for email: {form.email.data}")
        
        if not user:
            app.logger.warning(f"No user found with email: {form.email.data}")
            flash('Invalid email or password', 'danger')
            return render_template('login.html', form=form)
            
        if check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            app.logger.info(f"Successful login for user: {user.email} (role: {user.role})")
            next_page = request.args.get('next')
            if not next_page or urlparse(next_page).netloc != '':
                next_page = url_for('user_dashboard' if user.role == 'user' else 'admin_dashboard')
            return redirect(next_page)
        else:
            app.logger.warning(f"Invalid password for user: {user.email}")
            flash('Invalid email or password', 'danger')
            
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already registered', 'danger')
            return render_template('register.html', form=form)
        
        user = User(
            email=form.email.data,
            name=form.name.data,
            password_hash=generate_password_hash(form.password.data),
            role='user'
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/admin/resend-expired/<int:reminder_id>')
@login_required
@role_required('admin')
def resend_expired_reminder(reminder_id):
    """Resend expired review reminder"""
    reminder = ReviewReminder.query.get_or_404(reminder_id)
    project = Project.query.get_or_404(reminder.project_id)
    reviewer = User.query.filter_by(email=reminder.reviewer_email).first()
    
    if not reviewer:
        flash('Reviewer not found!', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # Create new reminder
    send_review_reminder_email(
        reviewer_email=reminder.reviewer_email,
        reviewer_name=reviewer.name,
        project_name=project.name,
        project_id=project.id
    )
    
    flash(f'New review reminder sent to {reviewer.name}', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    submissions = Submission.query.order_by(Submission.created_at.desc()).all()
    projects = Project.query.all()
    users = User.query.all()
    questions = Question.query.order_by(Question.order).all()

    # Get expired reminders
    expired_reminders = ReviewReminder.query.filter(
        ReviewReminder.status == 'expired',
        ReviewReminder.scheduled_date.is_(None),
        ~ReviewReminder.reviewer_email.in_(
            ReviewReminder.query.filter(ReviewReminder.status == 'pending')
            .with_entities(ReviewReminder.reviewer_email)
        )
    ).all()

    # Pass all submissions to template for compatibility
    return render_template('admin_dashboard.html',
                         submissions=submissions,
                         projects=projects,
                         users=users,
                         questions=questions)

@app.route('/admin/questions/add', methods=['GET', 'POST'])
@role_required('admin')
def add_question():
    form = QuestionForm()
    if form.validate_on_submit():
        max_order = db.session.query(db.func.max(Question.order)).scalar() or 0
        question = Question(
            text=form.text.data,
            question_type=form.question_type.data,
            options=form.options.data if form.question_type.data in ['radio', 'checkbox'] else None,
            required=form.required.data,
            order=max_order + 1
        )
        db.session.add(question)
        db.session.commit()
        flash('Question added successfully!', 'success')
        return redirect(url_for('add_question'))
    return render_template('question_form.html', form=form, title='Add Question')

@app.route('/admin/questions/edit/<int:id>', methods=['GET', 'POST'])
@role_required('admin')
def edit_question(id):
    question = Question.query.get_or_404(id)
    form = QuestionForm(obj=question)
    if form.validate_on_submit():
        question.text = form.text.data
        question.question_type = form.question_type.data
        question.options = form.options.data if form.question_type.data in ['radio', 'checkbox'] else None
        question.required = form.required.data
        db.session.commit()
        flash('Question updated successfully!', 'success')
        return redirect(url_for('add_question'))
    return render_template('question_form.html', form=form, title='Edit Question')

@app.route('/admin/questions/delete/<int:id>', methods=['POST'])
@role_required('admin')
def delete_question(id):
    question = Question.query.get_or_404(id)
    db.session.delete(question)
    db.session.commit()
    flash('Question deleted successfully!', 'success')
    return redirect(url_for('add_question'))

@app.route('/admin/projects')
@role_required('admin')
def manage_projects():
    projects = Project.query.all()
    return render_template('manage_projects.html', projects=projects)

@app.route('/admin/projects/add', methods=['GET', 'POST'])
@role_required('admin')
def add_project():
    form = ProjectForm()
    # Populate reviewer choices
    all_user_choices = [(0, 'No Reviewer Assigned')] + [(user.id, user.name) for user in User.query.all()]
    form.reviewer_id.choices = all_user_choices
    form.secondary_reviewer_id.choices = all_user_choices
    form.review_leads.choices = [(user.id, user.name) for user in User.query.all()]

    if form.validate_on_submit():
        project = Project(
            name=form.name.data,
            description=form.description.data,
            reviewer_id=form.reviewer_id.data if form.reviewer_id.data != 0 else None,
            secondary_reviewer_id=form.secondary_reviewer_id.data if form.secondary_reviewer_id.data != 0 else None
        )
        # Assign review leads
        selected_leads = request.form.getlist('review_leads')
        project.review_leads = User.query.filter(User.id.in_(selected_leads)).all() if selected_leads else []
        db.session.add(project)
        db.session.commit()
        flash('Project added successfully!', 'success')
        return redirect(url_for('manage_projects'))
    return render_template('project_form.html', form=form, title='Add Project')

@app.route('/admin/projects/edit/<int:id>', methods=['GET', 'POST'])
@role_required('admin')
def edit_project(id):
    project = Project.query.get_or_404(id)
    form = ProjectForm(obj=project)
    # Populate reviewer choices
    all_user_choices = [(0, 'No Reviewer Assigned')] + [(user.id, user.name) for user in User.query.all()]
    form.reviewer_id.choices = all_user_choices
    form.secondary_reviewer_id.choices = all_user_choices
    form.review_leads.choices = [(user.id, user.name) for user in User.query.all()]
    # Pre-select current review leads
    form.review_leads.data = [user.id for user in project.review_leads]

    if form.validate_on_submit():
        project.name = form.name.data
        project.description = form.description.data
        project.reviewer_id = form.reviewer_id.data if form.reviewer_id.data != 0 else None
        project.secondary_reviewer_id = form.secondary_reviewer_id.data if form.secondary_reviewer_id.data != 0 else None
        # Update review leads
        selected_leads = request.form.getlist('review_leads')
        project.review_leads = User.query.filter(User.id.in_(selected_leads)).all() if selected_leads else []
        db.session.commit()
        flash('Project updated successfully!', 'success')
        return redirect(url_for('manage_projects'))
    return render_template('project_form.html', form=form, title='Edit Project')

@app.route('/admin/projects/delete/<int:id>', methods=['POST'])
@role_required('admin')
def delete_project(id):
    project = Project.query.get_or_404(id)
    db.session.delete(project)
    db.session.commit()
    flash('Project deleted successfully!', 'success')
    return redirect(url_for('manage_projects'))

@app.route('/dashboard')
@login_required
def user_dashboard():
    user_submissions = Submission.query.filter_by(user_id=current_user.id).order_by(Submission.created_at.desc()).all()
    from datetime import datetime
    now = datetime.now()
    if current_user.role == 'review_lead':
        projects = current_user.review_lead_projects
    else:
        projects = Project.query.all()
    return render_template('user_dashboard.html', submissions=user_submissions, projects=projects, now=now)

def send_review_reminder(submission_id):
    """Send review reminder email for a scheduled submission"""
    submission = Submission.query.get(submission_id)
    if not submission:
        return
    
    user = User.query.get(submission.user_id)
    project = Project.query.get(submission.project_id)
    
    subject = f"Review Reminder: {project.name} - {submission.month}"
    body = f"""
    Hello {user.name},
    
    This is a reminder that you have scheduled a QA review for {project.name} (Month: {submission.month}).
    Please complete your review at your earliest convenience.
    
    You can submit your review by visiting: {url_for('submit_review', project_id=project.id, _external=True)}
    
    Best regards,
    QA Review System
    """
    
    send_email(user.email, subject, body)

@app.route('/schedule_review/<int:project_id>', methods=['GET', 'POST'])
@login_required
def schedule_review(project_id):
    project = Project.query.get_or_404(project_id)
    form = ReviewScheduleForm()
    
    if form.validate_on_submit():
        # Check for existing submission for this user/project/month
        existing = Submission.query.filter_by(
            user_id=current_user.id,
            project_id=project_id,
            month=form.review_month.data
        ).first()
        if existing:
            existing.scheduled_date = datetime.fromisoformat(form.scheduled_date.data) if form.scheduled_date.data else None
            existing.status = 'scheduled'
            db.session.commit()
        else:
            submission = Submission(
                user_id=current_user.id,
                project_id=project_id,
                month=form.review_month.data,
                scheduled_date=datetime.fromisoformat(form.scheduled_date.data) if form.scheduled_date.data else None,
                status='scheduled'
            )
            db.session.add(submission)
            db.session.commit()
        
    flash('QA Review scheduled successfully!', 'success')
    return redirect(url_for('user_dashboard'))
    
    form.review_month.data = datetime.now().strftime('%Y-%m')
    form.scheduled_date.data = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%dT%H:%M')
    
    return render_template('schedule_review.html', project=project, form=form)

@app.route('/submit_review/<int:submission_id>', methods=['GET', 'POST'])
@login_required
def submit_review(submission_id):
    submission = Submission.query.get_or_404(submission_id)
    if submission.user_id != current_user.id:
        abort(403)
        
    questions = Question.query.order_by(Question.order).all()
    
    if request.method == 'POST':
        for question in questions:
            if question.question_type == 'checkbox':
                answer_values = request.form.getlist(f'question_{question.id}')
                answer_text = ', '.join(answer_values) if answer_values else ''
            else:
                answer_text = request.form.get(f'question_{question.id}')
            
            if answer_text or not question.required:
                answer = Answer(
                    submission_id=submission.id,
                    question_id=question.id,
                    answer_text=answer_text or ''
                )
                db.session.add(answer)
        
        submission.status = 'submitted'
        db.session.commit()
        flash('QA Review submitted successfully!', 'success')
        return redirect(url_for('user_dashboard'))
    
    current_month = datetime.now().strftime('%Y-%m')
    min_schedule_date = datetime.now().strftime('%Y-%m-%dT%H:%M')
    default_schedule_date = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%dT%H:%M')
    
    project = submission.project
    return render_template('submit_review.html', 
                         project=project, 
                         submission=submission,
                         questions=questions, 
                         current_month=current_month,
                         min_schedule_date=min_schedule_date,
                         default_schedule_date=default_schedule_date)

@app.route('/submission/<int:id>')
@login_required
def view_submission(id):
    submission = Submission.query.get_or_404(id)
    
    if current_user.role != 'admin' and submission.user_id != current_user.id:
        flash('You do not have permission to view this submission.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    return render_template('view_submission.html', submission=submission)

@app.route('/admin/send-reminders')
@login_required
@role_required('admin')
def send_reminders():
    """Manually send review reminders"""
    now = datetime.utcnow()
    
    # Send reminders regardless of the date
    send_monthly_reminders()
    flash('Review reminders sent successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/domain-email', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def domain_email():
    """Send email to all users from 10pearls.com domain"""
    form = DomainEmailForm()
    
    if form.validate_on_submit():
        # Always use 10pearls.com domain
        domain = '10pearls.com'
        subject = form.subject.data
        message = form.message.data
        recipient_emails = form.recipient_emails.data if form.recipient_emails.data else None
        
        # Send emails to domain users
        sent_count, result = send_domain_email(domain, subject, message, recipient_emails)
        
        if isinstance(result, str):
            # No users found
            flash(result, 'warning')
        else:
            # Emails sent
            if sent_count > 0:
                flash(f'Email sent successfully to {sent_count} users from @{domain}!', 'success')
            if result:  # failed_emails
                flash(f'Failed to send to {len(result)} users: {", ".join(result[:3])}{"..." if len(result) > 3 else ""}', 'warning')
        
        return redirect(url_for('domain_email'))
    
    # Pre-fill the domain field
    form.domain.data = '10pearls.com'
    return render_template('domain_email.html', form=form)

@app.route('/admin/users')
@login_required
@role_required('admin')
def manage_users():
    """View and manage all users"""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/users/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(id):
    """Edit user details and role"""
    user = User.query.get_or_404(id)
    
    if request.method == 'POST':
        user.name = request.form.get('name', user.name)
        user.email = request.form.get('email', user.email)
        user.role = request.form.get('role', user.role)
        
        # Check if email is already taken by another user
        existing_user = User.query.filter(User.email == user.email, User.id != user.id).first()
        if existing_user:
            flash('Email already taken by another user!', 'danger')
            return render_template('edit_user.html', user=user)
        
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('manage_users'))
    
    return render_template('edit_user.html', user=user)

@app.route('/admin/users/delete/<int:id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(id):
    """Delete a user"""
    user = User.query.get_or_404(id)
    
    # Prevent admin from deleting themselves
    if user.id == current_user.id:
        flash('You cannot delete your own account!', 'danger')
        return redirect(url_for('manage_users'))
    
    # Prevent deleting the last admin
    admin_count = User.query.filter_by(role='admin').count()
    if user.role == 'admin' and admin_count <= 1:
        flash('Cannot delete the last admin user!', 'danger')
        return redirect(url_for('manage_users'))
    
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/invite', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def invite_user():
    """Send invitation to new user"""
    form = InviteForm()
    
    if form.validate_on_submit():
        email = form.email.data.lower()
        # Enforce allowed domain for invitations
        allowed = app.config.get('ALLOWED_EMAIL_DOMAIN')
        if allowed and not email.endswith(f"@{allowed}"):
            flash(f"Invites are restricted to @{allowed} email addresses.", 'danger')
            return render_template('invite_user.html', form=form)
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('User with this email already exists!', 'danger')
            return render_template('invite_user.html', form=form)
        
        # Check if invitation already exists
        existing_invitation = Invitation.query.filter_by(email=email).first()

        # If there's an existing, non-expired invitation, reuse its token so previously sent links remain valid.
        if existing_invitation and existing_invitation.expires_at > datetime.utcnow():
            token = existing_invitation.token
            # Optionally extend expiration by 7 days from now
            existing_invitation.expires_at = datetime.utcnow() + timedelta(days=7)
            existing_invitation.status = 'pending'
            invitation = existing_invitation
        else:
            # Create a new invitation (or replace an expired one)
            token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(days=7)
            if existing_invitation:
                # update expired invitation
                existing_invitation.token = token
                existing_invitation.expires_at = expires_at
                existing_invitation.status = 'pending'
                existing_invitation.invited_by = current_user.id
                invitation = existing_invitation
            else:
                invitation = Invitation(
                    email=email,
                    invited_by=current_user.id,
                    token=token,
                    status='pending',
                    expires_at=expires_at
                )
        
        db.session.add(invitation)
        db.session.commit()
        
        # Send invitation email
        send_invitation_email(
            email, 
            current_user.name, 
            token, 
            form.message.data
        )
        
        # Check if email is configured
        if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            invitation_url = f"http://127.0.0.1:5000/accept-invitation/{token}"
            flash(f'Invitation created! Email not configured. Share this link manually: {invitation_url}', 'warning')
        else:
            flash(f'Invitation sent successfully to {email}!', 'success')
        
        return redirect(url_for('manage_users'))
    
    return render_template('invite_user.html', form=form)

@app.route('/accept-invitation/<token>', methods=['GET', 'POST'])
def accept_invitation(token):
    """Accept invitation and create account"""
    invitation = Invitation.query.filter_by(token=token, status='pending').first()
    
    if not invitation:
        flash('Invalid or expired invitation!', 'danger')
        return redirect(url_for('login'))
    
    if invitation.expires_at < datetime.utcnow():
        invitation.status = 'expired'
        db.session.commit()
        flash('Invitation has expired!', 'danger')
        return redirect(url_for('login'))
    
    # Use RegisterForm so template can access form and show validation errors
    form = RegisterForm()

    if form.validate_on_submit():
        # Ensure the email matches the invitation
        if form.email.data.lower() != invitation.email.lower():
            flash('The email does not match the invitation.', 'danger')
            return render_template('accept_invitation.html', invitation=invitation, form=form)

        # Create user
        user = User(
            email=invitation.email,
            name=form.name.data,
            password_hash=generate_password_hash(form.password.data),
            role='user'
        )

        db.session.add(user)
        invitation.status = 'accepted'
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    # Pre-fill email field on the form for user convenience
    if request.method == 'GET':
        form.email.data = invitation.email

    return render_template('accept_invitation.html', invitation=invitation, form=form)

@app.route('/init-db')
@login_required
@role_required('admin')
def init_db():
    db.create_all()
    flash('Database tables created successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/test-email/<to>')
@login_required
@role_required('admin')
def test_email(to):
    """Test email configuration"""
    try:
        success = send_email(
            to=to,
            subject="Test Email from QuestReviewer",
            body="This is a test email to verify the email configuration is working correctly."
        )
        if success:
            flash('Test email sent successfully!', 'success')
        else:
            flash('Failed to send test email. Check the logs for details.', 'danger')
    except Exception as e:
        flash(f'Error sending test email: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.cli.command('init-db-cli')
def init_db_cli():
    db.create_all()
    
    admin = User.query.filter_by(email='admin@qa.com').first()
    if not admin:
        admin = User(
            email='admin@qa.com',
            name='Admin User',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()
        print('Database initialized! Admin created (email: admin@qa.com, password: admin123)')
    else:
        print('Database already initialized!')

def check_and_send_reminders():
    """Check for scheduled reviews and send reminders"""
    with app.app_context():
        # Find submissions that have scheduled dates within the last minute
        now = datetime.utcnow()
        one_minute_ago = now - timedelta(minutes=1)
        
        scheduled_submissions = Submission.query.filter(
            Submission.scheduled_date >= one_minute_ago,
            Submission.scheduled_date <= now
        ).all()
        
        for submission in scheduled_submissions:
            try:
                send_review_reminder(submission.id)
                app.logger.info(f"Sent reminder for submission {submission.id}")
            except Exception as e:
                app.logger.error(f"Failed to send reminder for submission {submission.id}: {str(e)}")

# Initialize schedulers
def start_schedulers():
    # Monthly reminders scheduler
    monthly_scheduler = Thread(target=run_scheduler, daemon=True)
    monthly_scheduler.start()
    app.logger.info("Started monthly reminder scheduler")
    
    # Review reminders scheduler
    def review_scheduler():
        while True:
            try:
                check_and_send_reminders()
            except Exception as e:
                app.logger.error(f"Error in review scheduler: {str(e)}")
            time.sleep(60)  # Check every minute
            
    reminder_scheduler = Thread(target=review_scheduler, daemon=True)
    reminder_scheduler.start()
    app.logger.info("Started review reminder scheduler")

# Route: Send reminder for individual submission (admin)
@app.route('/admin/send-individual-reminder/<int:submission_id>', methods=['POST'])
@login_required
@role_required('admin')
def send_individual_reminder(submission_id):
    submission = Submission.query.get_or_404(submission_id)
    if not submission.user:
        flash('No user assigned to this submission.', 'danger')
        return redirect(url_for('admin_dashboard'))
    # Send reminder email to the user assigned to the submission
    try:
        send_review_reminder_email(
            submission.user.email,
            submission.user.name,
            submission.project.name if submission.project else '-',
            submission.project.id if submission.project else None
        )
        flash(f'Reminder sent to {submission.user.email} for project {submission.project.name}.', 'success')
    except Exception as e:
        flash(f'Failed to send reminder: {str(e)}', 'danger')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Start schedulers
    start_schedulers()
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)
