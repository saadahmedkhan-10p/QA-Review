import os
from urllib.parse import urlparse
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    submissions = db.relationship('Submission', backref='project', lazy=True, cascade='all, delete-orphan')

class Submission(db.Model):
    __tablename__ = 'submissions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    month = db.Column(db.String(7), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    answers = db.relationship('Answer', backref='submission', lazy=True, cascade='all, delete-orphan')

class Answer(db.Model):
    __tablename__ = 'answers'
    
    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer, db.ForeignKey('submissions.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    answer_text = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    submit = SubmitField('Save Project')

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
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            if not next_page or urlparse(next_page).netloc != '':
                next_page = url_for('index')
            return redirect(next_page)
        else:
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

@app.route('/admin/dashboard')
@role_required('admin')
def admin_dashboard():
    submissions = Submission.query.order_by(Submission.created_at.desc()).all()
    projects = Project.query.all()
    users = User.query.all()
    questions = Question.query.order_by(Question.order).all()
    
    project_filter = request.args.get('project')
    month_filter = request.args.get('month')
    
    if project_filter:
        submissions = [s for s in submissions if s.project_id == int(project_filter)]
    if month_filter:
        submissions = [s for s in submissions if s.month == month_filter]
    
    return render_template('admin_dashboard.html', 
                         submissions=submissions, 
                         projects=projects,
                         users=users,
                         questions=questions)

@app.route('/admin/questions')
@role_required('admin')
def manage_questions():
    questions = Question.query.order_by(Question.order).all()
    return render_template('manage_questions.html', questions=questions)

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
        return redirect(url_for('manage_questions'))
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
        return redirect(url_for('manage_questions'))
    return render_template('question_form.html', form=form, title='Edit Question')

@app.route('/admin/questions/delete/<int:id>', methods=['POST'])
@role_required('admin')
def delete_question(id):
    question = Question.query.get_or_404(id)
    db.session.delete(question)
    db.session.commit()
    flash('Question deleted successfully!', 'success')
    return redirect(url_for('manage_questions'))

@app.route('/admin/projects')
@role_required('admin')
def manage_projects():
    projects = Project.query.all()
    return render_template('manage_projects.html', projects=projects)

@app.route('/admin/projects/add', methods=['GET', 'POST'])
@role_required('admin')
def add_project():
    form = ProjectForm()
    if form.validate_on_submit():
        project = Project(
            name=form.name.data,
            description=form.description.data
        )
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
    if form.validate_on_submit():
        project.name = form.name.data
        project.description = form.description.data
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
    projects = Project.query.all()
    return render_template('user_dashboard.html', submissions=user_submissions, projects=projects)

@app.route('/submit/<int:project_id>', methods=['GET', 'POST'])
@login_required
def submit_review(project_id):
    project = Project.query.get_or_404(project_id)
    questions = Question.query.order_by(Question.order).all()
    
    if request.method == 'POST':
        current_month = request.form.get('month')
        
        submission = Submission(
            user_id=current_user.id,
            project_id=project_id,
            month=current_month
        )
        db.session.add(submission)
        db.session.flush()
        
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
        
        db.session.commit()
        flash('QA Review submitted successfully!', 'success')
        return redirect(url_for('user_dashboard'))
    
    current_month = datetime.now().strftime('%Y-%m')
    return render_template('submit_review.html', project=project, questions=questions, current_month=current_month)

@app.route('/submission/<int:id>')
@login_required
def view_submission(id):
    submission = Submission.query.get_or_404(id)
    
    if current_user.role != 'admin' and submission.user_id != current_user.id:
        flash('You do not have permission to view this submission.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    return render_template('view_submission.html', submission=submission)

@app.route('/init-db')
@login_required
@role_required('admin')
def init_db():
    db.create_all()
    flash('Database tables created successfully!', 'success')
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
