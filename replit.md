# QA Review System

## Overview
A Flask-based Quality Assurance Review application with role-based access control, admin panel for question management, and monthly project submission tracking. The application allows administrators to configure review questions and manage projects, while users can submit monthly QA reviews for their assigned projects.

## Recent Changes
- **2025-10-22**: Initial project setup with complete Flask application
  - Created database models for Users, Questions, Projects, Submissions, and Answers
  - Implemented authentication system with Flask-Login
  - Built role-based access control (Admin, User roles)
  - Created admin panel for managing questions and projects
  - Built submission form system for monthly QA reviews
  - Added responsive Bootstrap UI with gradient design
  - Initialized PostgreSQL database with admin user

## Project Architecture

### Tech Stack
- **Backend**: Flask (Python 3.11)
- **Database**: PostgreSQL (via Neon/Replit)
- **Authentication**: Flask-Login with password hashing
- **Forms**: Flask-WTF with CSRF protection
- **ORM**: SQLAlchemy
- **Frontend**: Jinja2 templates with Bootstrap 5

### Database Schema
- **users**: User accounts with email, password, name, and role
- **questions**: Review questions with text, type, required flag, and order
- **projects**: Projects that can be reviewed
- **submissions**: User submissions for specific projects and months
- **answers**: Individual answers linking submissions to questions

### User Roles
- **Admin**: Full access to manage questions, projects, and view all submissions
- **User**: Can submit reviews and view their own submissions

### Key Features
1. **Authentication**:
   - Email/password registration and login
   - Session management with Flask-Login
   - Role-based access control

2. **Admin Panel**:
   - Create, edit, delete review questions
   - Manage projects
   - View all submissions with filtering by project and month
   - Dashboard with statistics

3. **User Interface**:
   - Submit monthly QA reviews for projects
   - View personal submission history
   - Dynamic form generation based on admin-configured questions

4. **Question Types**:
   - Short text
   - Long text (textarea)
   - Number
   - Date

### File Structure
```
.
├── app.py                 # Main application with routes, models, and forms
├── templates/             # Jinja2 HTML templates
│   ├── base.html         # Base template with navigation and Bootstrap
│   ├── login.html        # Login page
│   ├── register.html     # Registration page
│   ├── admin_dashboard.html      # Admin overview and submissions
│   ├── manage_questions.html     # Question management
│   ├── question_form.html        # Add/edit question form
│   ├── manage_projects.html      # Project management
│   ├── project_form.html         # Add/edit project form
│   ├── user_dashboard.html       # User overview and submission list
│   ├── submit_review.html        # Monthly QA review form
│   └── view_submission.html      # View submission details
└── static/               # Static assets (CSS, JS)
```

### Routes
- `/` - Home (redirects to dashboard based on role)
- `/login` - User login
- `/register` - User registration
- `/logout` - User logout
- `/init-db` - Database initialization (creates tables and admin user)
- `/dashboard` - User dashboard
- `/submit/<project_id>` - Submit QA review for a project
- `/submission/<id>` - View submission details
- `/admin/dashboard` - Admin dashboard with all submissions
- `/admin/questions` - Manage questions
- `/admin/questions/add` - Add new question
- `/admin/questions/edit/<id>` - Edit question
- `/admin/questions/delete/<id>` - Delete question
- `/admin/projects` - Manage projects
- `/admin/projects/add` - Add new project
- `/admin/projects/edit/<id>` - Edit project
- `/admin/projects/delete/<id>` - Delete project

### Default Admin Credentials
- **Email**: admin@qa.com
- **Password**: admin123

## Environment Variables
- `DATABASE_URL` - PostgreSQL connection string (automatically set by Replit)
- `SESSION_SECRET` - Flask session secret key (automatically set by Replit)

## Getting Started

### Initial Setup
1. The application is automatically running on port 5000
2. Initialize the database with admin user (first time only):
   ```bash
   flask --app app init-db-cli
   ```
3. Visit the home page to access the login screen
4. Login with admin credentials to configure questions and projects
5. Regular users can register and start submitting reviews once projects are created

### Security Features
- **CSRF Protection**: All forms are protected with CSRF tokens via Flask-WTF
- **Secure Authentication**: Passwords are hashed using Werkzeug's password hashing
- **Open Redirect Protection**: Login redirects are validated to prevent external redirects
- **Role-Based Access Control**: Admin routes are protected with authentication decorators
- **Database Initialization**: Admin creation is restricted to CLI command only

## Future Enhancements (Next Phase)
- Email notifications for submission deadlines
- Submission approval workflow with comments
- Analytics dashboard with charts showing QA trends
- Export functionality (CSV, PDF reports)
- Submission versioning and edit history
- Additional user roles (Reviewer, Manager)
- Question categories and templates
- File upload support for questions
- Bulk import/export of questions
