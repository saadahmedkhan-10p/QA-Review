from app import app, db, User
from werkzeug.security import generate_password_hash

def create_admin():
    with app.app_context():
        # Check if admin already exists
        admin = User.query.filter_by(email='admin@admin.com').first()
        if admin:
            print("Admin user already exists!")
            return
            
        # Create admin user
        admin = User(
            email='admin@admin.com',
            name='Administrator',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        
        db.session.add(admin)
        db.session.commit()
        print("Admin user created successfully!")
        print("Email: admin@admin.com")
        print("Password: admin123")

if __name__ == '__main__':
    create_admin()