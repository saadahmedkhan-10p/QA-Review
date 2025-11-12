from app import app, db, User
from werkzeug.security import generate_password_hash
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def setup_admin():
    with app.app_context():
        try:
            # First check if admin exists
            admin = User.query.filter_by(email='admin@questreviewer.com').first()
            if admin:
                logger.info("Admin user already exists. Updating password...")
                admin.password_hash = generate_password_hash('admin123')
            else:
                logger.info("Creating new admin user...")
                admin = User(
                    email='admin@questreviewer.com',
                    name='System Administrator',
                    password_hash=generate_password_hash('admin123'),
                    role='admin'
                )
                db.session.add(admin)
            
            db.session.commit()
            logger.info("Admin setup complete!")
            logger.info("Login credentials:")
            logger.info("Email: admin@questreviewer.com")
            logger.info("Password: admin123")
            
            # Verify admin exists and password works
            admin = User.query.filter_by(email='admin@questreviewer.com').first()
            from werkzeug.security import check_password_hash
            if admin and check_password_hash(admin.password_hash, 'admin123'):
                logger.info("Verified: Admin credentials are working correctly")
            else:
                logger.error("Error: Could not verify admin credentials!")
                
        except Exception as e:
            logger.error(f"Error setting up admin: {str(e)}")
            db.session.rollback()

if __name__ == '__main__':
    setup_admin()