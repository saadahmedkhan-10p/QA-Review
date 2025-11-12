import os
import sys
import logging
from app import app, db, User
from werkzeug.security import generate_password_hash

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db():
    with app.app_context():
        # Ensure instance directory exists
        instance_path = os.path.join(app.root_path, 'instance')
        os.makedirs(instance_path, exist_ok=True)
        
        db_path = os.path.join(instance_path, 'quest_reviewer.db')
        logger.info(f"Initializing database at: {db_path}")
        
        try:
            # Create all tables
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Check if admin exists
            admin = User.query.filter_by(email='admin@questreviewer.com').first()
            if admin:
                logger.info("Admin user already exists")
            else:
                # Create admin user
                admin = User(
                    email='admin@questreviewer.com',
                    name='System Administrator',
                    password_hash=generate_password_hash('admin123'),
                    role='admin'
                )
                db.session.add(admin)
                db.session.commit()
                logger.info("Created admin user (admin@questreviewer.com / admin123)")
            
            return True
                
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            return False

if __name__ == '__main__':
    if init_db():
        logger.info("Database initialization completed successfully")
        sys.exit(0)
    else:
        logger.error("Database initialization failed")
        sys.exit(1)