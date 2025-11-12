from app import app, db
import os

# Create instance directory if it doesn't exist
instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
os.makedirs(instance_path, exist_ok=True)

with app.app_context():
    db.create_all()
    print("Database created successfully!")