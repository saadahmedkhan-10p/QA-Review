from app import app, db, init_db_cli

with app.app_context():
    # Drop all existing tables
    db.drop_all()
    print("Dropped all tables")
    
    # Create all tables with new schema
    db.create_all()
    print("Created all tables with new schema")
    
    # Initialize admin user
    init_db_cli()
    print("Database reset complete!")