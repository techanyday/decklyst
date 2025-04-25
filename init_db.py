from app import app
from models import init_db

with app.app_context():
    init_db()
    print("Database initialized successfully!")
