#!/usr/bin/env python3
"""Test script to verify database connection."""

from dotenv import load_dotenv
load_dotenv()

from app import create_app
from models import db

def test_connection():
    """Test the database connection."""
    try:
        app = create_app()
        with app.app_context():
            # Try to connect and execute a simple query
            db.engine.execute(db.text('SELECT 1'))
            print("✅ Database connection successful!")
            return True
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False

if __name__ == "__main__":
    test_connection()