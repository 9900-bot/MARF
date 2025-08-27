# File: backend/models.py

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Initialize SQLAlchemy to be used by the Flask application
db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    full_name = db.Column(db.String(120))
    email = db.Column(db.String(120), unique=True, nullable=False)
    
    # Add this column for password reset
    reset_token = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f"<User {self.full_name}>"

class Equipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    price = db.Column(db.Float, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_number = db.Column(db.String(20), nullable=False)
    image_filename = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f"<Equipment {self.name}>"

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f"<Booking for User {self.user_id} on Equipment {self.equipment_id}>"
