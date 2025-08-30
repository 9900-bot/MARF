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
    reset_token = db.Column(db.String(200), nullable=True)

    # Relationships
    equipment = db.relationship('Equipment', backref='owner', lazy=True)
    bookings = db.relationship('Booking', backref='user', lazy=True)
    operators = db.relationship('Operator', backref='manager', lazy=True)

    # --- ADDED THIS NEW RELATIONSHIP FOR FARM SOLUTIONS ---
    # A User can submit multiple solutions. This creates the 'user.solutions' list.
    solutions = db.relationship('FarmSolution', backref='author', lazy=True, foreign_keys='FarmSolution.user_id')

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
    location = db.Column(db.String(255), nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    bookings = db.relationship('Booking', backref='equipment', lazy=True, cascade="all, delete-orphan")

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

class Operator(db.Model):
    __tablename__ = 'operators'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    contact_number = db.Column(db.String(20), nullable=False)
    location_name = db.Column(db.String(255), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    availability_status = db.Column(db.String(20), nullable=False, default='available')
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<Operator {self.full_name}>"


# --- ADDED THIS NEW MODEL FOR FARM SOLUTIONS ---

class FarmSolution(db.Model):
    __tablename__ = 'farm_solutions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending_review')
    submitted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Fields for the admin moderation process
    reviewed_at = db.Column(db.DateTime, nullable=True)
    moderator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    admin_notes = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f"<FarmSolution '{self.title}'>"