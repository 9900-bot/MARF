from flask import Flask, request, jsonify, send_from_directory, url_for, redirect, render_template, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from passlib.hash import sha256_crypt
from datetime import datetime, timedelta
import os
import re
import uuid
import random
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
# Import for Google Sign-in
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
# Import the database models from models.py
from models import *
from sqlalchemy import or_

import math
import ssl
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from geopy.geocoders import Nominatim
from sqlalchemy import func


def haversine(lat1, lon1, lat2, lon2):
    """
    Calculate great-circle distance (km) between two lat/lon points.
    """
    R = 6371  # Earth radius in km
    dLat = math.radians(lat2 - lat1)
    dLon = math.radians(lon2 - lon1)
    a = math.sin(dLat/2)**2 + math.cos(math.radians(lat1)) \
        * math.cos(math.radians(lat2)) * math.sin(dLon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

# Create the Flask application instance
app = Flask(__name__, static_folder='../frontend/static', template_folder='../frontend')
CORS(app)
app.secret_key = "super_secret_key" 
# --- Configuration ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = "super-secret-key-that-should-be-kept-safe"
app.config["SECRET_KEY"] = "a-secret-key-for-token-generation"
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')
# Mail server configuration (you need to fill this out)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'marfteam22@gmail.com'
app.config['MAIL_PASSWORD'] = 'cprc jtem pvvx ggbk'
mail = Mail(app)

# You must provide your own Google Client ID here
GOOGLE_CLIENT_ID = "YOUR_GOOGLE_CLIENT_ID_HERE"

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
jwt = JWTManager(app)
db.init_app(app)
CORS(app)

with app.app_context():
    db.create_all() 

# --- ADD THIS NEW FUNCTION ANYWHERE IN YOUR app.py ---
@app.cli.command("init-db")
def init_db_command():
    """Drops and recreates the database tables."""
    with app.app_context():
        print("--- Dropping all database tables... ---")
        db.drop_all()
        print("--- Creating all database tables... ---")
        db.create_all()
        print("--- Database initialized successfully! ---")

# --- Password Validation Function ---
def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."
    return None

# --- Email Validation Function ---
def validate_email(email):
    if not email:
        return "Email is required."
    
    email_regex = re.compile(r"^[\w.-]+@([\w-]+\.)+[\w-]{2,4}$")
    if not email_regex.match(email):
        return "Please enter a valid email address."
    
    domain = email.split('@')[-1]
    allowed_domains = ['gmail.com', 'yahoo.com', 'outlook.com']
    if domain not in allowed_domains:
        return f"Email domain '{domain}' is not supported."
        
    return None

def send_verification_email(to_email, reset_link):
    sender_email = app.config['MAIL_USERNAME']
    app_password = app.config['MAIL_PASSWORD']

    subject = "Password Reset Request"
    body = f"""
    Hello,

    We received a request to reset your password.
    Click here to reset it: {reset_link}

    If this wasn't you, please ignore this email.

    Regards,
    Team MARF
    """

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_email
    msg.attach(MIMEText(body, "plain"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, app_password)
            server.sendmail(sender_email, to_email, msg.as_string())
        print("✅ Email sent successfully!")
        return True
    except Exception as e:
        print(f"❌ Error sending email: {e}")
        return False


# --- API Endpoints ---
@app.route("/")
@app.route("/dash.html")
def serve_dashboard():
    return render_template("dash.html")


@app.route("/uploads/<filename>", methods=["GET"])
def get_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    full_name = data.get("full_name")
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "farmer")

    if not full_name or not username or not password or not email:
        return jsonify({"msg": "All required fields are missing"}), 400

    password_error = validate_password(password)
    if password_error:
        return jsonify({"msg": password_error}), 400

    email_error = validate_email(email)
    if email_error:
        return jsonify({"msg": email_error}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "Username already exists"}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "Email already exists"}), 409

    hashed_password = sha256_crypt.hash(password)
    new_user = User(username=username, password=hashed_password, role=role, full_name=full_name, email=email)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User created successfully"}), 201

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username_or_email = data.get("username")
        password = data.get("password")

        if not username_or_email or not password:
            return jsonify({"msg": "Username/phone/email and password are required"}), 400

        user = User.query.filter(
            or_(
                User.username == username_or_email,
                User.email == username_or_email
            )
        ).first()

        if user and sha256_crypt.verify(password, user.password):
            access_token = create_access_token(identity=str(user.id))
            return jsonify(
                access_token=access_token, 
                role=user.role, 
                full_name=user.full_name,
                email=user.email
            ), 200
        else:
            return jsonify({"msg": "Invalid username or password"}), 401
    return render_template('login.html')
    
@app.route("/google/callback", methods=["POST"])
def google_callback():
    data = request.get_json()
    token = data.get("token")
    if not token:
        return jsonify({"msg": "Token not provided"}), 400

    try:
        # Use a new request object for the verification call
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), "337803351297-uuqu9h0uas0qq4okmhq4g2649jn3v9s6.apps.googleusercontent.com")
        email = idinfo.get("email")
        if not email:
            return jsonify({"msg": "Email not found in token"}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            # For this simple app, we can auto-register the user
            user = User(
                username=email, # Use email as username for Google logins
                email=email,
                full_name=idinfo.get("name"),
                password=sha256_crypt.hash(str(uuid.uuid4())), # Generate a random password
                role="farmer"
            )
            db.session.add(user)
            db.session.commit()
            
        access_token = create_access_token(identity=str(user.id))
        return jsonify(
            access_token=access_token,
            role=user.role,
            full_name=user.full_name,
            email=user.email
        ), 200
        
    except ValueError:
        return jsonify({"msg": "Invalid token"}), 400
    


@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data.get("email")

    print("📩 Forgot password request received for:", email) # DEBUG

    if not email:
        return jsonify({"msg": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg": "Email not found"}), 404

    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    token = s.dumps(user.email, salt='password-reset-salt')
    reset_link = url_for('verify_reset', token=token, _external=True)

    msg = Message(
        subject='Password Reset Request for MARF',
        sender=app.config['MAIL_USERNAME'],
        recipients=[user.email]
    )
    msg.body = (
        f'Hello {user.full_name},\n\n'
        f'Click the following link to reset your password: {reset_link}\n\n'
        f'The link will expire in 10 minutes.\n\n'
        f'If you did not request a password reset, please ignore this email.'
    )
    
    try:
        mail.send(msg)
        print("📨 Sending mail to:", email) # DEBUG
        return jsonify({"msg": "Password reset link sent to your email"}), 200
    except Exception as e:
        print("❌ Mail send failed:", e)
        return jsonify({"msg": "Failed to send email"}), 500


@app.route("/verify-reset/<token>", methods=["GET"])
def verify_reset(token):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=600)
    except (SignatureExpired, BadSignature):
        return jsonify({"msg": "Link expired or invalid, please request a new one."}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404
        
    user.reset_token = token
    db.session.commit()
    
    return redirect(url_for('reset_password_page', token=token))
    
@app.route("/reset-password-page")
def reset_password_page():
    return render_template("reset_password.html")

@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    token = data.get("token")
    new_password = data.get("password")

    if not token or not new_password:
        return jsonify({"msg": "Missing token or new password"}), 400

    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=600)
    except (SignatureExpired, BadSignature):
        return jsonify({"msg": "Link expired or invalid, please request a new one."}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404

    if user.reset_token != token:
        return jsonify({"msg": "Invalid or reused token"}), 400

    password_error = validate_password(new_password)
    if password_error:
        return jsonify({"msg": password_error}), 400

    user.password = sha256_crypt.hash(new_password)
    user.reset_token = None
    db.session.commit()

    return jsonify({"msg": "Password reset successful"}), 200



@app.route("/addequipment", methods=["POST"])
@jwt_required()
def add_equipment():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user or user.role != 'owner':
        return jsonify({"msg": "Permission denied"}), 403

    # form fields
    name = request.form.get("name")
    description = request.form.get("description")
    price = request.form.get("price")
    contact_number = request.form.get("contact_number")
    image_file = request.files.get("image")
    location = request.form.get("location")      # human readable address
    latitude = request.form.get("latitude")     # may be '' or None
    longitude = request.form.get("longitude")

    # basic validation (same as before + location optional)
    if not name or not description or not price or not contact_number or not image_file:
        return jsonify({"msg": "All required fields (name, description, price, contact_number, image) are required"}), 400

    try:
        price_val = float(price)
        if price_val <= 0:
            return jsonify({"msg": "Please enter a valid positive price."}), 400
    except ValueError:
        return jsonify({"msg": "Invalid price value."}), 400

    # save image
    image_filename = str(uuid.uuid4()) + os.path.splitext(image_file.filename)[1]
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
    image_file.save(image_path)

    # convert coordinates if provided
    lat_val = None
    lon_val = None
    try:
        if latitude:
            lat_val = float(latitude)
        if longitude:
            lon_val = float(longitude)
    except Exception:
        # ignore conversion errors, store None
        lat_val = None
        lon_val = None

    new_equipment = Equipment(
        name=name,
        description=description,
        price=price_val,
        owner_id=current_user_id,
        contact_number=contact_number,
        image_filename=image_filename,
        location=location,
        latitude=lat_val,
        longitude=lon_val
    )

    db.session.add(new_equipment)
    db.session.commit()

    return jsonify({"msg": "Equipment added successfully"}), 201


@app.route("/my-equipment", methods=["GET"])
@jwt_required()
def my_equipment():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user or user.role != 'owner':
        return jsonify({"msg": "Permission denied. Only owners can view their equipment."}), 403

    owner_equipment = Equipment.query.filter_by(owner_id=current_user_id).all()

    equipment_list = [{
        "id": equip.id,
        "name": equip.name,
        "description": equip.description,
        "price": equip.price,
        "contact_number": equip.contact_number,
        "image_url": f"/uploads/{equip.image_filename}" if equip.image_filename else "https://placehold.co/600x400/cccccc/333333?text=No+Image",
        "location": equip.location,
        "latitude": equip.latitude,
        "longitude": equip.longitude
    } for equip in owner_equipment]

    return jsonify(equipment_list), 200

@app.route("/equipment", methods=["GET"])
def get_equipment():
    # Get location from session if available, fallback to query args
    lat = session.get('latitude', request.args.get("lat", type=float))
    lon = session.get('longitude', request.args.get("lon", type=float))

    equipment = Equipment.query.all()
    equipment_list = []

    for equip in equipment:
        dist = None
        if lat and lon and equip.latitude and equip.longitude:
            dist = haversine(lat, lon, equip.latitude, equip.longitude)

        equipment_list.append({
            "id": equip.id,
            "name": equip.name,
            "description": equip.description,
            "price": equip.price,
            "contact_number": equip.contact_number,
            "image_url": f"/uploads/{equip.image_filename}" if equip.image_filename else "https://placehold.co/600x400/cccccc/333333?text=No+Image",
            "location": equip.location,
            "latitude": equip.latitude,
            "longitude": equip.longitude,
            "distance": dist
        })

    # Sort by distance if a location is available
    if lat is not None and lon is not None:
        equipment_list.sort(key=lambda x: x["distance"] if x["distance"] is not None else float("inf"))

    return jsonify(equipment_list), 200


@app.route("/delete-equipment/<int:equipment_id>", methods=["DELETE"])
@jwt_required()
def delete_equipment(equipment_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user or user.role != "owner":
        return jsonify({"error": "Permission denied"}), 403

    equipment = Equipment.query.get(equipment_id)

    if not equipment:
        return jsonify({"error": "Equipment not found"}), 404

    if equipment.owner_id != current_user_id:
        return jsonify({"error": "You can only delete your own equipment"}), 403

    # Delete associated image file if exists
    if equipment.image_filename:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], equipment.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)

    db.session.delete(equipment)
    db.session.commit()

    return jsonify({"msg": "Equipment deleted successfully"}), 200


@app.route("/book", methods=["POST"])
@jwt_required()
def book_equipment():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if user.role != 'farmer':
        return jsonify({"msg": "Permission denied. Only farmers can book equipment."}), 403

    data = request.get_json()
    equipment_id = data.get("equipment_id")
    start_date_str = data.get("start_date")
    end_date_str = data.get("end_date")

    if not equipment_id or not start_date_str or not end_date_str:
        return jsonify({"msg": "Missing booking details"}), 400

    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
    except ValueError:
        return jsonify({"msg": "Invalid date format. Use YYYY-MM-DD"}), 400

    existing_bookings = Booking.query.filter(
        Booking.equipment_id == equipment_id,
        Booking.start_date <= end_date,
        Booking.end_date >= start_date
    ).first()

    if existing_bookings:
        return jsonify({"msg": "Equipment is not available during this period"}), 409
    
    new_booking = Booking(
        user_id=current_user_id,
        equipment_id=equipment_id,
        start_date=start_date,
        end_date=end_date
    )
    db.session.add(new_booking)
    db.session.commit()

    return jsonify({"msg": "Booking successful"}), 201


@app.route("/booking-history", methods=["GET"])
@jwt_required()
def booking_history():
    current_user_id = get_jwt_identity()

    history = db.session.query(Booking, Equipment).join(
        Equipment, Booking.equipment_id == Equipment.id
    ).filter(Booking.user_id == current_user_id).all()

    booking_list = [{
        "booking_id": booking.id,
        "equipment_name": equipment.name,
        "start_date": booking.start_date.strftime('%Y-%m-%d'),
        "end_date": booking.end_date.strftime('%Y-%m-%d'),
        "total_cost": (booking.end_date - booking.start_date).days * equipment.price
    } for booking, equipment in history]

    return jsonify(booking_list), 200

@app.route("/dashboard", methods=["GET"])
@jwt_required()
def dashboard():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({"msg": "User not found"}), 404

    return jsonify({
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "full_name": user.full_name,
        "id": user.id
    }), 200

@app.route("/my-account", methods=["GET"])
@jwt_required()
def my_account():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"msg": "User not found"}), 404

    return jsonify({
        "title": "My Account",
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.username,  # hardcoded or fallback
        "address": "Mandya, Karnataka",  # hardcoded or fallback
        "language": "English",  # default
        "profile_picture_url": "https://placehold.co/200x200"
    }), 200

# --- OPERATOR API ENDPOINTS (REPLACE the old ones in your app.py) ---

# --- REPLACE the old /api/operators POST endpoint with this new, improved version ---

@app.route("/api/operators", methods=['POST'])
@jwt_required()
def register_operator():
    """
    Endpoint for a logged-in user to register as an operator.
    This also changes the user's role.
    This version performs geocoding on the backend for accuracy.
    """
    try:
        current_user_id = int(get_jwt_identity())
    except (ValueError, TypeError):
        return jsonify({"msg": "Invalid token identity"}), 422

    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"msg": "User not found"}), 404
    
    if user.role == 'owner':
        return jsonify({"msg": "Users with the 'owner' role cannot also be operators."}), 403
        
    data = request.get_json()
    # Note: We no longer require latitude and longitude from the client.
    required_fields = ['fullName', 'contactNumber', 'locationName', 'availability']
    if not all(field in data for field in required_fields):
        return jsonify({"msg": "Missing required fields (fullName, contactNumber, locationName, availability)"}), 400

    location_name = data.get('locationName')
    lat, lon = None, None

    # --- START OF THE FIX: Geocoding the address ---
    try:
        # Initialize the geocoder (Nominatim is a free service from OpenStreetMap)
        geolocator = Nominatim(user_agent="marf_app_v1") 
        
        # Attempt to get coordinates from the provided location name
        location_data = geolocator.geocode(location_name)
        
        if location_data:
            lat = location_data.latitude
            lon = location_data.longitude
            print(f"✅ Geocoding successful for '{location_name}': ({lat}, {lon})")
        else:
            # If geocoding fails, we can't create an operator with a valid location.
            print(f"❌ Geocoding failed for '{location_name}'")
            return jsonify({"msg": f"Could not find coordinates for the location: '{location_name}'. Please provide a more specific address."}), 400

    except Exception as e:
        print(f"❌ An error occurred during geocoding: {e}")
        return jsonify({"msg": "An error occurred while processing the location."}), 500
    # --- END OF THE FIX ---

    new_operator = Operator(
        user_id=current_user_id,
        full_name=data['fullName'],
        contact_number=data['contactNumber'],
        location_name=location_name, # Store the original human-readable name
        latitude=lat,               # Store the newly found latitude
        longitude=lon,              # Store the newly found longitude
        availability_status=data['availability']
    )
    
    user.role = 'operator'
    
    db.session.add(new_operator)
    db.session.commit()

    return jsonify({"msg": "Successfully registered as an operator. Your role has been updated."}), 201
# --- REPLACE this endpoint in app.py ---
@app.route('/save-location', methods=['POST'])
@jwt_required() # Protect this endpoint
def save_location():
    data = request.json
    latitude = data.get("latitude")
    longitude = data.get("longitude")

    if not latitude or not longitude:
        return jsonify({"msg": "Missing latitude or longitude"}), 400

    # Store location in the user's session
    session['latitude'] = float(latitude)
    session['longitude'] = float(longitude)

    return jsonify({"msg": "Location saved to session successfully"}), 200


# --- REPLACE this endpoint in app.py ---
# --- REMOVE the old register_operator and get_operators functions ---
# --- ADD this new combined function in their place ---

from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity # Make sure this is imported at the top

@app.route("/api/operators", methods=['GET', 'POST'])
def handle_operators():
# In app.py, inside the handle_operators function

    # --- POST Request Logic (for registering a new operator) ---
    if request.method == 'POST':
        # This block is for creating a new operator. It must be protected.
        try:
            verify_jwt_in_request()
        except Exception as e:
            return jsonify(msg="Missing or invalid authorization token."), 401

        try:
            current_user_id = int(get_jwt_identity())
        except (ValueError, TypeError):
            return jsonify({"msg": "Invalid token identity"}), 422

        user = User.query.get(current_user_id)
        if not user:
            return jsonify({"msg": "User not found"}), 404
        
        # --- LOGIC CHANGE STARTS HERE ---

        # REMOVED: The check that a user can only be one operator.
        # REMOVED: The restriction that 'owners' cannot add operators. This is more flexible.
        
        data = request.get_json()
        required_fields = ['fullName', 'contactNumber', 'locationName', 'availability']
        if not all(field in data for field in required_fields):
            return jsonify({"msg": "Missing required fields (fullName, contactNumber, locationName, availability)"}), 400

        # ADDED: A new, better check. Prevent a user from adding two operators with the same phone number.
        contact_number = data.get('contactNumber')
        existing_operator = Operator.query.filter_by(user_id=current_user_id, contact_number=contact_number).first()
        if existing_operator:
            return jsonify({"msg": f"You have already created an operator profile with the contact number {contact_number}."}), 409

        location_name = data.get('locationName')
        lat, lon = None, None

        try:
            geolocator = Nominatim(user_agent="marf_app_v2") # Changed user agent version
            location_data = geolocator.geocode(location_name)
            
            if location_data:
                lat = location_data.latitude
                lon = location_data.longitude
            else:
                return jsonify({"msg": f"Could not find coordinates for location: '{location_name}'."}), 400
        except Exception as e:
            print(f"❌ Geocoding error: {e}")
            return jsonify({"msg": "An error occurred while processing the location."}), 500

        new_operator = Operator(
            user_id=current_user_id, # The user is the manager/creator
            full_name=data['fullName'],
            contact_number=contact_number,
            location_name=location_name,
            latitude=lat,
            longitude=lon,
            availability_status=data['availability']
        )
        
        # REMOVED: We no longer change the user's role. A user is a user, they just manage operators.
        # user.role = 'operator' 
        
        db.session.add(new_operator)
        db.session.commit()
        
        # UPDATED: The success message is now more accurate.
        return jsonify({"msg": "Operator profile created successfully."}), 201
    # --- GET Request Logic (for searching/filtering operators) ---
    if request.method == 'GET':
        args = request.args
        name_filter = args.get('name')
        availability_filter = args.get('availability')
        distance_km = args.get('distance', type=float)
        
        lat = args.get('lat', session.get('latitude'), type=float)
        lng = args.get('lon', session.get('longitude'), type=float)

        query = db.session.query(Operator).filter(Operator.is_active == True)

        if name_filter:
            query = query.filter(Operator.full_name.ilike(f"%{name_filter}%"))
        if availability_filter and availability_filter != 'all':
            query = query.filter(Operator.availability_status == availability_filter)

        if lat is not None and lng is not None:
            distance_sql = 6371 * func.acos(
                func.cos(func.radians(lat)) * func.cos(func.radians(Operator.latitude)) *
                func.cos(func.radians(Operator.longitude) - func.radians(lng)) +
                func.sin(func.radians(lat)) * func.sin(func.radians(Operator.latitude))
            )
            
            query = query.add_columns(distance_sql.label('distance'))
            
            if distance_km is not None:
                query = query.filter(distance_sql <= distance_km)
                
            query = query.order_by(distance_sql)
            
            results = query.all()
            operator_list = []
            for row in results:
                op, dist = row
                op_data = {
                    "id": op.id, "user_id": op.user_id, "full_name": op.full_name,
                    "contact_number": op.contact_number, "location_name": op.location_name,
                    "latitude": op.latitude, "longitude": op.longitude,
                    "availability_status": op.availability_status, "distance": dist
                }
                operator_list.append(op_data)
        else:
            results = query.all()
            operator_list = [
                {"id": op.id, "user_id": op.user_id, "full_name": op.full_name,
                 "contact_number": op.contact_number, "location_name": op.location_name,
                 "latitude": op.latitude, "longitude": op.longitude,
                 "availability_status": op.availability_status, "distance": None} for op in results
            ]

        return jsonify(operator_list), 200

# --- ADD THIS NEW ENDPOINT to app.py ---

@app.route("/my-operators", methods=["GET"])
@jwt_required()
def my_operators():
    """
    Endpoint for a logged-in user to view all the operator
    profiles they have created.
    """
    try:
        current_user_id = int(get_jwt_identity())
    except (ValueError, TypeError):
        return jsonify({"msg": "Invalid token identity"}), 422
        
    # Query for all operators created by the current user
    user_operators = Operator.query.filter_by(user_id=current_user_id).order_by(Operator.full_name).all()
    
    # Serialize the data into a list of dictionaries
    operator_list = [
        {
            "id": op.id,
            "user_id": op.user_id,
            "full_name": op.full_name,
            "contact_number": op.contact_number,
            "location_name": op.location_name,
            "latitude": op.latitude,
            "longitude": op.longitude,
            "availability_status": op.availability_status,
            "is_active": op.is_active
        } for op in user_operators
    ]
    
    return jsonify(operator_list), 200

# --- FARM SOLUTIONS API ENDPOINTS ---
# Add these new functions to your app.py file

@app.route("/api/solutions", methods=["GET"])
def get_solutions():
    """
    Public endpoint to fetch all APPROVED farm solutions.
    """
    # Query for solutions that are approved and join with the User table to get author info
    approved_solutions = db.session.query(FarmSolution, User).join(
        User, FarmSolution.user_id == User.id
    ).filter(
        FarmSolution.status == 'approved'
    ).order_by(
        FarmSolution.submitted_at.desc()
    ).all()

    solutions_list = []
    for solution, user in approved_solutions:
        solutions_list.append({
            "id": solution.id,
            "title": solution.title,
            "description": solution.description,
            "submitted_at": solution.submitted_at.strftime("%B %d, %Y"),
            "author_name": user.full_name,
            # You might want to add a location field to your User model in the future
            "author_location": "Karnataka, India" 
        })
        
    return jsonify(solutions_list), 200


@app.route("/api/solutions", methods=["POST"])
@jwt_required()
def submit_solution():
    """
    Protected endpoint for a logged-in user to submit a new farm solution.
    """
    try:
        current_user_id = int(get_jwt_identity())
    except (ValueError, TypeError):
        return jsonify({"msg": "Invalid token identity"}), 422
    
    data = request.get_json()
    title = data.get("title")
    description = data.get("description")

    if not title or not description:
        return jsonify({"msg": "Title and description are required."}), 400

    new_solution = FarmSolution(
        user_id=current_user_id,
        title=title,
        description=description
        # The 'status' and 'submitted_at' fields will use their default values
    )

    db.session.add(new_solution)
    db.session.commit()

    return jsonify({"msg": "Your solution has been submitted for review. Thank you!"}), 201

# Add these imports at the top of your app.py if they are not already there
from flask_jwt_extended import verify_jwt_in_request
from functools import wraps

# --- ADMIN PANEL API ENDPOINTS ---

# Helper decorator to protect routes for admins only
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt() # You might need to import get_jwt from flask_jwt_extended
            if claims.get('role') != 'admin':
                return jsonify(msg='Admins only!'), 403
            else:
                return fn(*args, **kwargs)
        return decorator
    return wrapper


@app.route("/api/admin/solutions/pending", methods=["GET"])
@jwt_required() # First, ensure user is logged in
def get_pending_solutions():
    """
    Fetches all farm solutions with a 'pending_review' status.
    Protected to ensure only admins can access it.
    """
    # We need to get the user ID and then check their role from the database
    # as claims might not be set up in your simple token.
    try:
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        if not user or user.role != 'admin':
            return jsonify(msg="Administrator access required."), 403
    except (ValueError, TypeError):
        return jsonify(msg="Invalid token."), 422

    pending_solutions = db.session.query(FarmSolution, User).join(
        User, FarmSolution.user_id == User.id
    ).filter(
        FarmSolution.status == 'pending_review'
    ).order_by(
        FarmSolution.submitted_at.asc() # Show oldest first
    ).all()

    solutions_list = []
    for solution, author in pending_solutions:
        solutions_list.append({
            "id": solution.id,
            "title": solution.title,
            "description": solution.description,
            "submitted_at": solution.submitted_at.strftime("%B %d, %Y"),
            "author_name": author.full_name
        })
        
    return jsonify(solutions_list), 200


@app.route("/api/admin/solutions/review/<int:solution_id>", methods=["POST"])
@jwt_required()
def review_solution(solution_id):
    """
    Updates the status of a farm solution to 'approved' or 'rejected'.
    Protected to ensure only admins can perform this action.
    """
    try:
        moderator_id = int(get_jwt_identity())
        user = User.query.get(moderator_id)
        if not user or user.role != 'admin':
            return jsonify(msg="Administrator access required."), 403
    except (ValueError, TypeError):
        return jsonify(msg="Invalid token."), 422
    
    solution = FarmSolution.query.get(solution_id)
    if not solution:
        return jsonify(msg="Solution not found."), 404
        
    if solution.status != 'pending_review':
        return jsonify(msg="This solution has already been reviewed."), 400

    data = request.get_json()
    decision = data.get("decision")
    notes = data.get("notes")

    if decision not in ['approved', 'rejected']:
        return jsonify(msg="Invalid decision. Must be 'approved' or 'rejected'."), 400

    # Update the solution record
    solution.status = decision
    solution.moderator_id = moderator_id
    solution.admin_notes = notes
    solution.reviewed_at = datetime.utcnow()
    
    db.session.commit()
    
    return jsonify(msg=f"Solution has been successfully {decision}."), 200

# --- ADD THIS NEW ENDPOINT TO YOUR app.py FILE ---

@app.route("/my-solutions", methods=["GET"])
@jwt_required()
def my_solutions():
    """
    Fetches all farm solutions submitted by the currently logged-in user.
    """
    try:
        current_user_id = int(get_jwt_identity())
    except (ValueError, TypeError):
        return jsonify({"msg": "Invalid token identity"}), 422
        
    # Query for all solutions created by the current user, ordered by most recent first
    user_solutions = FarmSolution.query.filter_by(
        user_id=current_user_id
    ).order_by(
        FarmSolution.submitted_at.desc()
    ).all()
    
    # Serialize the data into a list of dictionaries
    solutions_list = [
        {
            "id": sol.id,
            "title": sol.title,
            "description": sol.description,
            "submitted_at": sol.submitted_at.strftime("%Y-%m-%d"),
            "status": sol.status,  # e.g., 'pending_review', 'approved', 'rejected'
            "admin_notes": sol.admin_notes # Optional: show feedback to the user
        } for sol in user_solutions
    ]
    
    return jsonify(solutions_list), 200

if __name__ == "__main__":
    app.run(debug=True)
