# Import necessary libraries for the application
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from datetime import datetime, timedelta
import os
import sqlite3
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from utils.inference import ModelInference  
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__, template_folder="templates")
app.secret_key = os.environ.get('SECRET_KEY')

app.config.update(
    MAIL_SERVER=os.environ.get('MAIL_SERVER'),
    MAIL_PORT=os.environ.get('MAIL_PORT'),
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD')
)

mail = Mail(app)

otp_store = {}


UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create the upload folder if it doesn't exist
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  # Set the upload folder in app config
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Set maximum content length to 5 MB

# Model path
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'model', 'detection_model.pt')

# Dummy users with hashed passwords for authentication
users = [
    {"username": "admin", "password": generate_password_hash("admin123"), "role": "admin"},
    {"username": "user", "password": generate_password_hash("user123"), "role": "user"}
]

# Simulated database for roads with random data
roads = []

# Function to initialize the database
def init_db():
    db_path = "database.db"  # Path to the database file
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        # Create a table for storing user queries
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                image_url TEXT NOT NULL,
                description TEXT NOT NULL,
                location TEXT,
                status TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS registered_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TEXT NOT NULL
            )
        """)
        conn.commit()  # Commit the changes to the database

# Call the function to initialize the database
init_db()

# Load the YOLO model
model_inference = ModelInference(MODEL_PATH)  # Load model at startup

# Initialize rate limiter with more lenient limits for session checks
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Add a specific limit for session checks
session_limiter = limiter.shared_limit("30 per minute", scope="session")

@app.before_request
def session_timeout():
    # Set the session to be permanent, meaning it will not expire when the user closes the browser
    session.permanent = True
    # Set the lifetime of the permanent session to 30 minutes
    app.permanent_session_lifetime = timedelta(minutes=30)

@app.before_request
def log_request():
    pass

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user' in session:
        if session.get('role') == 'admin':
            return render_template('index.html', roads=roads, user=session['user'], role=session['role'], now=datetime.now())
        return redirect(url_for('query_page'))
    captcha = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['captcha'] = captcha  # Store the CAPTCHA in the session
    return render_template('landing_page.html', captcha=captcha)
    

@app.route('/send-otp', methods=['POST'])
def send_otp():
    try:
        data = request.get_json()
        email = data.get('email')
        if not email or '@' not in email:
            return jsonify({'success': False, 'error': 'Invalid email address'})
        otp = ''.join(random.choices(string.digits, k=6))
        otp_store[email] = {
            'otp': otp,
            'timestamp': datetime.now(),
            'verified': False
        }
        if send_otp_email(email, otp):
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to send OTP'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    email = data["email"]
    otp = data["otp"]
    stored_otp = otp_store.get(email)
    if stored_otp and stored_otp["otp"] == otp:
        verified = session.get("otp_verified_emails", [])
        if email not in verified:
            verified.append(email)
            session["otp_verified_emails"] = verified
        return jsonify({"success": True})
    return jsonify({"success": False})

def send_otp_email(email, otp):
    try:
        msg = Message(
            'Your OTP for Road Health Monitor Registration',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = f'Your OTP for registration is: {otp}\nThis OTP will expire in 5 minutes.'
        mail.send(msg)
        return True
    except Exception as e:
        return False

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        otp = request.form['otp']
        if not username or len(username.strip()) < 2:
            return render_template('signup.html', error="Username must be at least 2 characters long", username=username, email=email)
        if not email or '@' not in email:
            return render_template('signup.html', error="Please provide a valid email address", username=username, email=email)
        if not password or len(password) < 8:
            return render_template('signup.html', error="Password must be at least 8 characters long", username=username, email=email)
        if password != confirm_password:
            return render_template('signup.html', error="Passwords do not match", username=username, email=email)
        stored_data = otp_store.get(email)
        if not stored_data or stored_data['otp'] != otp:
            return render_template('signup.html', error="Invalid or expired OTP", username=username, email=email)
        try:
            if add_user_to_db(username, email, password):
                otp_store.pop(email, None)
                session['registration_success'] = True
                return redirect(url_for('login'))
            else:
                return render_template('signup.html', error="Registration failed. Please try again with different credentials.", username=username, email=email)
        except Exception as e:
            return render_template('signup.html', error="An error occurred during registration. Please try again.", username=username, email=email)
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('index'))
    registration_success = session.pop('registration_success', False)
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        captcha = request.form.get('captcha', '')
        stored_captcha = session.get('captcha')
        if not captcha:
            return render_template('login.html', error="Please enter the CAPTCHA", username=username)
        if not stored_captcha or captcha.lower() != stored_captcha.lower():
            new_captcha = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            session['captcha'] = new_captcha
            return render_template('login.html', error="Invalid CAPTCHA", username=username, captcha=new_captcha)
        session.pop('captcha', None)  # Clear the CAPTCHA after validation
        user = next((u for u in users if u["username"] == username), None)
        if user and check_password_hash(user["password"], password):
            session['user'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('index'))
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, password, role FROM registered_users WHERE username = ? OR email = ?", (username, username))
            user_data = cursor.fetchone()
            if user_data and check_password_hash(user_data[1], password):
                session['user'] = user_data[0]
                session['role'] = user_data[2]
                return redirect(url_for('index'))
        new_captcha = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        session['captcha'] = new_captcha
        return render_template('login.html', error="Invalid credentials", username=username, captcha=new_captcha)
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['captcha'] = captcha_text
    return render_template('login.html', captcha=captcha_text, registration_success=registration_success)

@app.route('/query')
@login_required
def query_page():
    try:
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, timestamp, image_url, description FROM queries")
            queries = cursor.fetchall()
        return render_template('query.html', queries=queries)
    except sqlite3.Error as e:
        return jsonify({'error': 'Database error: ' + str(e)}), 500

@app.route('/submit_query', methods=['POST'])
def submit_query():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401  # Return unauthorized error if not logged in
    if 'image' not in request.files or request.files['image'].filename == '':
        return jsonify({'error': 'No image uploaded'}), 400  # Return error if no image is uploaded
    
    file_path = None  # Initialize file_path variable
    try:
        file = request.files['image']  # Get the uploaded file
        description = request.form['description']  # Get the description from the form
        location = request.form.get('location', '')  # Get the location from the form (optional)
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')  # Get the current timestamp
        filename = f"{session['user']}_{timestamp}_{file.filename}"  # Create a unique filename
        file_path = os.path.join(UPLOAD_FOLDER, filename)  # Define the file path for saving
        
        file.save(file_path)  # Save the uploaded file
        
        # Use the preloaded model
        pothole_detected = model_inference.predict(file_path)

        if pothole_detected:
            image_url = f'/static/uploads/{filename}'  # URL for the uploaded image
            
            with sqlite3.connect("database.db") as conn:
                cursor = conn.cursor()
                # Insert the query into the database with default status 'pending'
                cursor.execute("""
                    INSERT INTO queries (username, timestamp, image_url, description, location, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (session['user'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), image_url, description, location, 'pending'))
                
                # Update road conditions based on pothole detection
                # Find the closest road to the reported location
                if location:
                    try:
                        lat, lng = map(float, location.split(','))
                        # Find the road with the closest geolocation
                        closest_road = min(roads, key=lambda r: 
                            ((r['geolocation']['latitude'] - lat) ** 2 + 
                             (r['geolocation']['longitude'] - lng) ** 2) ** 0.5)
                        
                        # Update the road's condition based on the detection
                        current_condition = closest_road['condition']
                        if current_condition == 'Good':
                            closest_road['condition'] = 'Fair'
                        elif current_condition == 'Fair':
                            closest_road['condition'] = 'Poor'
                        elif current_condition == 'Poor':
                            closest_road['condition'] = 'Critical'
                        
                        # Update last inspected date
                        closest_road['last_inspected'] = datetime.now().isoformat()
                        
                    except ValueError:
                        # If location parsing fails, just continue without updating road conditions
                        pass
                
                conn.commit()  # Commit the changes to the database
            
            return jsonify({
                'message': 'Query submitted successfully', 
                'image_url': image_url,
                'success': True,
                'road_updated': True if location else False
            })  # Return success message
        else:
            return jsonify({
                'message': 'No pothole detected. Image not saved.',
                'success': False
            }), 200  # Return message if no pothole detected
    
    except Exception as e:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)  # Remove the file if an error occurs
        return jsonify({'error': str(e)}), 500  # Handle any other errors

@app.route('/get_queries')
def get_queries():
    try:
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, username, timestamp, image_url, description, location, status 
                FROM queries 
                ORDER BY timestamp DESC
            """)
            queries = cursor.fetchall()
            processed_queries = []
            for q in queries:
                location = q[5] or 'Location not specified'
                lat, lng = None, None
                if location != 'Location not specified':
                    try:
                        lat, lng = map(float, location.split(','))
                    except ValueError:
                        pass
                processed_queries.append({
                    'id': q[0],
                    'username': q[1],
                    'timestamp': q[2],
                    'image_url': q[3],
                    'description': q[4],
                    'location': location,
                    'status': q[6],
                    'coordinates': {'lat': lat, 'lng': lng} if lat and lng else None
                })
        return jsonify({
            'queries': processed_queries,
            'total': len(processed_queries)
        })
    except sqlite3.Error as e:
        return jsonify({'error': 'Database error occurred'}), 500

@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    
    # Instead of redirecting directly to login, redirect to a special logout page
    return redirect(url_for('perform_logout'))

@app.route('/perform_logout')
def perform_logout():
    # This page will handle the final redirect to login
    return render_template('logout.html')

# Add a session check endpoint
@app.route('/check_session')
@session_limiter
def check_session():
    """Check if the user is still logged in and return the status as JSON."""
    try:
        if 'user' in session:
            return jsonify({'logged_in': True})
        return jsonify({'logged_in': False})
    except Exception as e:
        return jsonify({'logged_in': False})

@app.after_request
def add_header(response):
    # Prevent caching for all responses
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    
    # Add security headers
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Updated CSP to allow necessary resources
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.tailwindcss.com; "
        "img-src 'self' data: https://images.unsplash.com; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )
    
    return response

@app.route('/update_complaint_status', methods=['POST'])
@login_required
def update_complaint_status():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json()
    complaint_id = data.get('complaint_id')
    new_status = data.get('status')
    if not complaint_id or not new_status:
        return jsonify({'error': 'Missing complaint_id or status'}), 400
    try:
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE queries SET status = ? WHERE id = ?
            """, (new_status, complaint_id))
            conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Admin routes with rate limiting and authentication
@app.route('/admin/dashboard')
@login_required
@limiter.limit("30 per minute")
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('index'))
    return render_template('admin_dashboard.html', roads=roads, user=session['user'], role=session['role'], now=datetime.now())

@app.route('/api/pothole_detections')
@login_required
@limiter.limit("30 per minute")
def get_pothole_detections():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, image_url, description, location, status 
                FROM queries 
                ORDER BY timestamp DESC
            """)
            detections = cursor.fetchall()
            processed_detections = []
            for d in detections:
                processed_detections.append({
                    'id': d[0],
                    'timestamp': d[1],
                    'image_url': d[2],
                    'description': d[3],
                    'location': d[4],
                    'status': d[5] or 'pending'
                })
        return jsonify(processed_detections)
    except sqlite3.Error:
        return jsonify({'error': 'Database error occurred'}), 500

# Error handler for rate limit exceeded
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'rate_limit_exceeded',
        'message': 'Too many requests. Please try again later.'
    }), 429

def add_user_to_db(username, email, password):
    try:
        db_path = "database.db"
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            hashed_password = generate_password_hash(password)
            created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(
                "INSERT INTO registered_users (username, email, password, role, created_at) VALUES (?, ?, ?, 'user', ?)",
                (username, email, hashed_password, created_at)
            )
            conn.commit()
            return True
    except sqlite3.IntegrityError as e:
        return False
    except Exception as e:
        return False

if __name__ == '__main__':
    app.run() 
