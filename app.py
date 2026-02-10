from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
import random
import smtplib
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail
import os
from werkzeug.utils import secure_filename
from flask import request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import re

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///yourdatabase.db'  # Replace with your actual database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///all_storage.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'path/to/static/uploads'  # Define your upload directory

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


# SQLAlchemy Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///all_storage.db'  # Updated to new database name
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')  # Add role column

    def __repr__(self):
        return f'<User {self.username}>'


# Define Rental model
class Rental(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    duration = db.Column(db.String(50), nullable=False)
    property_type = db.Column(db.String(50), nullable=False)
    #status = db.Column(db.String(50), nullable=True)  # Allow NULL for status
    status = db.Column(db.String(50), default='pending', nullable=False)  # Ensure status is either 'pending' or a default value
    
    def __repr__(self):
        return f'<Rental {self.name}>'

# Ensure database tables are created
with app.app_context():
    db.create_all()

# Property Model
class Property(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    price = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    images = db.relationship('Image', backref='property', lazy=True, cascade="all, delete-orphan")  # Cascade delete

    def __repr__(self):
        return f"<Property {self.name}>"

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=False)  # Foreign key
    image_path = db.Column(db.String(255), nullable=False)  # Store image file path

    def __repr__(self):
        return f"<Image {self.image_path}>"
 
@app.route('/admin_panel')
def admin_panel():
    user_id = session.get('user_id')

    if not user_id:
        flash("You must be logged in to access the admin panel.", "warning")
        return redirect(url_for('login'))

    user = User.query.get(user_id)

    if user is None:
        flash("User not found. Please log in again.", "danger")
        session.pop('user_id', None)
        return redirect(url_for('login'))

    if user.role != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('index'))  # ✅ Changed from 'home' to 'index'

    total_users = User.query.count()
    total_properties = Property.query.count()
    rented_requests = Rental.query.filter_by(status='rented').count()
    pending_requests = Rental.query.filter_by(status='pending').count()

    return render_template(
        'admin.html',
        total_users=total_users,
        total_properties=total_properties,
        rented_requests=rented_requests,
        pending_requests=pending_requests
    )



def is_admin():
    user_id = session.get('user_id')  # Retrieve logged-in user's ID
    return user_id == 1  # Return True if the user is an admin

# Route for Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            # Check if the user is an admin and redirect accordingly
            if user.role == 'admin':
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('index'))
        error = 'Invalid username or password.'

    return render_template('login.html', error=error)

# Route for Signup Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Password validation
        if len(password) < 8:
            message = "Password must be at least 8 characters."
        elif not re.search(r'[A-Z]', password):
            message = "Password must contain at least one uppercase letter."
        elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            message = "Password must contain at least one special character."
        else:
            # Check if username already exists
            if User.query.filter_by(username=username).first():
                message = "Username already exists."
            else:
                # Hash the password with pbkdf2:sha256
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

                # Create a new user with hashed password
                new_user = User(username=username, password=hashed_password)

                # Add user to the database
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for('login'))

    return render_template('signup.html', message=message)

# Route for Root URL (Home page)
@app.route('/', methods=['GET', 'POST'])
def index():
    # Handle search query directly on the homepage
    search_query = request.args.get('search')  # Get the search query from URL parameters

    if search_query:
        # Filter properties based on location using the 'ilike' method for case-insensitive search
        properties = Property.query.filter(Property.location.ilike(f"%{search_query}%")).all()
    else:
        # If no search query, show all properties
        properties = Property.query.all()

    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('index.html', properties=properties, search_query=search_query)

# Email Configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "homeheaven24x7@gmail.com"  # Replace with your Gmail address
SMTP_PASSWORD = "iajj yjyk xflu cumr"  # Replace with your Gmail app-specific password

# Global variable to store OTP
otp_store = {}

# Route to Display Rented Properties
@app.route('/rented')
def rented():
    rentals = Rental.query.all()
    return render_template('rented.html', rentals=rentals)


@app.route('/delete_rental/<int:rental_id>', methods=['POST'])
def delete_rental(rental_id):
    rental = Rental.query.get(rental_id)
    if rental:
        # Send email notifying the user about the deletion
        try:
            # Message for the user
            message = f"Subject: Rental Request Update\n\nDear {rental.name},\n\nWe are sorry to inform you that we currently do not have the property you requested available.\n\nBest regards,\nRental Team"

            # Send the email
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(SMTP_USERNAME, rental.email, message)
                
            flash("Rental request has been deleted, and the user has been notified.", "success")
        except Exception as e:
            flash(f"Error sending email: {e}", "danger")
        
        # Delete the rental from the database
        db.session.delete(rental)
        db.session.commit()

    return redirect(url_for('rented'))

@app.route('/approve_rental/<int:rental_id>', methods=['POST'])
def approve_rental(rental_id):
    rental = Rental.query.get(rental_id)
    if rental:
        # Update rental status to "approved"
        rental.status = "Approved"
        db.session.commit()

        # Send email to the user who rented the property
        try:
            msg = MIMEMultipart()
            msg['From'] = SMTP_USERNAME
            msg['To'] = rental.email
            msg['Subject'] = "Your Property Rental is Approved!"

            # Create the email body
            body = f"""
            Dear {rental.name},

            We are pleased to inform you that your rental request for the property you selected has been approved.
            Your requested property is now available for you!

            Thank you for choosing our services.

            Best regards,
            The Rental Team
            """
            msg.attach(MIMEText(body, 'plain'))

            # Send the email
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(SMTP_USERNAME, rental.email, msg.as_string())

            flash("Rental approved and email sent to the user.", "success")
        except Exception as e:
            flash(f"Error sending email: {e}", "danger")
    else:
        flash("Rental not found.", "error")

    return redirect(url_for('rented'))

@app.route('/rent_property', methods=['GET', 'POST'])
def rent_property():
    if request.method == 'POST':
        # Retrieve form details
        name = request.form['name']
        email = request.form['email']
        duration = request.form['duration']
        property_type = request.form['property_type']

        # Generate OTP
        otp = str(random.randint(100000, 999999))
        otp_store[email] = otp  # Save OTP against the email for verification

        # Send OTP via email
        try:
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)

                email_message = (
                    f"Subject: Rental Request Verification\n\n"
                    f"Dear {name},\n\n"
                    f"Thank you for choosing our rental services. To proceed with your request, please use the "
                    f"following One-Time Password (OTP) for verification:\n\n"
                    f"OTP: {otp}\n\n"
                    f"This OTP is valid for a limited time and should not be shared with anyone. "
                    f"If you did not initiate this request, please ignore this email or contact our support team immediately.\n\n"
                    f"Best regards,\n"
                    f"Rental Support Team"
                )

                server.sendmail(SMTP_USERNAME, email, email_message)
                flash("OTP has been sent to your email address.", "success")
        except Exception as e:
            flash(f"Error sending OTP: {e}", "danger")
            return redirect(url_for('rent_property'))

        # Redirect to OTP verification page
        session['rent_data'] = {'name': name, 'email': email, 'duration': duration, 'property_type': property_type}
        print(session['rent_data'])
        return redirect(url_for('verify_otp'))

    return render_template('rent_property.html')

# In your verify_otp route after successfully verifying OTP
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        # Retrieve email and entered OTP from session and form
        email = session.get('rent_data', {}).get('email')
        entered_otp = request.form['otp']
        
        if email and otp_store.get(email) == entered_otp:
            # OTP matches, proceed with saving rental data
            try:
                # Extract and remove rental data from session
                rent_data = session.pop('rent_data', {})
                new_rental = Rental(
                    name=rent_data['name'],
                    email=rent_data['email'],
                    duration=rent_data['duration'],
                    property_type=rent_data['property_type'],
                )
                db.session.add(new_rental)
                db.session.commit()

                # Send a thank-you email to the user
                try:
                    msg = MIMEMultipart()
                    msg['From'] = SMTP_USERNAME
                    msg['To'] = email
                    msg['Subject'] = "Thank You for Renting with Us!"

                    # Email body
                    body = f"""
                    Dear {rent_data['name']},

                    Thank you for using our website to rent a property. We will notify you in the next few days once the property you requested becomes available.

                    We appreciate your interest in our services.

                    Best regards,
                    The Rental Team
                    """
                    msg.attach(MIMEText(body, 'plain'))

                    # Send the email
                    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                        server.starttls()
                        server.login(SMTP_USERNAME, SMTP_PASSWORD)
                        server.sendmail(SMTP_USERNAME, email, msg.as_string())
                except Exception as email_error:
                    flash(f"Error sending thank you email: {email_error}", "danger")

                # Redirect to property details after successful rental submission
                property_id = rent_data.get('property_id')  # Ensure property_id is part of the rent_data
                if property_id:
                    flash("Property rental request submitted successfully!", "success")
                    return redirect(url_for('property_detail', property_id=property_id))
                else:
                    # Removed the "Property ID not found" flash message
                    return redirect(url_for('properties'))  # Redirect to properties listing if no property_id

            except Exception as db_error:
                # Rollback on database error
                db.session.rollback()
                flash(f"An error occurred while submitting your request: {db_error}", "danger")
                return render_template('rent_property.html')

        else:
            # OTP does not match
            flash("OTP does not match. Please try again.", "danger")

    # Render the OTP verification page if GET or on error
    return render_template('verify_otp.html')

# Set the directory where you want to save uploaded images
UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Configure the upload folder
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


@app.route('/add_property', methods=['GET', 'POST'])
def add_property():
    if request.method == 'POST':
        # Get data from the form
        name = request.form['name']
        location = request.form['location']
        price = request.form['price']
        description = request.form['description']
        images = request.files.getlist('images')  # Get multiple uploaded images

        # Create the new property
        new_property = Property(
            name=name,
            location=location,
            price=price,
            description=description
        )
        db.session.add(new_property)
        db.session.commit()  # Commit first to get property ID

        # Process and save each image
        for image in images:
            if image and allowed_file(image.filename):  # Validate file
                filename = secure_filename(image.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(image_path)

                # Save image path to the Image table
                new_image = Image(property_id=new_property.id, image_path=f'uploads/{filename}')
                db.session.add(new_image)

        db.session.commit()  # Commit all images

        flash("Property and images added successfully!", "success")
        return redirect(url_for('add_property'))

    return render_template('add_property.html')

@app.route('/edit_property', methods=['GET'])
def edit_property():
    search_name = request.args.get('search_name', '').strip()
    search_location = request.args.get('search_location', '').strip()

    # Start with all properties
    query = Property.query

    if search_name:
        query = query.filter(Property.name.ilike(f"%{search_name}%"))
    if search_location:
        query = query.filter(Property.location.ilike(f"%{search_location}%"))

    properties = query.all()  # Execute the query

    return render_template('edit_property.html', properties=properties)

@app.route('/update_property/<int:property_id>', methods=['POST'])
def update_property(property_id):
    """Update property details and upload images."""
    property_to_update = Property.query.get(property_id)

    if not property_to_update:
        abort(404, description="Property not found")

    # Update property fields from form data
    property_to_update.name = request.form.get('name', property_to_update.name)
    property_to_update.location = request.form.get('location', property_to_update.location)
    property_to_update.price = request.form.get('price', property_to_update.price)
    property_to_update.description = request.form.get('description', property_to_update.description)

    # Handle new image uploads
    if 'image_file' in request.files:
        image_files = request.files.getlist('image_file')
        for image in image_files:
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(file_path)  # Save file to static/uploads/

                # Add image record to the database
                new_image = Image(image_path=f'uploads/{filename}', property_id=property_id)
                db.session.add(new_image)

    # Commit changes to the database
    db.session.commit()
    flash('Property updated successfully!', 'success')

    return redirect(url_for('edit_property'))


@app.route('/delete_property/<int:property_id>', methods=['POST'])
def delete_property(property_id):
    # Find the property to delete
    property_to_delete = Property.query.get(property_id)

    if not property_to_delete:
        return "Property not found.", 404

    try:
        # Delete associated images from the filesystem and database
        for image in property_to_delete.images:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(image.image_path))
            
            # Attempt to delete the file from the filesystem
            if os.path.exists(image_path):
                os.remove(image_path)
            
            # Delete the image record from the database
            db.session.delete(image)

        # Delete the property from the database
        db.session.delete(property_to_delete)
        db.session.commit()  # Commit the changes

        return redirect(url_for('edit_property'))
    except Exception as e:
        db.session.rollback()  # Rollback the transaction in case of an error
        print(f"Error during property deletion: {e}")
        return "An error occurred while deleting the property.", 500

    
@app.route('/delete_image/<int:property_id>/<int:image_id>', methods=['POST'])
def delete_image(property_id, image_id):
    image = Image.query.get(image_id)
    if image:
        # Remove image from the file system
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image.image_path))
        except FileNotFoundError:
            pass
        
        # Remove image from the database
        db.session.delete(image)
        db.session.commit()
    
    return redirect(url_for('edit_property', property_id=property_id))

@app.route('/upload', methods=['POST'])
def upload_image():
    if 'image_file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['image_file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        # Save the image path to the database (e.g., property.images)
        return redirect(url_for('edit_property'))


@app.route('/properties', methods=['GET'])
def properties():
    search_query = request.args.get('search')
    selected_location = request.args.get('location')

    # Query properties by search query and selected location
    query = Property.query
    if search_query:
        query = query.filter(Property.location.ilike(f'%{search_query}%'))
    if selected_location:
        query = query.filter_by(location=selected_location)

    # Get distinct locations for the filter dropdown
    locations = db.session.query(Property.location).distinct().all()

    properties = query.all()

    return render_template('properties.html', 
                           properties=properties,
                           locations=[loc[0] for loc in locations],
                           selected_location=selected_location,
                           search_query=search_query)


@app.route('/view_property')
def view_property():
    # Fetch all properties from the database
    properties = Property.query.all()

    # Loop through the properties and fetch the images related to each property
    for property in properties:
        property.images = Image.query.filter_by(property_id=property.id).all()

    # Pass the properties along with their associated images to the template
    return render_template('view_property.html', properties=properties)


@app.route('/property_detail/<int:property_id>')
def property_detail(property_id):
    # Fetch the specific property from the database
    property = Property.query.get_or_404(property_id)
    
    return render_template('property_detail.html', property=property)

# Route for Contact Page
@app.route('/contact')
def contact():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('contact.html')

# Route for Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/admin/logout', methods=['GET'])
def admin_logout():
    # Clear admin-specific session keys
    session.pop('admin_id', None)
    session.pop('admin_role', None)

    # Redirect to the admin login page
    return redirect(url_for('admin_login'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
