import os
from flask import Flask, flash, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_, func
import pymysql
import threading
from datetime import datetime, date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import re
from werkzeug.utils import secure_filename
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from functools import wraps
from flask_cors import CORS
import base64
import pytz
import random
import string
import time







# Required for PyMySQL to work with SQLAlchemy
pymysql.install_as_MySQLdb()


otp_store = {} 

app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret')

# Admin credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'

VERIFICATION_CODE = "SECRET2025"  # hardcoded code

@app.route("/verify_code", methods=["GET", "POST"])
def verify_code():
    if request.method == "POST":
        code = request.form["code"]
        if code == VERIFICATION_CODE:
            session["verified"] = True
            return redirect(url_for("create_admin"))
        else:
            flash("Invalid verification code!")
    return render_template("verify_code.html")

@app.route("/create_admin", methods=["GET", "POST"])
def create_admin():
    if not session.get("verified"):
        return redirect(url_for("verify_code"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        position = request.form.get("position", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Check password match
        if not password or password != confirm_password:
            return render_template("create_admin.html", error="Passwords do not match!")

        # Check if username already exists
        existing_user = Admin.query.filter_by(username=username).first()
        if existing_user:
            return render_template("create_admin.html", error="Username already taken!")

        # Create new admin
        new_admin = Admin(full_name=full_name, position=position, username=username)
        new_admin.set_password(password)  # hash password

        db.session.add(new_admin)
        db.session.commit()

        # Log in the admin immediately
        session['admin_id'] = new_admin.id
        session['admin'] = True
        session.pop("verified", None)  # reset verification

        # Redirect to dashboard (or assets page)
        return redirect(url_for("dashboard"))

    # GET request just renders the form
    return render_template("create_admin.html")




# SQLAlchemy + PyMySQL connection
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'mysql+pymysql://root:@localhost:3306/barma'
)

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True
}

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)




TEXTBEE_API_KEY = os.environ.get('TEXTBEE_API_KEY')
TEXTBEE_DEVICE_ID = os.environ.get('TEXTBEE_DEVICE_ID')
TEXTBEE_API_URL = f"https://api.textbee.dev/api/v1/gateway/devices/{TEXTBEE_DEVICE_ID}/send-sms"

def send_sms(phone_number, message):
    """Send SMS using TextBee API, auto-convert local PH numbers."""
    # Convert 0-prefixed numbers to +63 format
    if phone_number.startswith("0") and len(phone_number) == 11:
        phone_number = "+63" + phone_number[1:]

    headers = {
        "Content-Type": "application/json",
        "x-api-key": TEXTBEE_API_KEY
    }

    payload = {
        "recipients": [phone_number],
        "message": message
    }

    try:
        response = requests.post(TEXTBEE_API_URL, headers=headers, json=payload)
        if response.status_code in [200, 201]:
            print(f"[SMS SENT] to {phone_number}: {message}")
        else:
            print(f"[SMS FAILED] {response.status_code} - {response.text}")

    except Exception as e:
        print(f"[SMS ERROR] {e}")

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin_id = session.get('admin_id')
        if not admin_id or not Admin.query.get(admin_id):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function




def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class Admin(db.Model):
    __tablename__ = "admins"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Resident(db.Model):
    __tablename__ = 'residents'
    
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    purok = db.Column(db.String(50), nullable=False)  # ✅ Added
    phone_number = db.Column(db.String(20), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    id_picture_path = db.Column(db.String(255), nullable=True)
    selfie_picture_path = db.Column(db.String(255), nullable=True)  # ✅ Added
    is_verified = db.Column(db.Boolean, default=False)
    is_restricted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)





class Asset(db.Model):
    __tablename__ = 'assets'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    classification = db.Column(db.String(20), nullable=False, default='Borrowing')
    available_quantity = db.Column(db.Integer, nullable=True, default=0)
    active_borrowed = db.Column(db.Integer, nullable=True, default=0)


    # ✅ Relationships to Borrowing and Reservation
    borrowings = db.relationship('Borrowing', backref='asset', lazy=True)
    reservations = db.relationship('Reservation', backref='asset', lazy=True)



class Reservation(db.Model):
    __tablename__ = 'reservations'
    id = db.Column(db.Integer, primary_key=True)
    resident_name = db.Column(db.String(255), nullable=False)
    item = db.Column(db.String(255), nullable=False)
    purpose = db.Column(db.String(255), nullable=True)
    reservation_start = db.Column(db.DateTime, nullable=False)
    reservation_end = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.Enum('Pending', 'Approved', 'Rejected'), default='Pending')
    rejection_reason = db.Column(db.String(255), nullable=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    request_date = db.Column(db.Date, nullable=True)



class Borrowing(db.Model):
    __tablename__ = 'borrowings'
    id = db.Column(db.Integer, primary_key=True)
    resident_name = db.Column(db.String(255), nullable=False)
    item = db.Column(db.String(255), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    purpose = db.Column(db.String(255), nullable=True)
    request_date = db.Column(db.Date, nullable=False)
    return_date = db.Column(db.Date, nullable=False)
    due_date = db.Column(db.Date)
    status = db.Column(db.Enum('Pending', 'Approved', 'Rejected', 'Returned', 'Return Requested'), default='Pending')
    rejection_reason = db.Column(db.String(255), nullable=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    reminder_sent = db.Column(db.Boolean, default=False)
    borrow_date = db.Column(db.Date, nullable=True)
    

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50))  # 'Reservation' or 'Borrowing'
    resident_name = db.Column(db.String(100))
    item = db.Column(db.String(100))
    quantity = db.Column(db.Integer)  # ➕ Add this
    purpose = db.Column(db.String(200))  # ➕ Add this
    action_type = db.Column(db.String(50))  # 'Approved', 'Rejected', 'Returned'
    action_date = db.Column(db.DateTime, default=datetime.utcnow)
    borrow_date = db.Column(db.DateTime, nullable=True)  # ✅ changed to DateTime
    return_date = db.Column(db.DateTime, nullable=True)  # ✅ changed to DateTime
    reason = db.Column(db.Text, nullable=True)


def restrict_overdue_accounts():
    with app.app_context():  # ensure context if called outside routes
        overdue_borrowings = Borrowing.query.filter(
            and_(
                Borrowing.return_date < date.today(),
                Borrowing.status.in_(['Approved', 'Return Requested'])
            )
        ).all()

        restricted_names = set()

        for borrow in overdue_borrowings:
            resident = Resident.query.filter_by(full_name=borrow.resident_name).first()
            if resident and not resident.is_restricted:
                resident.is_restricted = True
                restricted_names.add(resident.full_name)

                # ✅ Log automatic restriction in History
                new_history = History(
                    type='Account Restriction',
                    resident_name=resident.full_name,
                    action_type='Automatically Restricted',
                    reason=f'Overdue borrowed item: {borrow.item} (Return date: {borrow.return_date})'
                )
                db.session.add(new_history)

        if restricted_names:
            db.session.commit()
            print(f"[AUTO RESTRICT] Restricted residents: {restricted_names}")
        else:
            print("[AUTO RESTRICT] No accounts to restrict today.")



@app.route('/')
def home():
    return redirect(url_for('login'))

PH_TZ = pytz.timezone('Asia/Manila')

def send_return_reminders():
    today_ph = datetime.now(PH_TZ).date()
    tomorrow_ph = today_ph + timedelta(days=1)

    # Only get borrowings that are approved, due tomorrow, and haven't been reminded yet
    borrowings = Borrowing.query.filter(
        func.date(Borrowing.return_date) == tomorrow_ph,
        Borrowing.status == 'Approved',
        Borrowing.reminder_sent == False  # ensures we don't send duplicate reminders
    ).all()

    print(f"Checking reminders for: {tomorrow_ph}, found: {len(borrowings)}")

    for b in borrowings:
        # Match resident by name
        resident = Resident.query.filter_by(full_name=b.resident_name).first()
        if resident and resident.phone_number:
            message = (
                f"Hi {resident.full_name}, this is a reminder to please return "
                f"the {b.item} by {b.return_date}. Thank you!"
            )

            send_sms(resident.phone_number, message)
            print(f"✅ Reminder sent to {resident.full_name}")

            # Mark as reminded
            b.reminder_sent = True
            db.session.commit()
        else:
            print(f"⚠️ Resident not found or missing phone number for {b.resident_name}")




# Scheduler: runs every 2 hours (PH time)
scheduler = BackgroundScheduler(timezone=PH_TZ)
scheduler.add_job(send_return_reminders, 'interval', hours=2)
scheduler.start()

with app.app_context():
    send_return_reminders()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Look for user in database
        user = Admin.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['admin_id'] = user.id   # <-- add this
            session['admin'] = True          # optional, keep for other checks
            restrict_overdue_accounts()      # your existing function
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')





@app.route('/dashboard')
def dashboard():
    if not session.get('admin'):
        return redirect(url_for('login'))

    assets = Asset.query.all()
    reservations = Reservation.query.order_by(Reservation.reservation_start.desc()).all()
    borrowings = Borrowing.query.order_by(Borrowing.request_date.desc()).all()

    print("[DEBUG] Borrowings sent to dashboard:")
    for b in borrowings:
        print(f"{b.id} - {b.item} - {b.status}")
    residents = Resident.query.all()
    
    return render_template(
        'dashboard.html',
        assets=assets,
        reservations=reservations,
        borrowings=borrowings,
        residents=residents
    )


@app.route('/add_asset', methods=['POST'])
def add_asset():
    if not session.get('admin'):
        return redirect(url_for('login'))

    name = request.form['name'].strip()
    quantity = int(request.form['quantity'])
    classification = request.form['classification']

    # 🔍 Check if an asset with the same name already exists
    existing_asset = Asset.query.filter_by(name=name).first()
    if existing_asset:
        flash("Asset with this name already exists!", "danger")
        return redirect(url_for('assets_page'))

    # ✅ If no duplicate, proceed to add
    asset = Asset(name=name, quantity=quantity, classification=classification)
    db.session.add(asset)
    db.session.commit()

    flash("Asset added successfully!", "success")
    return redirect(url_for('assets_page'))


@app.route('/edit_asset/<int:id>', methods=['GET', 'POST'])
def edit_asset(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    asset = Asset.query.get_or_404(id)
    if request.method == 'POST':
        asset.name = request.form['name']
        asset.quantity = int(request.form['quantity'])
        db.session.commit()
        return redirect(url_for('assets_page'))

    return render_template('edit_asset.html', asset=asset)

@app.route('/delete_asset/<int:id>')
def delete_asset(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    asset = Asset.query.get_or_404(id)
    db.session.delete(asset)
    db.session.commit()
    return redirect(url_for('assets_page'))

@app.route('/add_reservation', methods=['POST'])
def add_reservation():
    if not session.get('admin'):
        return redirect(url_for('login'))

    name = request.form['resident_name']
    item = request.form['item']
    request_date = datetime.strptime(request.form['request_date'], '%Y-%m-%d')

    reservation = Reservation(
        resident_name=name,
        item=item,
        request_date=request_date
    )
    db.session.add(reservation)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('admin', None)
    return redirect(url_for('login'))

@app.route('/approve_reservation/<int:id>')
def approve_reservation(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    reservation = Reservation.query.get_or_404(id)
    reservation.status = 'Approved'

    # ✅ Add to history with reservation dates
    history = History(
        type='Reservation',
        resident_name=reservation.resident_name,
        item=reservation.item,
        purpose=reservation.purpose,
        action_type='Approved',
        borrow_date=reservation.reservation_start,  # ✅ store Reserved Date From
        return_date=reservation.reservation_end      # ✅ store Reserved Date To
    )

    db.session.add(history)
    db.session.commit()

    # ✅ Send SMS
    resident = Resident.query.filter_by(full_name=reservation.resident_name).first()
    if resident:
        send_sms(
            resident.phone_number,
            f"Hi {resident.full_name}, your reservation for {reservation.item} "
            f"from {reservation.reservation_start.strftime('%Y-%m-%d')} "
            f"to {reservation.reservation_end.strftime('%Y-%m-%d')} has been APPROVED."
        )

    return redirect(url_for('dashboard'))



@app.route('/reject_reservation/<int:id>', methods=['POST'])
def reject_reservation(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    reservation = Reservation.query.get_or_404(id)
    reason = request.form.get('reason')
    reservation.status = 'Rejected'
    reservation.rejection_reason = reason

    # ✅ Add to History with reason field
    history = History(
        type='Reservation',
        resident_name=reservation.resident_name,
        item=reservation.item,
        purpose=reservation.purpose,
        action_type='Rejected',
        borrow_date=reservation.reservation_start,
        return_date=reservation.reservation_end,
        reason=reason  # ✅ store rejection reason here
    )

    db.session.add(history)
    db.session.commit()

    resident = Resident.query.filter_by(full_name=reservation.resident_name).first()
    if resident:
        send_sms(
            resident.phone_number,
            f"Hi {resident.full_name}, your reservation for {reservation.item} has been REJECTED. Reason: {reason}"
        )

    return redirect(url_for('dashboard'))



@app.route('/approve_borrowing/<int:id>', methods=['GET', 'POST'])
def approve_borrowing(id):
    borrowing = Borrowing.query.get_or_404(id)
    asset = Asset.query.get_or_404(borrowing.asset_id)

    if borrowing.status.lower() == "approved":
        flash('Borrowing request already approved.', 'info')
        return redirect(url_for('dashboard'))

    # Calculate total approved quantity for this asset
    approved_borrowed_qty = db.session.query(db.func.sum(Borrowing.quantity)).filter(
        Borrowing.asset_id == asset.id,
        Borrowing.status == 'Approved'
    ).scalar() or 0

    available_qty = asset.quantity - approved_borrowed_qty

    if borrowing.quantity > available_qty:
        flash(f"Cannot approve request: requested quantity ({borrowing.quantity}) exceeds available assets ({available_qty}).", "danger")
        return redirect(url_for('dashboard'))

    # ✅ Approve borrowing
    borrowing.status = "Approved"

    # ✅ Update asset availability and active borrowed count
    asset.available_quantity = asset.quantity - db.session.query(
        db.func.sum(Borrowing.quantity)
    ).filter(
        Borrowing.asset_id == asset.id,
        Borrowing.status == 'Approved'
    ).scalar() or 0

    asset.active_borrowed = db.session.query(
        db.func.sum(Borrowing.quantity)
    ).filter(
        Borrowing.asset_id == asset.id,
        Borrowing.status == 'Approved'
    ).scalar() or 0

    # ✅ Add to history
    history = History(
        type='Borrowing',
        resident_name=borrowing.resident_name,
        item=borrowing.item,
        quantity=borrowing.quantity,
        purpose=borrowing.purpose,
        action_type='Approved',
        borrow_date=borrowing.borrow_date,  # include borrow_date if available
        return_date=borrowing.return_date
    )

    db.session.add(history)
    db.session.commit()
    flash('Borrowing approved.', 'success')

    # ✅ Send SMS notification
    resident = Resident.query.filter_by(full_name=borrowing.resident_name).first()
    if resident:
        send_sms(
            resident.phone_number,
            f"Hi {resident.full_name}, your borrowing request for {borrowing.item} "
            f"({borrowing.quantity}) has been APPROVED. You may now claim the item(s) at the Barangay Hall. "
            f"Kindly ensure that the asset is returned on or before {borrowing.return_date} to avoid inconvenience."
        )

    return redirect(url_for('dashboard'))



@app.route('/reject_borrowing/<int:id>', methods=['POST'])
def reject_borrowing(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    borrowing = Borrowing.query.get_or_404(id)
    reason = request.form.get('reason')
    borrowing.status = 'Rejected'
    borrowing.rejection_reason = reason

    # ✅ Add to History with reason field
    history = History(
        type='Borrowing',
        resident_name=borrowing.resident_name,
        item=borrowing.item,
        quantity=borrowing.quantity,
        purpose=borrowing.purpose,
        action_type='Rejected',
        borrow_date=borrowing.borrow_date,
        return_date=borrowing.return_date,
        reason=reason  # ✅ store rejection reason
    )

    db.session.add(history)
    db.session.commit()

    resident = Resident.query.filter_by(full_name=borrowing.resident_name).first()
    if resident:
        send_sms(
            resident.phone_number,
            f"Hi {resident.full_name}, your borrowing request for {borrowing.item} "
            f"({borrowing.quantity}) has been REJECTED. Reason: {reason}"
        )

    return redirect(url_for('dashboard'))


@app.route('/generate_residents_report')
def generate_residents_report():
    residents = Resident.query.all()
    output = "Full Name, Username, Phone Number, Gender, Purok\n"
    for r in residents:
        output += f"{r.full_name},{r.username},{r.phone_number},{r.gender},{r.purok}\n"

    response = make_response(output)
    response.headers["Content-Disposition"] = "attachment; filename=residents_report.csv"
    response.headers["Content-Type"] = "text/csv"
    return response


@app.route('/history')
def history_page():
    if not session.get('admin'):
        return redirect(url_for('login'))

    # Separate query for restriction logs
    restriction_logs = History.query.filter_by(type='Account Restriction').order_by(History.action_date.desc()).all()
    # Other history logs (reservations and borrowings)
    other_logs = History.query.filter(History.type != 'Account Restriction').order_by(History.action_date.desc()).all()

    admin = Admin.query.get(session['admin_id'])
    return render_template(
        'history.html',
        restriction_logs=restriction_logs,
        other_logs=other_logs,
        username=admin.full_name
    )



@app.route('/return_borrowing/<int:borrowing_id>', methods=['POST'])
def return_borrowing(borrowing_id): 
    borrowing = Borrowing.query.get_or_404(borrowing_id)
    
    if borrowing.status.lower() == "approved": 
        borrowing.status = "Returned"
        db.session.commit() 
        flash('Item marked as returned.', 'success')
    else: 
        flash('Only approved borrowings can be returned.', 'info') 
    
    
    return redirect(url_for('manage_borrowing'))



@app.route('/assets')
@admin_required
def assets_page():
    admin = Admin.query.get(session['admin_id'])
    assets = Asset.query.all()  # ✅ show all classifications
    borrowings = Borrowing.query.all()  # needed for calculations

    return render_template('assets.html', assets=assets, borrowings=borrowings, admin_name=admin.full_name)



@app.route('/help')
def help_page():
    return render_template('help.html', admin_name=session.get('admin_name', 'Admin'))



@app.route('/api/register', methods=['POST'])
def register_resident():
    data = request.get_json()  # JSON payload from frontend

    # Required fields
    required_fields = ['full_name', 'gender', 'purok', 'phone_number', 'username', 'password', 'id_picture', 'selfie_picture']
    if not all(field in data and data[field] for field in required_fields):
        return jsonify({'error': 'All fields including ID and selfie picture are required'}), 400

    # Extract data
    full_name = data['full_name']
    gender = data['gender']
    purok = data['purok']
    phone_number = data['phone_number']
    username = data['username']
    raw_password = data['password']

    # Decode Base64 images
    import base64
    try:
        id_bytes = base64.b64decode(data['id_picture'])
        selfie_bytes = base64.b64decode(data['selfie_picture'])
    except Exception as e:
        return jsonify({'error': 'Invalid Base64 image data'}), 400

    # Define folders inside static/
    ID_FOLDER = os.path.join('static', 'id_pictures')
    SELFIE_FOLDER = os.path.join('static', 'selfie_pictures')
    os.makedirs(ID_FOLDER, exist_ok=True)
    os.makedirs(SELFIE_FOLDER, exist_ok=True)

    # Generate filenames and relative paths
    id_filename = f"{username}_id.jpg"
    selfie_filename = f"{username}_selfie.jpg"
    id_picture_path = f"id_pictures/{id_filename}"        # relative path for DB
    selfie_picture_path = f"selfie_pictures/{selfie_filename}"  # relative path for DB

    # Save images to disk
    try:
        with open(os.path.join(ID_FOLDER, id_filename), 'wb') as f:
            f.write(id_bytes)
        with open(os.path.join(SELFIE_FOLDER, selfie_filename), 'wb') as f:
            f.write(selfie_bytes)
    except Exception as e:
        print(f"File save error: {e}")
        return jsonify({'error': 'Failed to save uploaded images'}), 500

    # Hash password
    from werkzeug.security import generate_password_hash
    hashed_password = generate_password_hash(raw_password, method='pbkdf2:sha256', salt_length=8)

    # Check if username already exists
    if Resident.query.filter_by(full_name=full_name).first():
        return jsonify({'error': 'Full name already registered'}), 400

    if Resident.query.filter_by(phone_number=phone_number).first():
        return jsonify({'error': 'Phone number already registered'}), 400
        
    if Resident.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already taken'}), 400



    # Save resident to DB
    resident = Resident(
        full_name=full_name,
        gender=gender,
        phone_number=phone_number,
        username=username,
        password=hashed_password,
        id_picture_path=id_picture_path,
        selfie_picture_path=selfie_picture_path,
        purok=purok,
        is_verified=False
    )
    db.session.add(resident)
    db.session.commit()

    return jsonify({'message': 'Registration successful. Your account is pending admin verification.'}), 201



@app.route('/api/login', methods=['POST'])
def login_resident():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    print("Attempting login:", username, password)

    resident = Resident.query.filter_by(username=username).first()

    if resident:
        print("Resident found:", resident.username)
        print("DB hashed password:", resident.password)
        print("Entered password:", password)
        print("Password check:", check_password_hash(resident.password, password))

        if resident.is_restricted:
            print("❌ Account is restricted")
            return jsonify({'error': 'Your account is restricted'}), 403

        if not resident.is_verified:
            print("❌ Account not yet verified")
            return jsonify({'error': 'Your account is not yet verified by the admin.'}), 403

        if check_password_hash(resident.password, password):
            return jsonify({
                'message': 'Login successful',
                'resident_id': resident.id,
                'name': resident.full_name
            })

        else:
            print("❌ Incorrect password")
    else:
        print("❌ Username not found")

    return jsonify({'error': 'Invalid credentials'}), 401



@app.route('/api/assets', methods=['GET'])
def get_assets():
    all_assets = Asset.query.all()
    asset_data = []

    for asset in all_assets:
        quantity = asset.quantity or 0  # default to 0 if None
        approved_borrowed = 0
        approved_reserved = 0

        if asset.classification == 'Borrowing':
            approved_borrowed = db.session.query(db.func.sum(Borrowing.quantity)).filter(
                Borrowing.asset_id == asset.id,
                Borrowing.status == 'Approved'
            ).scalar() or 0

        elif asset.classification == 'Reservation':
            approved_reserved = db.session.query(db.func.count(Reservation.id)).filter(
                Reservation.asset_id == asset.id,
                Reservation.status == 'Approved'
            ).scalar() or 0

        available_quantity = quantity - approved_borrowed - approved_reserved

        asset_data.append({
            'id': asset.id,
            'name': asset.name,
            'available_quantity': max(available_quantity, 0),  # avoid negative
            'classification': asset.classification
        })

    return jsonify(asset_data)





@app.route('/api/borrowings/all', methods=['GET'])
def get_all_borrowings():
    borrowings = Borrowing.query.all()
    result = []
    for b in borrowings:
        result.append({
            'item': b.item,
            'quantity': b.quantity,
            'resident_name': b.resident_name,
            'status': b.status,
            'request_date': b.request_date.strftime('%Y-%m-%d'),
            'return_date': b.return_date.strftime('%Y-%m-%d')
        })
    return jsonify(result)

@app.route('/api/reservations/all', methods=['GET'])
def get_all_reservations():
    reservations = Reservation.query.all()
    result = []
    for r in reservations:
        result.append({
            'resident_name': r.resident_name,
            'purpose': r.purpose,
            'date': r.request_date.strftime('%Y-%m-%d')
        })
    return jsonify(result)


@app.route('/api/borrow', methods=['POST'])
def borrow_asset():
    data = request.get_json()
    try:
        new_borrow = Borrowing(
            asset_id=data['asset_id'],
            resident_name=data['resident_name'],
            item=data['item'],  # ✅ FIX: Include item here
            quantity=data['quantity'],
            purpose=data['purpose'],
            status='Pending',
            request_date=datetime.strptime(data['request_date'], '%Y-%m-%d'),
            return_date=datetime.strptime(data['return_date'], '%Y-%m-%d'),
            borrow_date=datetime.strptime(data['borrow_date'], '%Y-%m-%d')

        )
        db.session.add(new_borrow)
        db.session.commit()
        return jsonify({'message': 'Borrowing request submitted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400



@app.route('/api/reserve', methods=['POST'])
def reserve_asset():
    data = request.get_json()
    try:
        asset_id = data['asset_id']
        reservation_start = datetime.strptime(data['reservation_start'], '%Y-%m-%d %H:%M')
        reservation_end = datetime.strptime(data['reservation_end'], '%Y-%m-%d %H:%M')

        # ✅ STRICT BLOCKING OVERLAP CHECK
        overlap = Reservation.query.filter(
            Reservation.asset_id == asset_id,
            Reservation.status.in_(["Pending", "Approved"]),
            Reservation.reservation_start < reservation_end,   # existing starts before new ends
            Reservation.reservation_end > reservation_start    # existing ends after new starts
        ).first()

        if overlap:
            return jsonify({
                'error': f'This time slot is already booked from '
                         f'{overlap.reservation_start.strftime("%I:%M %p")} '
                         f'to {overlap.reservation_end.strftime("%I:%M %p")}'
            }), 400

        # Create reservation
        new_reservation = Reservation(
            asset_id=asset_id,
            resident_name=data['resident_name'],
            item=data['item'],
            purpose=data['purpose'],
            status='Pending',
            reservation_start=reservation_start,
            reservation_end=reservation_end,
            request_date=datetime.utcnow().date()
        )
        db.session.add(new_reservation)
        db.session.commit()
        return jsonify({'message': 'Reservation request submitted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400




@app.route('/api/reserved-dates/<int:asset_id>')
def get_reserved_dates(asset_id):
    reservations = Reservation.query.filter_by(asset_id=asset_id).filter(
        Reservation.status.in_(['Pending', 'Approved'])
    ).all()

    fully_booked_dates = set()
    for r in reservations:
        res_start = r.reservation_start.time()
        res_end = r.reservation_end.time()
        # compare against datetime.time objects
        if res_start <= time(18, 0) and res_end >= time(7, 0):
            fully_booked_dates.add(r.reservation_start.date().isoformat())

    return jsonify(list(fully_booked_dates))

@app.route('/api/debug_assets')
def debug_assets():
    assets = Asset.query.all()
    return jsonify([a.name for a in assets])

@app.route('/manage_accounts')
def manage_accounts():
    if not session.get('admin'):
        return redirect(url_for('login'))

    # Separate residents
    residents = Resident.query.filter_by(is_verified=True).all()
    pending_residents = Resident.query.filter_by(is_verified=False).all()

    # Get the admin name from session
    admin = Admin.query.get(session['admin_id'])

    return render_template(
        'manage_accounts.html',
        residents=residents,
        pending_residents=pending_residents,
        admin_name=admin.full_name  # <-- pass admin name here
    )

@app.route('/verify_resident/<int:id>', methods=['POST'])
def verify_resident(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    resident = Resident.query.get_or_404(id)
    resident.is_verified = True
    db.session.commit()

    # Send SMS notification
    message = f"Hello {resident.full_name}, your account has been verified. You can now log in to BARMA."
    send_sms(resident.phone_number, message)

    flash('Resident verified and SMS sent.', 'success')
    return redirect(url_for('manage_accounts'))


@app.route('/reject_resident/<int:id>', methods=['POST'])
def reject_resident(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    resident = Resident.query.get_or_404(id)

    # Send SMS notification before deleting
    message = f"Hello {resident.full_name}, your account has been rejected. Please go the barangay office for assistance."
    send_sms(resident.phone_number, message)

    db.session.delete(resident)
    db.session.commit()

    flash('Resident rejected and SMS sent.', 'danger')
    return redirect(url_for('manage_accounts'))



@app.route('/restrict_resident/<int:id>')
def restrict_resident(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    resident = Resident.query.get_or_404(id)
    resident.is_restricted = not resident.is_restricted  # Toggle

    # ✅ Determine action type
    action = 'Restricted' if resident.is_restricted else 'Unrestricted'

    # ✅ Add to history log
    new_history = History(
        type='Account Restriction',
        resident_name=resident.full_name,
        action_type=f'Manually {action}',
        reason=f'Account was {action.lower()} by admin.'
    )

    db.session.add(new_history)
    db.session.commit()

    return redirect(url_for('manage_accounts'))


@app.route('/api/return-request', methods=['POST'])
def return_request():
    data = request.get_json()
    borrow_id = data.get('id')
    print(f"[DEBUG] Received return request for ID: {borrow_id}")

    borrowing = Borrowing.query.get(borrow_id)
    if not borrowing:
        print("[ERROR] Borrowing not found")
        return jsonify({'error': 'Borrowing not found'}), 404

    print(f"[DEBUG] Current status: {borrowing.status}")
    if borrowing.status == 'Approved':
        borrowing.status = 'Return Requested'
        try:
            db.session.commit()
            print(f"[DEBUG] Status updated to: {borrowing.status}")
            return jsonify({'message': 'Return request sent successfully'}), 200
        except Exception as e:
            print(f"[ERROR] DB commit failed: {e}")
            return jsonify({'error': 'Failed to update status'}), 500
    else:
        print(f"[DEBUG] Invalid status for return: {borrowing.status}")
        return jsonify({'error': 'Invalid status'}), 400

@app.route('/api/confirm-return/<int:borrow_id>', methods=['POST'])
def confirm_return(borrow_id):
    try:
        borrow = Borrowing.query.get(borrow_id)
        if not borrow or borrow.status != 'Return Requested':
            return jsonify({'error': 'Invalid or already returned borrowing'}), 400

        asset = Asset.query.get(borrow.asset_id)
        if asset:
            asset.quantity += borrow.quantity  # ✅ Restore quantity

        borrow.status = 'Returned'  # ✅ Update status

        db.session.commit()
        return jsonify({'message': 'Return confirmed and quantity restored'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    
@app.route('/api/borrowings/<string:resident_name>', methods=['GET'])
def get_borrowings_by_resident(resident_name):
    borrowings = Borrowing.query.filter_by(resident_name=resident_name).filter(
        Borrowing.status.in_(['Approved', 'Return Requested'])
    ).all()

    print(f"Borrowings for {resident_name}: {[b.status for b in borrowings]}")

    result = []
    for b in borrowings:
        result.append({
            'id': b.id,
            'item': b.item,
            'quantity': b.quantity,
            'request_date': b.request_date.strftime('%Y-%m-%d'),
            'return_date': b.return_date.strftime('%Y-%m-%d'),
            'status': b.status
        })
    return jsonify(result)

@app.route('/api/pending-borrowings/<string:resident_name>', methods=['GET'])
def get_pending_borrowings(resident_name):
    borrowings = Borrowing.query.filter_by(resident_name=resident_name, status='Pending').all()

    result = []
    for b in borrowings:
        result.append({
            'item': b.item,
            'quantity': b.quantity,
            'request_date': b.request_date.strftime('%Y-%m-%d'),
            'return_date': b.return_date.strftime('%Y-%m-%d'),
            'status': b.status
        })
    return jsonify(result)

@app.route('/api/pending-reservations/<string:resident_name>', methods=['GET'])
def get_pending_reservations(resident_name):
    today = datetime.now()  # include time for DateTime comparison
    reservations = Reservation.query.filter_by(
        resident_name=resident_name, 
        status='Pending'
    ).filter(
        Reservation.reservation_start >= today
    ).order_by(
        Reservation.reservation_start.asc()
    ).all()

    result = []
    for r in reservations:
        result.append({
            'id': r.id,
            'purpose': r.purpose,
            'start': r.reservation_start.strftime('%Y-%m-%d %H:%M'),
            'end': r.reservation_end.strftime('%Y-%m-%d %H:%M'),
            'status': r.status
        })
    return jsonify(result)


@app.route('/reservations')
@admin_required
def reservations_page():
    admin = Admin.query.get(session['admin_id'])
    reservable_assets = Asset.query.filter_by(classification='Reservation').all()
    return render_template('reservation.html', reservable_assets=reservable_assets, admin_name=admin.full_name)




@app.route('/api/reservation-events')
def reservation_events():
    reservations = Reservation.query.filter_by(status='Approved').all()

    events = []
    for r in reservations:
        events.append({
            "title": r.item,  # Displayed on calendar
            "start": r.reservation_start.isoformat(),
            "end": r.reservation_end.isoformat(),
            "color": "#FFC100",
            "extendedProps": {
                "resident_name": r.resident_name,
                "purpose": r.purpose,
                "remarks": getattr(r, 'remarks', '')
            }
        })

    return jsonify(events)



@app.route('/update_asset/<int:id>', methods=['POST'])
def update_asset(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    # Read form values
    name = request.form['name'].strip()
    quantity = int(request.form['quantity'])
    classification = request.form['classification']

    # Get current asset
    asset = Asset.query.get_or_404(id)

    # ✅ Check if new name already exists on another asset
    duplicate = Asset.query.filter(
        Asset.name == name,
        Asset.id != id  # exclude the same asset from the check
    ).first()

    if duplicate:
        flash('Asset name already exists. Please use a different name.', 'danger')
        return redirect(url_for('assets_page'))

    # ✅ If no duplicate, update normally
    asset.name = name
    asset.quantity = quantity
    asset.classification = classification
    db.session.commit()

    flash('Asset updated successfully!', 'success')
    return redirect(url_for('assets_page'))


@app.route('/borrowings')
@admin_required
def borrowings_page():
    admin = Admin.query.get(session['admin_id'])
    borrowing_assets = Asset.query.filter_by(classification='Borrowing').all()
    asset_data = []

    for asset in borrowing_assets:
        quantity = asset.quantity or 0
        approved_borrowed = db.session.query(db.func.sum(Borrowing.quantity)).filter(
            Borrowing.asset_id == asset.id,
            Borrowing.status == 'Approved'
        ).scalar() or 0

        available_quantity = quantity - approved_borrowed
        if available_quantity < 0:
            available_quantity = 0

        asset_data.append({
            'id': asset.id,
            'name': asset.name,
            'available_quantity': available_quantity
        })

    return render_template('borrowings.html', borrowing_assets=asset_data, admin_name=admin.full_name)




@app.route('/api/request_reset_otp', methods=['POST'])
def request_reset_otp():
    data = request.get_json()
    if not data or 'username' not in data:
        return jsonify({"error": "Username required"}), 400

    username = data['username'].strip()
    user = Resident.query.filter_by(username=username).first()

    if not user:
        return jsonify({"error": "User not found"}), 404
    if not user.phone_number:
        return jsonify({"error": "No phone number associated"}), 400

    # ✅ Generate 6-digit OTP
    otp = ''.join(random.choices(string.digits, k=6))
    otp_store[username] = {'otp': otp, 'expires': time.time() + 300}  # expires in 5 mins

    # ✅ Send OTP via TextBee
    message = f"Your BARMA password reset code is: {otp}. It will expire in 5 minutes."
    send_sms(user.phone_number, message)

    return jsonify({"message": "OTP sent successfully"}), 200


@app.route('/api/verify_reset_otp', methods=['POST'])
def verify_reset_otp():
    data = request.get_json()
    if not data or 'username' not in data or 'otp' not in data:
        return jsonify({"error": "Invalid request"}), 400

    username = data['username'].strip()
    otp = data['otp'].strip()

    if username not in otp_store:
        return jsonify({"error": "No OTP request found"}), 400

    stored = otp_store[username]
    if time.time() > stored['expires']:
        otp_store.pop(username, None)
        return jsonify({"error": "OTP expired"}), 400

    if stored['otp'] != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    # ✅ Mark verified, allow password reset
    otp_store[username]['verified'] = True
    return jsonify({"message": "OTP verified"}), 200


@app.route('/api/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    if not data or 'username' not in data or 'new_password' not in data:
        return jsonify({"error": "Invalid request"}), 400

    username = data['username'].strip()
    new_password = data['new_password'].strip()

    # ✅ Ensure OTP verified
    if username not in otp_store or not otp_store[username].get('verified'):
        return jsonify({"error": "OTP verification required"}), 403

    # ✅ Password strength validation (same as registration)
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    if not re.search(r"[A-Z]", new_password):
        return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
    if not re.search(r"[a-z]", new_password):
        return jsonify({"error": "Password must contain at least one lowercase letter"}), 400
    if not re.search(r"\d", new_password):
        return jsonify({"error": "Password must contain at least one number"}), 400
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", new_password):
        return jsonify({"error": "Password must contain at least one special character"}), 400

    # ✅ Update password securely
    user = Resident.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
    db.session.commit()

    # ✅ Clean up OTP
    otp_store.pop(username, None)

    return jsonify({"message": "Password reset successful"}), 200



@app.route('/api/user-id/<name>', methods=['GET'])
def get_user_id_by_name(name):
    user = Resident.query.filter_by(full_name=name).first()
    if user:
        return jsonify({'user_id': user.id}), 200
    else:
        return jsonify({'error': 'User not found'}), 404


@app.route('/admin/approve-return/<int:borrow_id>', methods=['POST'])
def approve_return(borrow_id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    borrowing = Borrowing.query.get_or_404(borrow_id)

    if borrowing.status == 'Return Requested':
        # ✅ Update borrowing status
        borrowing.status = 'Returned'

        # ✅ Add to History (like in reject route)
        history = History(
            type='Borrowing',
            resident_name=borrowing.resident_name,
            item=borrowing.item,
            quantity=borrowing.quantity,
            purpose=borrowing.purpose,
            action_type='Returned'  # you can customize message here too
            # action_date=datetime.utcnow()  # optional if your model has default
        )

        db.session.add(history)
        db.session.commit()  # commit both status + history

        flash('Return approved successfully.', 'success')

        # ✅ Send SMS notification
        resident = Resident.query.filter_by(full_name=borrowing.resident_name).first()
        if resident and resident.phone_number:
            send_sms(
                resident.phone_number,
                f"Hi {resident.full_name}, your return request for "
                f"{borrowing.item} ({borrowing.quantity}) has been APPROVED. Thank you!"
            )
    else:
        flash('Cannot approve return. Status must be "Return Requested".', 'warning')

    return redirect(url_for('dashboard'))


@app.route('/api/account/<string:full_name>', methods=['GET'])
def get_account(full_name):
    user = Resident.query.filter_by(full_name=full_name).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'id': user.id,
        'full_name': user.full_name,
        'username': user.username,
        'phone_number': user.phone_number,
        'gender': user.gender,
        'purok': user.purok,  # include Purok
        'is_verified': user.is_verified,
        'is_restricted': user.is_restricted,
        'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'id_picture_path': user.id_picture_path
    })


@app.route('/api/account/update', methods=['POST'])
def update_account():
    data = request.get_json()
    user = Resident.query.get(data['id'])

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Check for unique constraints
    if Resident.query.filter(Resident.username == data['username'], Resident.id != user.id).first():
        return jsonify({'error': 'Username already exists'}), 400
    if Resident.query.filter(Resident.phone_number == data['phone_number'], Resident.id != user.id).first():
        return jsonify({'error': 'Phone number already exists'}), 400

    # Update fields
    user.username = data['username']
    user.phone_number = data['phone_number']
    user.gender = data['gender']
    user.purok = data.get('purok', user.purok)  # handle Purok update

    # Update password if provided
    if 'password' in data and data['password']:
        user.password = generate_password_hash(data['password'], method='pbkdf2:sha256')

    db.session.commit()
    return jsonify({'message': 'Account updated successfully'})


@app.route('/api/history/<string:full_name>', methods=['GET'])
def get_resident_history(full_name):
    try:
        history_entries = (
            History.query
            .filter_by(resident_name=full_name)  # still filtering by resident_name in the DB
            .order_by(History.action_date.desc())
            .limit(10)
            .all()
        )

        history = [
            {
                "action": f"{entry.type} - {entry.action_type} ({entry.item})",
                "timestamp": entry.action_date.strftime('%Y-%m-%d %H:%M:%S')
            }
            for entry in history_entries
        ]

        return jsonify(history)

    except Exception as e:
        print(f"Error fetching history for {full_name}: {e}")
        return jsonify({"error": "Failed to fetch history"}), 500


def run_daily_restriction():
    while True:
        now = datetime.now()
        # Set base run time today at 1AM
        next_run = datetime.combine(now.date(), datetime.min.time()).replace(hour=1)

        # If it's already past 1AM today, schedule for tomorrow 1AM
        if now >= next_run:
            next_run = next_run + timedelta(days=1)

        wait_seconds = (next_run - now).total_seconds()
        print(f"[SCHEDULER] Restriction check will run in {int(wait_seconds)} seconds.")

        time.sleep(wait_seconds)
        restrict_overdue_accounts()  # ✅ call your function


@app.route('/api/reservations/<int:reservation_id>/status', methods=['PUT'])
def update_reservation_status(reservation_id):
    data = request.get_json()
    try:
        reservation = Reservation.query.get_or_404(reservation_id)

        if 'status' not in data:
            return jsonify({'error': 'Status is required'}), 400

        old_status = reservation.status
        reservation.status = data['status']
        db.session.commit()

        # Send SMS to the resident after status update
        phone_number = reservation.user.phone_number  # Adjust if phone is in another table/field
        if reservation.status == "Approved":
            message = f"Your reservation for {reservation.purpose} on {reservation.reservation_start.strftime('%Y-%m-%d %H:%M')} has been APPROVED."
        elif reservation.status == "Rejected":
            message = f"Your reservation for {reservation.purpose} on {reservation.reservation_start.strftime('%Y-%m-%d %H:%M')} has been REJECTED."
        else:
            message = f"Your reservation status has been updated to {reservation.status}."

        send_sms(phone_number, message)

        return jsonify({'message': f"Reservation {reservation.status.lower()} and SMS sent"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@app.route('/api/reservations/<int:reservation_id>', methods=['PUT'])
def update_reservation(reservation_id):
    data = request.get_json()
    try:
        reservation = Reservation.query.get_or_404(reservation_id)

        if 'reservation_start' not in data or 'reservation_end' not in data:
            return jsonify({'error': 'Start and end times are required'}), 400

        new_start = datetime.strptime(data['reservation_start'], '%Y-%m-%d %H:%M')
        new_end = datetime.strptime(data['reservation_end'], '%Y-%m-%d %H:%M')

        if new_end <= new_start:
            return jsonify({'error': 'End time must be after start time.'}), 400

        # ✅ Stricter overlap check (includes edge cases like touching times)
        conflicts = Reservation.query.filter(
            Reservation.id != reservation_id,
            Reservation.asset_id == reservation.asset_id,
            Reservation.status.in_(["Approved", "Pending"]),
            Reservation.reservation_start <= new_end,
            Reservation.reservation_end >= new_start
        ).all()

        if conflicts:
            return jsonify({
                'error': 'This time slot overlaps an existing reservation.',
                'conflicts': [
                    {
                        'id': c.id,
                        'start': c.reservation_start.strftime('%Y-%m-%d %H:%M'),
                        'end': c.reservation_end.strftime('%Y-%m-%d %H:%M'),
                        'status': c.status,
                        'purpose': c.purpose
                    }
                    for c in conflicts
                ]
            }), 400

        # ✅ Proceed with update
        reservation.reservation_start = new_start
        reservation.reservation_end = new_end
        reservation.purpose = data.get('purpose', reservation.purpose)
        reservation.status = 'Pending'

        db.session.commit()
        return jsonify({'message': 'Reservation updated and sent for approval'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400



@app.route('/api/reservations/<resident_name>', methods=['GET'])
def get_user_reservations(resident_name):
    reservations = Reservation.query.filter_by(resident_name=resident_name).filter(
        Reservation.status == 'Approved'
    ).all()
    result = []
    for r in reservations:
        result.append({
            'id': r.id,
            'purpose': r.purpose,
            'status': r.status,
            'reservation_start': r.reservation_start.isoformat(),
            'reservation_end': r.reservation_end.isoformat()
        })

    return jsonify(result)


@app.route('/api/pending-reservations/<resident_name>', methods=['GET'])
def get_user_pending_reservations(resident_name):
    reservations = Reservation.query.filter_by(resident_name=resident_name).filter(
        Reservation.status == 'Pending'
    ).all()
    result = []
    for r in reservations:
        result.append({
            'id': r.id,
            'purpose': r.purpose,
            'status': r.status,
            'reservation_start': r.reservation_start.isoformat(),
            'reservation_end': r.reservation_end.isoformat()
        })

    return jsonify(result)


@app.route('/api/dashboard_data')
def dashboard_data():
    # Counts
    assets_count = Asset.query.count()
    residents_count = Resident.query.count()
    reservations_pending = Reservation.query.filter_by(status="Pending").count()
    borrowings_pending = Borrowing.query.filter_by(status="Pending").count()

    # Pending reservations
    reservations = Reservation.query.filter_by(status="Pending").order_by(Reservation.reservation_start.desc()).all()
    reservations_data = [{
        "id": r.id,
        "type": "Reservation",
        "resident_name": r.resident_name,
        "item": r.item,
        "purpose": r.purpose,
        "reservation_start": r.reservation_start.isoformat(),  # <-- send full ISO string
        "reservation_end": r.reservation_end.isoformat(),  
        "status": r.status
    } for r in reservations]

    # Pending borrowings
    borrowings_pending_list = Borrowing.query.filter_by(status="Pending").order_by(Borrowing.request_date.desc()).all()
    borrowings_pending_data = [{
        "id": b.id,
        "type": "Borrowing",
        "resident_name": b.resident_name,
        "item": b.item,
        "quantity": b.quantity,
        "purpose": b.purpose,
        "request_date": b.request_date.strftime('%Y-%m-%d'),
        "return_date": b.return_date.strftime('%Y-%m-%d'),
        "status": b.status
    } for b in borrowings_pending_list]

    # Active borrowings
    active_borrowings = Borrowing.query.filter(
        Borrowing.status.in_(["Approved", "Return Requested"])
    ).order_by(Borrowing.request_date.desc()).all()
    active_borrowings_data = [{
        "id": b.id,
        "resident_name": b.resident_name,
        "item": b.item,
        "quantity": b.quantity,
        "purpose": b.purpose,
        "request_date": b.request_date.strftime('%Y-%m-%d'),
        "return_date": b.return_date.strftime('%Y-%m-%d'),
        "status": b.status
    } for b in active_borrowings]

    return jsonify({
        "assets": assets_count,
        "residents": residents_count,
        "pending": reservations_pending + borrowings_pending,
        "pending_reservations": reservations_data,
        "pending_borrowings": borrowings_pending_data,
        "active_borrowings": active_borrowings_data
    })

@app.route('/api/add-reservation', methods=['POST'])
def add_reservation_alias():
    return reserve_asset()  # just call your existing function

@app.route('/api/add-web-reservation', methods=['POST'])
def add_web_reservation():
    data = request.get_json()
    try:
        new_reservation = Reservation(
            asset_id=data['asset_id'],
            item=data['item'],
            resident_name=data['resident_name'],
            purpose=data.get('purpose', ''),
            status='Approved',  # ✅ Directly approved, no pending request
            request_date=datetime.strptime(data['reservation_date'], '%Y-%m-%d')
        )
        db.session.add(new_reservation)
        db.session.commit()
        return jsonify({'message': 'Web reservation added successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/add-web-borrowing', methods=['POST'])
def add_web_borrowing():
    data = request.get_json()
    try:
        new_borrow = Borrowing(
            asset_id=data['asset_id'],
            item=data['item'],
            resident_name=data['resident_name'],
            quantity=data.get('quantity', 1),
            purpose=data.get('purpose', ''),
            status='Approved',  # ✅ Directly approved, no pending request
            request_date=datetime.strptime(data['request_date'], '%Y-%m-%d'),
            return_date=datetime.strptime(data['return_date'], '%Y-%m-%d')
        )
        db.session.add(new_borrow)
        db.session.commit()
        return jsonify({'message': 'Web borrowing added successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/reservations/<int:asset_id>/<string:date>', methods=['GET'])
def get_reservations_for_asset_and_date(asset_id, date):
    try:
        target_date = datetime.strptime(date, '%Y-%m-%d').date()
        reservations = Reservation.query.filter(
            Reservation.asset_id == asset_id,
            Reservation.reservation_start >= datetime.combine(target_date, time(0, 0)),
            Reservation.reservation_end <= datetime.combine(target_date, time(23, 59)),
            Reservation.status.in_(["Pending", "Approved"])
        ).all()

        result = []
        for r in reservations:
            result.append({
                'reservation_start': r.reservation_start.isoformat(),
                'reservation_end': r.reservation_end.isoformat(),
                'resident_name': r.resident_name,
                'purpose': r.purpose,
                'status': r.status
            })

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/edit_resident/<int:id>', methods=['POST'])
def edit_resident(id):
    resident = Resident.query.get_or_404(id)

    full_name = request.form.get('full_name').strip()
    username = request.form.get('username').strip()
    phone_number = request.form.get('phone_number').strip()
    purok = request.form.get('purok').strip()

    # Basic validation
    if not full_name or not username or not phone_number or not purok:
        flash('All fields are required.', 'danger')
        return redirect(url_for('manage_accounts'))

    # Optional: check if username is already used by another resident
    existing_user = Resident.query.filter(Resident.username == username, Resident.id != id).first()
    if existing_user:
        flash('Username already taken.', 'danger')
        return redirect(url_for('manage_accounts'))

    # Update the resident
    resident.full_name = full_name
    resident.username = username
    resident.phone_number = phone_number
    resident.purok = purok

    try:
        db.session.commit()
        flash('Resident details updated successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating resident: ' + str(e), 'danger')

    return redirect(url_for('manage_accounts'))


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)

