import os
from flask import Flask, flash, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_
import pymysql
import threading
from datetime import datetime, date, timedelta
import time 
from werkzeug.security import generate_password_hash, check_password_hash
import re
from werkzeug.utils import secure_filename
import requests
from apscheduler.schedulers.background import BackgroundScheduler


# Required for PyMySQL to work with SQLAlchemy
pymysql.install_as_MySQLdb()

app = Flask(__name__)
app.secret_key = 'secret_key_barma'

# Admin credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'

# SQLAlchemy + PyMySQL connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3306/barma'

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True
}

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# Separate folders for ID and Selfie pictures
ID_UPLOAD_FOLDER = r'C:\Users\renel\Desktop\BARMA\admin_web\static\id_pictures'
SELFIE_UPLOAD_FOLDER = r'C:\Users\renel\Desktop\BARMA\admin_web\static\selfie_pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Ensure both folders exist
os.makedirs(ID_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SELFIE_UPLOAD_FOLDER, exist_ok=True)


TEXTBEE_API_KEY = "9bfcb997-3072-45e5-99ad-0f05fe323b23"
TEXTBEE_DEVICE_ID = "68a6a678331241e70a37bf79"
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


def send_return_reminders():
    tomorrow = datetime.utcnow().date() + timedelta(days=1)
    borrowings = Borrowing.query.filter(Borrowing.return_date == tomorrow, Borrowing.status == 'Approved').all()
    for b in borrowings:
        resident = b.resident  # assuming Borrowing has a relationship to Resident
        if resident:
            send_sms(resident.phone_number, f"Reminder: Please return {b.item} tomorrow ({b.return_date}).")

scheduler = BackgroundScheduler()
scheduler.add_job(send_return_reminders, 'interval', hours=24)  # runs daily
scheduler.start()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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

    # ✅ Relationships to Borrowing and Reservation
    borrowings = db.relationship('Borrowing', backref='asset', lazy=True)
    reservations = db.relationship('Reservation', backref='asset', lazy=True)


class Reservation(db.Model):
    __tablename__ = 'reservations'
    id = db.Column(db.Integer, primary_key=True)
    resident_name = db.Column(db.String(255), nullable=False)
    item = db.Column(db.String(255), nullable=False)
    purpose = db.Column(db.String(255), nullable=True)
    request_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.Enum('Pending', 'Approved', 'Rejected'), default='Pending')
    
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)  # ✅ Add this


class Borrowing(db.Model):
    __tablename__ = 'borrowings'
    id = db.Column(db.Integer, primary_key=True)
    resident_name = db.Column(db.String(255), nullable=False)
    item = db.Column(db.String(255), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    purpose = db.Column(db.String(255), nullable=True)
    request_date = db.Column(db.Date, nullable=False)
    return_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.Enum('Pending', 'Approved', 'Rejected', 'Returned', 'Return Requested'), default='Pending')

    
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)  # ✅ Add this



class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50))  # 'Reservation' or 'Borrowing'
    resident_name = db.Column(db.String(100))
    item = db.Column(db.String(100))
    quantity = db.Column(db.Integer)  # ➕ Add this
    purpose = db.Column(db.String(200))  # ➕ Add this
    action_type = db.Column(db.String(50))  # 'Approved', 'Rejected', 'Returned'
    action_date = db.Column(db.DateTime, default=datetime.utcnow)

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

        if restricted_names:
            db.session.commit()
            print(f"[AUTO RESTRICT] Restricted residents: {restricted_names}")
        else:
            print("[AUTO RESTRICT] No accounts to restrict today.")


@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin'] = True
            restrict_overdue_accounts()
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if not session.get('admin'):
        return redirect(url_for('login'))

    assets = Asset.query.all()
    reservations = Reservation.query.order_by(Reservation.request_date.desc()).all()
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

    name = request.form['name']
    quantity = int(request.form['quantity'])
    classification = request.form['classification']  # NEW: Get classification from form

    asset = Asset(name=name, quantity=quantity, classification=classification)  # NEW: Pass classification
    db.session.add(asset)
    db.session.commit()

    return redirect(url_for('assets_page'))  # redirect to assets page


@app.route('/edit_asset/<int:id>', methods=['GET', 'POST'])
def edit_asset(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    asset = Asset.query.get_or_404(id)
    if request.method == 'POST':
        asset.name = request.form['name']
        asset.quantity = int(request.form['quantity'])
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('edit_asset.html', asset=asset)

@app.route('/delete_asset/<int:id>')
def delete_asset(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    asset = Asset.query.get_or_404(id)
    db.session.delete(asset)
    db.session.commit()
    return redirect(url_for('dashboard'))

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

    # Add to history
    history = History(
        type='Reservation',
        resident_name=reservation.resident_name,
        item=reservation.item,
        purpose=reservation.purpose,
        action_type='Approved'
    )

    db.session.add(history)
    db.session.commit()

    # ✅ Send SMS
    resident = Resident.query.filter_by(full_name=reservation.resident_name).first()
    if resident:
        send_sms(resident.phone_number,
                 f"Hi {resident.full_name}, your reservation for {reservation.item} has been APPROVED.")

    return redirect(url_for('dashboard'))



@app.route('/reject_reservation/<int:id>')
def reject_reservation(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    reservation = Reservation.query.get_or_404(id)
    reservation.status = 'Rejected'

    history = History(
        type='Reservation',
        resident_name=reservation.resident_name,
        item=reservation.item,
        purpose=reservation.purpose,
        action_type='Rejected'
    )

    db.session.add(history)
    db.session.commit()
    # After db.session.commit()
    resident = Resident.query.filter_by(full_name=reservation.resident_name).first()
    if resident:
        send_sms(resident.phone_number,
                f"Hi {resident.full_name}, your reservation for {reservation.item} has been REJECTED.")

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

    # Approve borrowing
    borrowing.status = "Approved"

    # Add to history
    history = History(
        type='Borrowing',
        resident_name=borrowing.resident_name,
        item=borrowing.item,
        quantity=borrowing.quantity,
        purpose=borrowing.purpose,
        action_type='Approved'
    )
    db.session.add(history)
    db.session.commit()
    flash('Borrowing approved.', 'success')

    # ✅ Send SMS notification
    resident = Resident.query.filter_by(full_name=borrowing.resident_name).first()
    if resident:
        send_sms(
            resident.phone_number,
            f"Hi {resident.full_name}, your borrowing request for {borrowing.item} ({borrowing.quantity}) has been APPROVED. Please return it by {borrowing.return_date}."
        )

    return redirect(url_for('dashboard'))


@app.route('/reject_borrowing/<int:id>')
def reject_borrowing(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    borrowing = Borrowing.query.get_or_404(id)
    borrowing.status = 'Rejected'

    # Add to history
    history = History(
        type='Borrowing',
        resident_name=borrowing.resident_name,
        item=borrowing.item,
        quantity=borrowing.quantity,
        purpose=borrowing.purpose,
        action_type='Rejected'
    )
    db.session.add(history)
    db.session.commit()

    # ✅ Send SMS notification
    resident = Resident.query.filter_by(full_name=borrowing.resident_name).first()
    if resident:
        send_sms(
            resident.phone_number,
            f"Hi {resident.full_name}, your borrowing request for {borrowing.item} ({borrowing.quantity}) has been REJECTED."
        )

    return redirect(url_for('dashboard'))


@app.route('/history')
def history_page():
    if not session.get('admin'):
        return redirect(url_for('login'))

    history_logs = History.query.order_by(History.action_date.desc()).all()

    return render_template('history.html', history_logs=history_logs)

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
def assets_page():
    if not session.get('admin'):
        return redirect(url_for('login'))
    assets = Asset.query.all()
    return render_template('assets.html', assets=assets)

@app.route('/api/register', methods=['POST'])
def register_resident():
    full_name = request.form.get('full_name')
    gender = request.form.get('gender')
    purok = request.form.get('purok')  # ✅ added
    phone_number = request.form.get('phone_number')
    username = request.form.get('username')
    raw_password = request.form.get('password')

    id_picture = request.files.get('id_picture')
    selfie_picture = request.files.get('selfie_picture')  # ✅ added

    # Validate required fields
    if not all([full_name, gender, purok, phone_number, username, raw_password, id_picture, selfie_picture]):
        return jsonify({'error': 'All fields including ID and selfie picture are required'}), 400

    # Validate phone number (PH format)
    if not re.fullmatch(r'^(09|\+639)\d{9}$', phone_number):
        return jsonify({'error': 'Invalid phone number format. Use 09XXXXXXXXX or +639XXXXXXXXX'}), 400

    # Validate password
    if not re.fullmatch(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$', raw_password):
        return jsonify({
            'error': 'Password must be at least 8 characters and include uppercase, lowercase, number, and special character'
        }), 400

    # Validate image file types
    if not (allowed_file(id_picture.filename) and allowed_file(selfie_picture.filename)):
        return jsonify({'error': 'Only JPG, JPEG, PNG formats are allowed for images.'}), 400

    # Check for duplicate username or full name
    if Resident.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already taken'}), 400

    if Resident.query.filter_by(full_name=full_name).first():
        return jsonify({'error': 'An account already exists for this full name'}), 400

    # Save files to correct folders
    id_filename = secure_filename(id_picture.filename)
    selfie_filename = secure_filename(selfie_picture.filename)

    id_picture_path = os.path.join('id_pictures', id_filename).replace('\\', '/')
    selfie_picture_path = os.path.join('selfie_pictures', selfie_filename).replace('\\', '/')

    try:
        id_picture.save(os.path.join(ID_UPLOAD_FOLDER, id_filename).replace('\\', '/'))
        selfie_picture.save(os.path.join(SELFIE_UPLOAD_FOLDER, selfie_filename).replace('\\', '/'))
    except Exception as e:
        print(f"File save error: {e}")
        return jsonify({'error': 'Failed to save uploaded images'}), 500

    # Hash password
    hashed_password = generate_password_hash(raw_password, method='pbkdf2:sha256', salt_length=8)

    resident = Resident(
    full_name=full_name,
    gender=gender,
    phone_number=phone_number,
    username=username,
    password=hashed_password,
    id_picture_path=id_picture_path,  # store relative path only
    selfie_picture_path=selfie_picture_path,  # store relative path only
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
            return_date=datetime.strptime(data['return_date'], '%Y-%m-%d')
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
        new_reservation = Reservation(
            asset_id=data['asset_id'],
            resident_name=data['resident_name'],
            item=data['item'],  # ✅ FIX: Include item here
            purpose=data['purpose'],
            status='Pending',
            request_date=datetime.strptime(data['reservation_date'], '%Y-%m-%d')
        )
        db.session.add(new_reservation)
        db.session.commit()
        return jsonify({'message': 'Reservation request submitted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/reserved-dates/<int:asset_id>')
def get_reserved_dates(asset_id):
    reservations = Reservation.query.filter_by(asset_id=asset_id).filter(
        Reservation.status.in_(['Pending', 'Approved'])
    ).all()
    
    reserved_dates = [r.request_date.strftime('%Y-%m-%d') for r in reservations]
    return jsonify(reserved_dates)


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

    return render_template('manage_accounts.html', residents=residents, pending_residents=pending_residents)

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
    today = datetime.today().date()
    reservations = Reservation.query.filter_by(resident_name=resident_name, status='Pending').filter(
        Reservation.request_date >= today
    ).order_by(Reservation.request_date.asc()).all()

    result = []
    for r in reservations:
        result.append({
            'id': r.id,
            'purpose': r.purpose,
            'date': r.request_date.strftime('%Y-%m-%d'),
            'status': r.status
        })
    return jsonify(result)



@app.route('/reservations')
def reservations_page():
    if not session.get('admin'):
        return redirect(url_for('login'))

    # Get all assets classified as 'Reservation'
    reservable_assets = Asset.query.filter_by(classification='Reservation').all()

    # Get active reservation records
    active_reservations = Reservation.query.filter(
        Reservation.status.in_(['Pending', 'Approved'])
    ).all()

    # Extract asset names that are actually reserved
    reserved_items = list(set(asset.name for asset in reservable_assets))

    return render_template(
        'reservation.html',
        reservable_assets=reservable_assets,
        reserved_items=reserved_items
    )


@app.route('/api/reservation-events')
def reservation_events():
    reservations = Reservation.query.filter(
        Reservation.status.in_(['Pending', 'Approved'])
    ).all()

    events = []
    for r in reservations:
        events.append({
            "title": r.item,  # Displayed on calendar
            "start": r.request_date.strftime('%Y-%m-%d'),
            "color": "#0d6efd" if r.status == 'Approved' else "#ffc107",
            "extendedProps": {
                "status": r.status,
                "resident_name": r.resident_name,
                "purpose": r.purpose,  # ✅ Add this line
                "remarks": getattr(r, 'remarks', '')  # Optional
            }
        })

    return jsonify(events)


@app.route('/update_asset/<int:id>', methods=['POST'])
def update_asset(id):
    if not session.get('admin'):
        return redirect(url_for('login'))

    asset = Asset.query.get_or_404(id)
    asset.name = request.form['name']
    asset.quantity = int(request.form['quantity'])
    asset.classification = request.form['classification']
    db.session.commit()

    return redirect(url_for('assets_page'))

@app.route('/borrowings')
def borrowings_page():
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
            available_quantity = 0  # prevent negative

        asset_data.append({
            'id': asset.id,
            'name': asset.name,
            'available_quantity': available_quantity
        })

    return render_template('borrowings.html', borrowing_assets=asset_data)



@app.route('/api/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    if not data or 'username' not in data or 'new_password' not in data:
        return jsonify({"error": "Invalid request data"}), 400

    username = data['username']
    new_password = data['new_password']

    user = Resident.query.filter_by(username=username).first()
    if user:
        user.password = generate_password_hash(new_password)
  # replace with actual hash function
        db.session.commit()
        return jsonify({"message": "Password reset successful"}), 200
    else:
        return jsonify({"error": "User not found"}), 404


@app.route('/api/user-id/<name>', methods=['GET'])
def get_user_id_by_name(name):
    user = Resident.query.filter_by(full_name=name).first()
    if user:
        return jsonify({'user_id': user.id}), 200
    else:
        return jsonify({'error': 'User not found'}), 404


@app.route('/admin/approve-return/<int:borrow_id>', methods=['POST'])
def approve_return(borrow_id):
    borrowing = Borrowing.query.get_or_404(borrow_id)

    if borrowing.status == 'Return Requested':
        borrowing.status = 'Returned'
        # Optional: borrowing.returned_on = datetime.utcnow()
        db.session.commit()
        flash('Return approved successfully.', 'success')

        # ✅ Send SMS notification
        resident = Resident.query.filter_by(full_name=borrowing.resident_name).first()
        if resident and resident.phone_number:
            send_sms(
                resident.phone_number,
                f"Hi {resident.full_name}, your return request for {borrowing.item} has been APPROVED. Thank you!"
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
        next_run = datetime.combine(now.date(), datetime.min.time())  # midnight
        next_run = next_run.replace(hour=1)  # run at 1 AM

        # If it's already past 1AM today, run tomorrow
        if now >= next_run:
            next_run = next_run.replace(day=now.day + 1)

        wait_seconds = (next_run - now).total_seconds()
        print(f"[SCHEDULER] Restriction check will run in {int(wait_seconds)} seconds.")

        time.sleep(wait_seconds)
        restrict_overdue_accounts()  # ✅ call the function

# Run in background thread
threading.Thread(target=run_daily_restriction, daemon=True).start()


@app.route('/api/reservations/<int:reservation_id>', methods=['PUT'])
def update_reservation(reservation_id):
    data = request.get_json()
    try:
        reservation = Reservation.query.get_or_404(reservation_id)

        # Extract new request_date if provided
        new_date = None
        if 'request_date' in data:
            new_date = datetime.strptime(data['request_date'], '%Y-%m-%d').date()

            # Check if another reservation already exists with the same date
            conflict = Reservation.query.filter(
                Reservation.id != reservation_id,  # exclude current one
                Reservation.request_date == new_date,
                Reservation.status.in_(["Approved", "Pending"])  # exclude cancelled/denied
            ).first()

            if conflict:
                return jsonify({'error': 'This date is already reserved.'}), 400

            reservation.request_date = new_date

        # Update other fields
        if 'purpose' in data:
            reservation.purpose = data['purpose']

        # Reset status to Pending after edit
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
            'date': r.request_date.strftime('%Y-%m-%d'),
            'time': getattr(r, 'time', 'N/A')
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
            'date': r.request_date.strftime('%Y-%m-%d'),
            'time': getattr(r, 'time', 'N/A')
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
    reservations = Reservation.query.filter_by(status="Pending").order_by(Reservation.request_date.desc()).all()
    reservations_data = [{
        "id": r.id,
        "type": "Reservation",
        "resident_name": r.resident_name,
        "item": r.item,
        "purpose": r.purpose,
        "request_date": r.request_date.strftime('%Y-%m-%d'),
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




if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)

