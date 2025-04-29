from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import os
from flask_dance.contrib.google import make_google_blueprint, google

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")

blueprint = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    scope=['profile', 'email']
)

app.register_blueprint(blueprint, url_prefix='/login')

# Security settings
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = os.getenv("OAUTHLIB_INSECURE_TRANSPORT", '1')
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = os.getenv("OAUTHLIB_RELAX_TOKEN_SCOPE", '1')

# Initialize database and authentication
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class Admin(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email= db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=True)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    appointments = db.relationship('Appointment', backref='patient', lazy=True)

class Doctor(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    specialization = db.Column(db.String(100), nullable=False)
    experience = db.Column(db.Integer)
    city = db.Column(db.String(50))
    fees = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200))
    password_hash = db.Column(db.String(128))
    appointments = db.relationship('Appointment', backref='doctor', lazy=True)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=False)
    appointment_date = db.Column(db.Date, nullable=False)
    time_slot = db.Column(db.String(20), nullable=False)
    illness = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='Confirmed')
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    contact = db.Column(db.String(20), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10), nullable=False)

def set_password(self, password):
    self.password_hash = generate_password_hash(password)

def check_password(self, password):
    return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    
    admin = Admin.query.get(int(user_id))
    if admin:
        return admin
    
    user = User.query.get(int(user_id))
    if user:
        return user
   
    return Doctor.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not isinstance(current_user, Admin):
            flash('You need to be logged in as an admin to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


#checkpoint 1
@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
    
        admin = Admin.query.filter_by(email=email).first()
        if admin and check_password_hash(admin.password_hash, password):
            login_user(admin)
            return redirect(url_for('admin_dashboard'))
            
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
            
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/google-login')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    resp = google.get('/oauth2/v2/userinfo')

    if resp.status_code != 200:
        flash('Google login failed', 'error')
        return redirect(url_for('login'))

    user_info= resp.json()
    email = user_info.get("email")
    username = user_info.get("name", email.split('@')[0])  

    
    user_info= User.query.filter_by(email=email).first()
    if not user_info:
        user = User(username=username, email=email)
        db.session.add(user)
        db.session.commit()

    login_user(user_info, remember=True)
    session.permanent = True 

    return redirect(url_for('index'))  


@app.route('/signup', methods=['GET', 'POST'])
def signup():
   
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))
        
    
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('signup'))

    
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful', 'success')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
  
    session.pop('username', None)
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    
    doctors = Doctor.query.all()
    return render_template('admin_dashboard.html', doctors=doctors)

@app.route('/doctor/login', methods=['GET', 'POST'])
def doctor_login():
   
    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        password = request.form.get('password')
       
        doctor = Doctor.query.filter_by(doctor_id=doctor_id).first()
        
        if doctor and check_password_hash(doctor.password_hash, password):
            login_user(doctor)
            return redirect(url_for('doctor_dashboard'))
        flash('Invalid doctor ID or password', 'error')
    return render_template('doctor_login.html')

@app.route('/doctor/logout')
@login_required
def doctor_logout():
    
    logout_user()
    return redirect(url_for('doctor_login'))


@app.route('/')
def index():
   
    app.logger.debug(f'current_user: {current_user.is_authenticated}')

    if current_user.is_authenticated:
        return render_template('index.html', username=current_user.username)
    return render_template('index.html')


@app.route('/book-appointment', methods=['GET', 'POST'])
@login_required
def book_appointment():
    
    if request.method == 'POST':
       
        session['appointment_data'] = {
            'first_name': request.form.get('first_name'),
            'last_name': request.form.get('last_name'),
            'contact': request.form.get('contact'),
            'gender': request.form.get('gender'),
            'age': int(request.form.get('age')),
            'city': request.form.get('city'),
            'illness': request.form.get('illness')
        }
        return redirect(url_for('select_doctor'))
    return render_template('appointment_form.html')

@app.route('/clear-session')
def clear_session():
    session.clear()
    return redirect(url_for('home'))

#checkpoint-1
@app.route('/select-doctor', methods=['GET', 'POST'])
@login_required

def select_doctor():
    
    if 'appointment_data' not in session:
        return redirect(url_for('book_appointment'))
    
 
    city = session['appointment_data']['city'].strip().lower()
    illness = session['appointment_data']['illness'].strip().lower()
    
    
    doctors = Doctor.query.filter(
        db.func.lower(Doctor.city) == city,
        db.func.lower(Doctor.specialization) == illness
    ).all()
    
    for doctor in doctors:
        doctor.available_slots = [
            f"{(datetime.now() + timedelta(days=i)).strftime('%Y-%m-%d')} {slot}"
            for i in range(1, 8)
            for slot in ['09:00 AM', '10:00 AM', '11:00 AM', '2:00 PM', '3:00 PM', '4:00 PM']
        ]
    
    return render_template('doctor_selection.html', doctors=doctors)

@app.route('/appointment-summary', methods=['GET', 'POST'])
@login_required
def appointment_summary():
    
    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        time_slot = request.form.get('time_slot')
        
       
        doctor = Doctor.query.get(doctor_id)
        
 
        appointment_data = session.get('appointment_data', {})
        appointment_data['doctor_id'] = doctor.id
        appointment_data['time_slot'] = time_slot
        appointment_data['date'] = time_slot.split(' ')[0]
        session['appointment_data'] = appointment_data
        
        return render_template('appointment_summary.html', 
                             appointment=appointment_data,
                             doctor=doctor)
    return redirect(url_for('book_appointment'))

@app.route('/confirm-appointment', methods=['POST'])
@login_required
def confirm_appointment():
   
    if 'appointment_data' not in session:
        return redirect(url_for('book_appointment'))
    
    data = session['appointment_data']
    
    appointment = Appointment(
        patient_id=current_user.id,
        doctor_id=data['doctor_id'],
        appointment_date=datetime.strptime(data['time_slot'].split(' ')[0], '%Y-%m-%d').date(),
        time_slot=data['time_slot'].split(' ', 1)[1],
        illness=data['illness'],
        first_name=data['first_name'],
        last_name=data['last_name'],
        contact=data['contact'],
        age=data['age'],
        gender=data['gender']
    )
    
   
    db.session.add(appointment)
    db.session.commit()
    
    
    session.pop('appointment_data', None)
    
    flash('Appointment confirmed successfully!', 'success')
    return redirect(url_for('my_appointments'))
#checkpoint 2

@app.route('/my-appointments')
@login_required
def my_appointments():
    
    
    appointments = Appointment.query.filter_by(patient_id=current_user.id).all()
   
    for appointment in appointments:
        doctor = Doctor.query.get(appointment.doctor_id)
        appointment.doctor_name = doctor.name if doctor else "Unknown"
        
    return render_template('my_appointments.html', appointments=appointments)

@app.route('/cancel-appointment', methods=['POST'])
@login_required
def cancel_appointment():
 
    appointment_id = request.form.get('appointment_id')
    appointment = Appointment.query.get(appointment_id)
    
    if appointment and appointment.patient_id == current_user.id:
        appointment.status = 'Cancelled'
        db.session.commit()
        flash('Appointment cancelled successfully', 'success')
    else:
        flash('Invalid appointment or permission denied', 'error')
        
    return redirect(url_for('my_appointments'))

@app.route('/doctor/dashboard')
@login_required
def doctor_dashboard():


    today = datetime.now().date()
    
    today_appointments = Appointment.query.filter_by(
        doctor_id=current_user.id,
        appointment_date=today,
        status='Confirmed'
    ).all()
    
    upcoming_appointments = Appointment.query.filter(
        Appointment.doctor_id == current_user.id,
        Appointment.appointment_date > today,
        Appointment.status == 'Confirmed'
    ).order_by(Appointment.appointment_date).all()
    
    first_day_of_month = datetime(today.year, today.month, 1).date()
    last_day_of_month = (datetime(today.year, today.month + 1, 1) - timedelta(days=1)).date() if today.month < 12 else datetime(today.year + 1, 1, 1).date() - timedelta(days=1)
    
    monthly_appointments = Appointment.query.filter(
        Appointment.doctor_id == current_user.id,
        Appointment.appointment_date >= first_day_of_month,
        Appointment.appointment_date <= last_day_of_month,
        Appointment.status == 'Confirmed'
    ).count()
    
    monthly_earnings = current_user.fees * monthly_appointments
    
    return render_template('doctor_dashboard.html',
                          doctor=current_user,
                          today_appointments=today_appointments,
                          upcoming_appointments=upcoming_appointments,
                          monthly_earnings=monthly_earnings)


@app.errorhandler(404)
def page_not_found(e):
   
    return render_template('404.html'), 404

@app.route('/profile')
@login_required
def profile():
    
    appointments = Appointment.query.filter_by(patient_id=current_user.id).all()
    
    return render_template('profile.html', 
                         appointments=appointments,
                         current_user=current_user)

@app.errorhandler(500)
def internal_server_error(e):
    
    return render_template('500.html'), 500

@app.route('/about')
def about():
    
    return render_template('about.html')



@app.route('/admin/add-doctor', methods=['GET', 'POST'])
@admin_required
def add_doctor():
    
    if request.method == 'POST':
      
        last_doctor = Doctor.query.order_by(Doctor.id.desc()).first()
        new_doctor_id = f"DOC{(last_doctor.id + 1) if last_doctor else 1}"
        
        doctor = Doctor(
            doctor_id=new_doctor_id,
            name=request.form.get('name'),
            specialization=request.form.get('specialization'),
            experience=int(request.form.get('experience')),
            city=request.form.get('city'),
            fees=float(request.form.get('fees')),
            image=request.form.get('image', '/static/images/doctor1.jpg'),
            password_hash=generate_password_hash(request.form.get('password'))
        )
        
        db.session.add(doctor)
        db.session.commit()
        flash('Doctor added successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('add_doctor.html')

@app.route('/admin/delete-doctor/<int:doctor_id>', methods=['POST'])
@admin_required
def delete_doctor(doctor_id):
    
    doctor = Doctor.query.get_or_404(doctor_id)
    
    Appointment.query.filter_by(doctor_id=doctor.id).delete()
    
    db.session.delete(doctor)
    db.session.commit()
    flash('Doctor deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))

def init_db():
    with app.app_context():
        db.create_all()
        
        if Admin.query.count() == 0:
            admin = Admin(
                username='admin',
                email='admin@doccure.com',
                password_hash=generate_password_hash('admin123')
            )
            db.session.add(admin)
            db.session.commit()

def add_more_doctors():
    
    with app.app_context():
        
        specialization_map = {
            'Heart Disease': 'Cardiology',
            'Bone & Joint Problems': 'Orthopedics',
            'Neurological Issues': 'Neurology',
            'Skin Problems': 'Dermatology',
            'ENT Issues': 'ENT',
            'Eye Problems': 'Ophthalmology'
        }
        
    
        cities = ['Mumbai', 'Delhi', 'Bangalore', 'Chennai', 'Kolkata']
        
        first_names = ['Aarav', 'Aditi', 'Arjun', 'Diya', 'Ishaan', 'Kavya', 'Neha', 'Rohan', 'Sanya', 'Vikram']
        last_names = ['Patel', 'Sharma', 'Singh', 'Gupta', 'Kumar', 'Reddy', 'Joshi', 'Malhotra', 'Kapoor', 'Verma']
        
       
        highest_id = 0
        doctors = Doctor.query.all()
        for doctor in doctors:
            try:
                
                doc_id = int(doctor.doctor_id[3:])
                if doc_id > highest_id:
                    highest_id = doc_id
            except:
                pass
        
        if highest_id == 0:
            highest_id = 1000  
        
        doctor_id = highest_id + 1
        doctors_added = 0
        
        
        for city in cities:
            for illness, specialization in specialization_map.items():
                
                existing_count = Doctor.query.filter_by(
                    specialization=specialization,
                    city=city
                ).count()
                
               
                doctors_to_add = max(0, 2 - existing_count)
                
                for i in range(doctors_to_add):
                    experience = 5 + (doctor_id % 20)  
                    fees = 500 + (doctor_id % 15) * 100  
                    
                    doctor_id_str = f'DOC{doctor_id}'
                    first_name = first_names[doctor_id % len(first_names)]
                    last_name = last_names[doctor_id % len(last_names)]
                    doctor = Doctor(
                        doctor_id=doctor_id_str,
                        name=f'Dr. {first_name} {last_name}',
                        specialization=specialization,
                        experience=experience,
                        city=city,
                        fees=fees,
                        image=f'/static/images/doctor{1 + (doctor_id % 10)}.jpg',
                        password_hash=generate_password_hash('doctor123')
                    )
                    db.session.add(doctor)
                    doctor_id += 1
                    doctors_added += 1
        
        db.session.commit()

            

if __name__ == '__main__':
    add_more_doctors()
    init_db()
    app.run(debug=True)