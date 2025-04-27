from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import os
from flask_dance.contrib.google import make_google_blueprint, google

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

app = Flask(__name__)

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


if __name__ == '__main__':
    add_more_doctors()
    init_db()
    app.run(debug=True)