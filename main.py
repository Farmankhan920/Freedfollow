from flask import Flask, render_template, request, redirect, url_for, flash, session
from replit import db # Replit's built-in database
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.urandom(24) # Secure random key for session management

# Initialize database keys if they don't exist
if "users" not in db:
    db["users"] = {}  # Stores user details: {email: {full_name, hashed_password, mobile}}
if "login_records" not in db:
    db["login_records"] = [] # Stores signup/login events for admin panel

ADMIN_PASSWORD_PLAIN = "Faiz920" # Admin panel access password

@app.route('/', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        mobile = request.form.get('mobile')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        errors = []
        if not all([full_name, email, mobile, password, confirm_password]):
            errors.append("Sabhi fields bharna zaroori hai.")
        if password != confirm_password:
            errors.append("Password aur Confirm Password match nahi karte.")
        if email in db["users"]:
            errors.append("Yeh email pehle se registered hai.")
        
        # Basic email validation (can be improved)
        if "@" not in email or "." not in email.split('@')[-1]:
            errors.append("Email format sahi nahi hai.")
        
        # Basic mobile validation (can be improved)
        if not mobile.isdigit() or len(mobile) < 10:
             errors.append("Mobile number sahi format mein nahi hai (kam se kam 10 अंक).")


        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('signup.html', 
                                   full_name=full_name, email=email, mobile=mobile) # Preserve input
        else:
            hashed_password = generate_password_hash(password)
            db["users"][email] = {
                "full_name": full_name,
                "hashed_password": hashed_password,
                "mobile": mobile
            }

            # Record this "signup" event for the admin panel
            # WARNING: Storing plain password here as per request, VERY INSECURE
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            db["login_records"].append({
                "timestamp": now,
                "full_name": full_name,
                "email": email,
                "mobile": mobile,
                "password_entered": password # SECURITY RISK!
            })
            
            flash('Signup safal! Ab aap Admin Panel access kar sakte hain.', 'success')
            # Store a temporary flag to show admin button
            session['show_admin_button'] = True 
            session['last_signed_up_email'] = email # To prefill if needed, or just for context
            return redirect(url_for('signup_success'))

    return render_template('signup.html')

@app.route('/signup_success')
def signup_success():
    if not session.get('show_admin_button'):
        return redirect(url_for('signup')) # Redirect if accessed directly without signup
    
    # Clear the flag so it doesn't persist
    # session.pop('show_admin_button', None) 
    # Actually, let's keep it so they can go back and see the button if they navigate away
    
    return render_template('signup_success.html')


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password_attempt = request.form.get('admin_password')
        if password_attempt == ADMIN_PASSWORD_PLAIN:
            session['admin_logged_in'] = True
            flash('Admin login safal!', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('Galat admin password.', 'danger')
    return render_template('admin_login.html')

@app.route('/admin_panel')
def admin_panel():
    if not session.get('admin_logged_in'):
        flash('Admin panel access karne ke liye login karein.', 'warning')
        return redirect(url_for('admin_login'))
    
    # Sort records by timestamp, newest first
    login_data = sorted(list(db["login_records"]), key=lambda x: x["timestamp"], reverse=True)
    return render_template('admin_panel.html', login_data=login_data)

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Aap admin panel se logout ho gaye hain.', 'info')
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)