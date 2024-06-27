from app import app
from flask import render_template, flash, redirect, url_for, request
from app.forms import Loginform
from flask_login import current_user, login_user, logout_user, login_required #The current_user comes from flask-login and can be used at any time during the handling of a request to obtain the user object that represents the clients of that request
import sqlalchemy as sa
from app import db
from app.models import User
from app.forms import RegistrationForm, Loginform, ResetPasswordRequestForm, ResetPasswordForm
from app.email import send_password_reset_email, send_email_confirmation_email
from urllib.parse import urlsplit
import subprocess, jwt

@app.route('/')
@app.route('/projects')
@login_required
def projects():
    projects = ['closed_end_project']
    return render_template('projects.html', title = 'Home Page', projects = projects)

@app.route('/login', methods=['GET', 'POST']) #Tells flask that the view function accepts GET and POST requests. GET requests are those that return information to the client and POSTS requests are used when the browser submits form data to the server
def login():
    if current_user.is_authenticated: #UseMixin is used to implement this general property that is required by flask-login
        flash('You are already logged in, please logout to access the login page')
        return redirect(url_for('projects'))
    form = Loginform()
    if form.validate_on_submit():
        user = db.session.scalar(sa.select(User).where(User.username == form.username.data))
        if user is None or not user.check_password(form.password.data) or not user.email_verified:
            flash('Invalid username, password, or email not verified')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('projects')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('projects'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('You are already logged in, please logout to access the register page')
        return redirect(url_for('projects'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username = form.username.data, email = form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        send_email_confirmation_email(user)
        flash('A verification email has been sent to you. Please verify your email to complete registration.')
        return redirect(url_for('login'))
    return render_template('register.html', title = 'Register', form = form)

@app.route('/reset_password_request', methods = ['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('projects'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = db.session.scalar(sa.select(User).where(User.email == form.email.data))
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('projects'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('projects'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

@app.route('/confirm_email/<token>', methods = ['GET', 'POST'])
def confirm_email(token):
    if current_user.is_authenticated: #User is logged in right now
        return redirect(url_for('projects'))
    user = User.verify_email_confirmation_token(token) #Find the user from the token
    if not user: #If the user isn't found then either they don't exist (not in db) or they are in db but their link expired
        flash('The verification link is invalid or has expired.')
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['confirm_email'] #Try to decode the token without considering time
            user = db.session.get(User, id) #Find the user based on this decoded token
            if user and not user.email_verified: #If the user exists and they're not verified
                db.session.delete(user) #Delete the user and commit the changes to the db
                db.session.commit()
                flash('Your registration has been invalidated. Please register again.')
        except:
            pass

        return redirect(url_for('register'))
    user.email_verified = True
    db.session.commit()
    flash('Your email has been verified!')
    return redirect(url_for('login'))

@app.route('/closed-end-project')
@login_required
def closed_end_project():
    return render_template('closed_end_project.html', title='Closed End Project')

@app.route('/run-closed-end-script', methods = ['POST'])
@login_required
def run_closed_end_script():
    subprocess.run(['python3', 'closed_end_project.py'])
    return redirect(url_for('projects'))