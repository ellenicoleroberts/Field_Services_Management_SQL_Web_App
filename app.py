from distutils.command import check
from distutils.command.install_egg_info import to_filename
from unicodedata import name
from flask import Flask, Response, request

from twilio.twiml.messaging_response import MessagingResponse
from flask import render_template, flash, redirect, url_for
from twilio import twiml

import os
from twilio.rest import Client

#from send_sms import *

from datetime import datetime, timedelta
from pytz import timezone

from flask_sqlalchemy import SQLAlchemy

from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SubmitField, DateField, IntegerField, FloatField, SelectField, PasswordField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length 

from numpy import random

from sqlalchemy import desc

import re

import time
import atexit

from apscheduler.schedulers.background import BackgroundScheduler

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

from webforms import UserForm, TechnicianForm, JobForm, MessageForm, IncomingForm, PasswordForm, LoginForm, SearchForm


#--------------------------------------------------------

app = Flask(__name__) #instance of Flask, creates an app

app.config['SECRET_KEY'] = "Simple Simply Simplifies"

#Add-Database------------------------------------------------------

#add SQLite database
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

#add Postgre database
#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://nicoleroberts:Simple0922!@localhost/simpledb' #root is MySQL username from download and password likewise. 'users' is my name of db.

#add Postgre database for HEROKU
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://gvdtjfyatqwptd:e50bf81d4db7717b7e8aa229483778080efb6b15c14023d5519e0319da861480@ec2-54-160-200-167.compute-1.amazonaws.com:5432/ddilq9tk5a1ci6'

#initialize the database with SQLAlchemy

db = SQLAlchemy(app) 

#Flask-Login-------------------------------------------------------- 

login_manager = LoginManager()  #instantiates Flask login
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader  #loads user
def load_user(user_id): 
    return Users.query.get(int(user_id))


#create a login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data.lower()).first()  #grabs 1st username (the ONLY one, as they are unique) -- if it exists!
        if user:
            if check_password_hash(user.password_hash, form.password.data): #checks the hash, returns True or False 
                login_user(user)
                flash("Login successful.")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong password, please try again.")
        else:
            flash("User doesn't exist or incorrect username. Please try again.")

    return render_template('login.html', form=form)


#create logout 
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You are now logged out.")
    return redirect(url_for('login'))


#Search-Bar----------------------------------------------------------------


#pass info to Navbar so can run search from navbar
@app.context_processor
def base():
    form = SearchForm()
    return dict(form=form)


#create search function
@app.route('/search', methods=['POST'])
def search():
    form = SearchForm()
    jobs = Jobs.query
    if form.validate_on_submit():
        input = form.searched.data.lower()
        jobs = jobs.filter(Jobs.description.like('%' + input + '%'))
        jobs = jobs.order_by(Jobs.date_added).all()

        return render_template("search.html", form=form, searched=input, jobs=jobs)

#Users------------------------------------------------------


#admin
@app.route('/admin')
@login_required
def admin(): 
    id = current_user.id
    if id == 9:
        return render_template("admin.html")
    else:
        flash("Sorry you must be the Admin to access this page.")
        return redirect(url_for("dashboard"))
        

#create a password test page
@app.route('/test_pw', methods=['GET', 'POST'])
def test_pw():
    email = None
    password = None
    pw_to_check = None
    passed = None
    form = PasswordForm() 

    #validate form
    if form.validate_on_submit():
        
        email = form.email.data
        password = form.password_hash.data
        
        form.email.data = '' #clear the form
        form.password_hash.data = ''

        #lookup user by email address
        pw_to_check = Users.query.filter_by(email=email).first() #returns 1st result (if it exists)

        #check hashed password, returns True or False
        passed = check_password_hash(pw_to_check.password_hash, password) #passes in hashed password v. password typed into form

    return render_template("testpassword.html", email=email, 
    password=password, form=form, pw_to_check=pw_to_check, passed=passed)


#create a dashboard page
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


#Additions-to-Database----------------------------------------------


#ADDS a user to database
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    username = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data.lower()).first() #DB Slot! if there is a 'first', this means that this user is already in db
        if user is None:
            user = Users.query.filter_by(username=form.username.data.lower()).first() #DB Slot! if there is a 'first', this means that this user is already in db
            if user is None:
                hashed_pw = generate_password_hash(form.password_hash.data, "sha256")  #hash the password
                user = Users(name=form.name.data, email=form.email.data.lower(), username=form.username.data.lower(), password_hash=hashed_pw) #DB Slot! defining new user to add to db
                db.session.add(user) #adding the user
                db.session.commit()  #comitting the addition
                flash("User added successfully.")
            else:
                flash("Darn, username already exists. Please choose a unique username.")
                return redirect(url_for("add_user"))
        else:
            flash("There is an account already associated with this email.")
            return redirect(url_for("add_user"))
        username = form.username.data
        form.name.data = '' #clearing the form, name box
        form.email.data = '' #clearing the form, email box
        form.username.data = '' #clearing the form, username box
        form.password_hash.data = ''
        
    our_users = Users.query.order_by(Users.date_added.desc()) #returns everything in database
    return render_template("add_user.html", form=form, username=username, our_users=our_users) #form, username, and our_users get passed into template


#ADDS technician to database
@app.route('/technician/add', methods=['GET', 'POST'])
@login_required
def add_tech():
    name = None
    form = TechnicianForm()
    if form.validate_on_submit():
        tech = Technicians.query.filter_by(phone=form.phone.data).first() #DB Slot! if there is a 'first', this means that this user is already in db
        if tech is None:
            dispatcher = current_user.id
            tech = Technicians(name=form.name.data, phone=form.phone.data, tech_rate=form.tech_rate.data, dispatcher_id=dispatcher) #DB Slot! defining new tech to add to db
            db.session.add(tech) #adding the user
            db.session.commit()  #comitting the addition
            flash("Technician added successfully.")
        else:
            flash("Technician already exists.")
        name = form.name.data
        form.name.data = '' #clearing the form, name box
        form.phone.data = '' #clearing the form, phone box
        form.tech_rate.data = ''
        
    our_techs = Technicians.query.order_by(Technicians.date_added.desc()) #returns everything in database
    return render_template("add_tech.html", form=form, name=name, our_techs=our_techs) #form, name, and our_users get passed into template


#ADDS job to database
@app.route('/job/add', methods=['GET', 'POST'])
@login_required
def add_job():
    
    description = None
    form = JobForm()

    if form.validate_on_submit():

        description = form.description.data.lower()

        job = Jobs(address=form.address.data, contact=form.contact.data, description=description, technician=form.technician.data,
        confirmed=form.confirmed.data, open=form.open.data, job_time=form.job_time.data, notes=form.notes.data) #DB Slot! defining new user to add to db

        db.session.add(job) #adding the user
        db.session.commit()  #comitting the addition

        description = form.description.data

        form.address.data = '' #clearing the form
        form.contact.data = '' 
        form.description.data = '' 
        form.technician.data = '' 
        form.confirmed.data = '' 
        form.open.data = '' 
        form.job_time.data = '' 
        form.notes.data = '' 
        flash("Job added successfully.")

    all_jobs = Jobs.query.order_by(Jobs.date_added.desc()) #returns everything in database
    return render_template("add_job.html", form=form, description=description, all_jobs=all_jobs) 


#ADDS job by way of an incoming lead to database
@app.route('/leadtojob/add/<string:source>/<string:description>', methods=['GET', 'POST'])
@login_required
def add_lead_as_job(source, description):
    
    description_body = None
    form = JobForm()

    description = description.lower()

    form.description.data = description

    if form.validate_on_submit():

        description = form.description.data.lower()

        if bool(Jobs.query.filter_by(description=description).first()) == False: 
        
            job = Jobs(address=form.address.data, contact=form.contact.data, description=description, technician=form.technician.data,
            confirmed=form.confirmed.data, open=form.open.data, job_time=form.job_time.data, notes=form.notes.data, source=source) #DB Slot! defining new user to add to db

            db.session.add(job) #adding the user
            db.session.commit()  #comitting the addition

            description_body = form.description.data

            form.address.data = '' #clearing the form
            form.contact.data = '' 
            form.description.data = '' 
            form.technician.data = '' 
            form.confirmed.data = '' 
            form.open.data = '' 
            form.job_time.data = '' 
            form.notes.data = '' 
            flash("Job added successfully.")

        else:
            flash("Darn, looks like this job was already added.")
            return redirect(url_for("incoming_leads"))

    all_jobs = Jobs.query.order_by(Jobs.date_added.desc()) #returns everything in database
    return render_template("add_job.html", form=form, description=description_body, all_jobs=all_jobs) 


#ADDS message and displays all messages to technicians (auto and direct)
@app.route('/message/add', methods=['GET', 'POST'])
@login_required
def add_message():
    
    call_type = "generic"
    message = None
    form = MessageForm()

    if form.validate_on_submit():
        
        recipient_id = form.technician_id.data

        recip_record = Technicians.query.get_or_404(recipient_id)

        if form.job_ref.data != '':

            message = Messages(technician_id=recipient_id, tech_name=recip_record.name, phone=recip_record.phone, message_body=form.message_body.data, job_ref=form.job_ref.data, direct_message=True) 
            recip_record.last_sms_job_ref = message.job_ref            

        else:

            message = Messages(technician_id=recipient_id, tech_name=recip_record.name, phone=recip_record.phone, message_body=form.message_body.data, job_ref=0, direct_message=True) 
            #DB Slot! defining new user to add to db

        recip_record.last_sms_direct = message.message_body

        db.session.add(message) #adding the message entry to db

        db.session.commit()  #comitting the addition

        send_message(message)

        message = form.message_body.data

        form.technician_id.data = '' #clearing the form
        form.message_body.data = '' 
        form.job_ref.data = '' 
        flash("Message sent successfully.")

    all_messages = Messages.query.filter(Messages.incoming_lead == False).order_by(Messages.date_added.desc()) #returns everything in database
    return render_template("add_message.html", form=form, message=message, all_messages=all_messages, heading="All Technician Messages", call_type=call_type) 


#ADDS message and displays all messages to technicians (auto and direct); also marks a given message as "read"
@app.route('/allmessagesread/<int:message_id>', methods=['GET', 'POST'])
@login_required
def all_messages_read(message_id):

    call_type = "generic" 
    message = None
    form = MessageForm()

    heading = "All Technician Messages"

    if form.validate_on_submit():
        
        recipient_id = form.technician_id.data

        recip_record = Technicians.query.get_or_404(recipient_id)

        if form.job_ref.data != '':

            message = Messages(technician_id=recipient_id, tech_name=recip_record.name, phone=recip_record.phone, message_body=form.message_body.data, job_ref=form.job_ref.data, direct_message=True) 
            recip_record.last_sms_job_ref = message.job_ref            

        elif form.job_ref.data == '':

            message = Messages(technician_id=recipient_id, tech_name=recip_record.name, phone=recip_record.phone, message_body=form.message_body.data, job_ref=0, direct_message=True) 
            #DB Slot! defining new user to add to db

        recip_record.last_sms_direct = message.message_body

        db.session.add(message) #adding the message entry to db

        db.session.commit()  #comitting the addition

        send_message(message)

        message = form.message_body.data

        form.technician_id.data = '' #clearing the form
        form.message_body.data = '' 
        form.job_ref.data = '' 
        flash("Message sent successfully.")

    message_read = Messages.query.get_or_404(message_id)
    message_read.read = True
    db.session.add(message_read) #adding the message entry to db
    db.session.commit()
    all_messages =  Messages.query.filter(Messages.incoming_lead == False).order_by(Messages.date_added.desc())

    return render_template("add_message.html", form=form, message=message, all_messages=all_messages, heading=heading, call_type=call_type)


#ADDS a direct message (to/from technicians) to database
@app.route('/directmessage/add', methods=['GET', 'POST'])
@login_required
def add_direct_message():
    
    call_type = "generic"
    message = None
    form = MessageForm()

    if form.validate_on_submit():
        
        recipient_id = form.technician_id.data

        recip_record = Technicians.query.get_or_404(recipient_id)

        message = Messages(technician_id=recipient_id, tech_name=recip_record.name, phone=recip_record.phone, message_body=form.message_body.data, job_ref=form.job_ref.data, direct_message=True) 
        #DB Slot! defining new user to add to db

        recip_record.last_sms_direct = message.message_body

        recip_record.last_sms_job_ref = message.job_ref

        db.session.add(message) #adding the message entry to db

        db.session.commit()  #comitting the addition

        send_message(message)

        message = form.message_body.data

        form.technician_id.data = '' #clearing the form
        form.message_body.data = '' 
        form.job_ref.data = '' 
        flash("Message sent successfully.")

    all_messages =  Messages.query.filter(Messages.direct_message == 'True', Messages.incoming_lead == False).order_by(Messages.date_added.desc())

    return render_template("add_message.html", form=form, message=message, all_messages=all_messages, heading="Direct Technician Messages", call_type=call_type) #form, name, and our_users get passed into template


#ADDS a message to INCOMING LEADS to database and displays all incoming leads
@app.route('/messages/incoming/<string:phone>', methods=['GET', 'POST'])
@login_required
def incoming_messages(phone):
        
    message = None
    form = IncomingForm()

    form.phone.data = phone

    if form.validate_on_submit():

        message_to_add = Messages(technician_id=000, phone=form.phone.data, message_body=form.message_body.data, job_ref=000, direct_message=True, incoming_lead=True) 

        db.session.add(message_to_add) #adding the message entry to db

        db.session.commit()  #comitting the addition

        send_message(message_to_add)    

        message = form.message_body.data

        form.phone.data = '' #clearing the form
        form.message_body.data = ''
        flash("Message sent successfully.")

    all_messages =  Messages.query.filter(Messages.incoming_lead).order_by(Messages.date_added.desc())

    return render_template("add_incoming.html", form=form, message=message, all_messages=all_messages, heading="Incoming Leads") 


#ADDS a message to INCOMING LEADS to database and displays all incoming leads; also marks a given message as "read"
@app.route('/messages/incomingread/<string:phone>/<string:message_id>', methods=['GET', 'POST'])
@login_required
def incoming_leads_read(phone, message_id):
        
    message = None
    form = IncomingForm()

    form.phone.data = phone

    if form.validate_on_submit():

        message_to_add = Messages(technician_id=000, phone=form.phone.data, message_body=form.message_body.data, job_ref=000, direct_message=True, incoming_lead=True) 

        db.session.add(message_to_add) #adding the message entry to db

        db.session.commit()  #comitting the addition

        send_message(message_to_add)    

        message = form.message_body.data

        form.phone.data = '' #clearing the form
        form.message_body.data = ''
        flash("Message sent successfully.")

    message_read = Messages.query.get_or_404(message_id)
    message_read.read = True
    db.session.add(message_read) #adding the message entry to db
    db.session.commit()
    all_messages =  Messages.query.filter(Messages.incoming_lead).order_by(Messages.date_added.desc())

    return render_template("add_incoming.html", form=form, message=message, all_messages=all_messages, heading="Incoming Leads")


#ADDS message and displays given technician's messages 
@app.route('/messages/tech/<int:tech_id>', methods=['GET', 'POST'])
@login_required
def tech_messages(tech_id):
    
    call_type = "tech"
    message = None
    form = MessageForm()

    recipient = Technicians.query.get_or_404(tech_id)

    form.technician_id.data = tech_id

    heading = f"Messages for {recipient.name}"

    if form.validate_on_submit():
        
        recipient_id = form.technician_id.data

        recip_record = Technicians.query.get_or_404(recipient_id)

        if form.job_ref.data != '':

            message = Messages(technician_id=recipient_id, tech_name=recip_record.name, phone=recip_record.phone, message_body=form.message_body.data, job_ref=form.job_ref.data, direct_message=True) 
            recip_record.last_sms_job_ref = message.job_ref            

        elif form.job_ref.data == '':

            message = Messages(technician_id=recipient_id, tech_name=recip_record.name, phone=recip_record.phone, message_body=form.message_body.data, job_ref=0, direct_message=True) 
            #DB Slot! defining new user to add to db

        recip_record.last_sms_direct = message.message_body

        db.session.add(message) #adding the message entry to db

        db.session.commit()  #comitting the addition

        send_message(message)

        message = form.message_body.data

        form.technician_id.data = '' #clearing the form
        form.message_body.data = '' 
        form.job_ref.data = '' 
        flash("Message sent successfully.")

    all_messages =  Messages.query.filter(Messages.technician_id == tech_id, Messages.incoming_lead == False).order_by(Messages.date_added.desc())
    
    return render_template("add_message.html", form=form, message=message, all_messages=all_messages, heading=heading, call_type=call_type) #form, name, and our_users get passed into template


#ADDS message to technician and displays given technician's messages and marks a given message as "read"
@app.route('/messagesread/tech/<int:tech_id>/<int:message_id>', methods=['GET', 'POST'])
@login_required
def tech_messages_read(tech_id, message_id):

    call_type = "tech" 
    message = None
    form = MessageForm()

    recipient = Technicians.query.get_or_404(tech_id)

    form.technician_id.data = tech_id

    heading = f"Messages for {recipient.name}"

    if form.validate_on_submit():
        
        recipient_id = form.technician_id.data

        recip_record = Technicians.query.get_or_404(recipient_id)

        if form.job_ref.data != '':

            message = Messages(technician_id=recipient_id, tech_name=recip_record.name, phone=recip_record.phone, message_body=form.message_body.data, job_ref=form.job_ref.data, direct_message=True) 
            recip_record.last_sms_job_ref = message.job_ref            

        elif form.job_ref.data == '':

            message = Messages(technician_id=recipient_id, tech_name=recip_record.name, phone=recip_record.phone, message_body=form.message_body.data, job_ref=0, direct_message=True) 
            #DB Slot! defining new user to add to db

        recip_record.last_sms_direct = message.message_body

        db.session.add(message) #adding the message entry to db

        db.session.commit()  #comitting the addition

        send_message(message)

        message = form.message_body.data

        form.technician_id.data = '' #clearing the form
        form.message_body.data = '' 
        form.job_ref.data = '' 
        flash("Message sent successfully.")

    message_read = Messages.query.get_or_404(message_id)
    message_read.read = True
    db.session.add(message_read) #adding the message entry to db
    db.session.commit()
    all_messages =  Messages.query.filter(Messages.technician_id == tech_id, Messages.incoming_lead == False).order_by(Messages.date_added.desc())

    return render_template("add_message.html", form=form, message=message, all_messages=all_messages, heading=heading, call_type=call_type) 


#ADDS message and displays a given job's messages 
@app.route('/messages/job/<int:job_id>/<int:tech_id>', methods=['GET', 'POST'])
@login_required
def job_messages(job_id, tech_id):

    call_type = "job"    
    message = None
    form = MessageForm()

    form.job_ref.data = job_id

    form.technician_id.data = tech_id

    heading = f"Messages for Job #{job_id}"

    if form.validate_on_submit():
        
        recipient_id = form.technician_id.data

        recip_record = Technicians.query.get_or_404(recipient_id)

        message = Messages(technician_id=recipient_id, tech_name=recip_record.name, phone=recip_record.phone, message_body=form.message_body.data, job_ref=form.job_ref.data, direct_message=True) 
        #DB Slot! defining new user to add to db

        recip_record.last_sms_direct = message.message_body

        recip_record.last_sms_job_ref = message.job_ref

        db.session.add(message) #adding the message entry to db

        db.session.commit()  #comitting the addition

        send_message(message)

        message = form.message_body.data

        form.technician_id.data = '' #clearing the form
        form.message_body.data = '' 
        form.job_ref.data = '' 
        flash("Message sent successfully.")

    all_messages =  Messages.query.filter(Messages.job_ref == job_id, Messages.incoming_lead == False).order_by(Messages.date_added.desc())

    return render_template("add_message.html", form=form, message=message, all_messages=all_messages, heading=heading, call_type=call_type) 


#ADDS message and displays a given job's messages and mark's a given message as "read"
@app.route('/messages/job/<int:job_id>/<int:tech_id>/<int:message_id>', methods=['GET', 'POST'])
@login_required
def job_messages_read(job_id, tech_id, message_id):
        
    call_type = "job"
    message = None
    form = MessageForm()

    form.job_ref.data = job_id

    form.technician_id.data = tech_id

    heading = f"Messages for Job #{job_id}"

    if form.validate_on_submit():
        
        recipient_id = form.technician_id.data

        recip_record = Technicians.query.get_or_404(recipient_id)

        message = Messages(technician_id=recipient_id, tech_name=recip_record.name, phone=recip_record.phone, message_body=form.message_body.data, job_ref=form.job_ref.data, direct_message=True) 
        #DB Slot! defining new user to add to db

        recip_record.last_sms_direct = message.message_body

        recip_record.last_sms_job_ref = message.job_ref

        db.session.add(message) #adding the message entry to db

        db.session.commit()  #comitting the addition

        send_message(message)

        message = form.message_body.data

        form.technician_id.data = '' #clearing the form
        form.message_body.data = '' 
        form.job_ref.data = '' 
        flash("Message sent successfully.")

    message_read = Messages.query.get_or_404(message_id)
    message_read.read = True
    db.session.add(message_read) #adding the message entry to db
    db.session.commit()
    
    all_messages =  Messages.query.filter(Messages.job_ref == job_id, Messages.incoming_lead == False).order_by(Messages.date_added.desc())

    return render_template("add_message.html", form=form, message=message, all_messages=all_messages, heading=heading, call_type=call_type) 


#Display-Queries-(Minus-Messaging)-------------------------------------------------------


#displays all technicians
@app.route('/technicians', methods=['GET', 'POST'])
@login_required
def technicians():
    our_techs = Technicians.query.order_by(Technicians.date_added.desc()) #returns everything in database
    return render_template("technicians.html", our_techs=our_techs) 


#displays all jobs
@app.route('/jobs', methods=['GET', 'POST'])
@login_required
def jobs():
    all_jobs = Jobs.query.order_by(Jobs.date_added.desc()) #returns everything in database
    return render_template("jobs.html", all_jobs=all_jobs, heading="All Jobs") 


#displays technician's jobs
@app.route('/jobs/tech/<int:tech_id>', methods=['GET', 'POST'])
@login_required
def tech_jobs(tech_id):

    all_jobs =  Jobs.query.filter(Jobs.technician == tech_id).order_by(Jobs.date_added.desc()) #returns only tech's jobs
    tech = Technicians.query.get_or_404(tech_id)
    heading = f"{tech.name}'s Jobs"
    return render_template("jobs.html", all_jobs=all_jobs, heading=heading) 


#Messaging-Display-Queries--------------------------------------------------------


#displays messages to/from incoming leads  WITHOUT message form 
@app.route('/incomingleads/add', methods=['GET', 'POST'])
@login_required
def incoming_leads():
    
    all_messages =  Messages.query.filter(Messages.incoming_lead).order_by(Messages.date_added.desc())

    return render_template("incoming_leads.html", all_messages=all_messages, heading="Incoming Leads") #form, name, and our_users get passed into template


#displays messages to/from incoming leads WITHOUT message form AND marks as read
@app.route('/incomingleadsshort/add/<int:message_id>', methods=['GET', 'POST'])
@login_required
def incoming_leads_read_short(message_id):
    message = Messages.query.get_or_404(message_id)
    message.read = True
    db.session.add(message) #adding the message entry to db
    db.session.commit()
    
    all_messages =  Messages.query.filter(Messages.incoming_lead).order_by(Messages.date_added.desc())

    return render_template("incoming_leads.html", all_messages=all_messages, heading="Incoming Leads") #form, name, and our_users get passed into template


#displays all messages to technicians (auto and direct) WITHOUT message form
@app.route('/allmessages', methods=['GET', 'POST'])
@login_required
def all_messages():
    all_messages =  Messages.query.filter(Messages.incoming_lead == False).order_by(Messages.date_added.desc())
    heading = "All Technician Messages"
    url = url_for("add_message")
    return render_template("tech_messages.html", all_messages=all_messages, heading=heading, url=url) 


#displays all messages (auto and direct) WITHOUT form AND marks as read
@app.route('/allmessagesreadshort/<int:message_id>', methods=['GET', 'POST'])
@login_required
def all_messages_read_short(message_id):
    message = Messages.query.get_or_404(message_id)
    message.read = True
    db.session.add(message) #adding the message entry to db
    db.session.commit()
    all_messages =  Messages.query.filter(Messages.incoming_lead == False).order_by(Messages.date_added.desc())
    heading = "All Technician Messages"
    url = url_for("add_message")
    return render_template("tech_messages.html", all_messages=all_messages, heading=heading, url=url) 


#displays all direct technician messages
@app.route('/directmessages', methods=['GET', 'POST'])
@login_required
def direct_messages():
    all_messages =  Messages.query.filter(Messages.direct_message == 'True', Messages.incoming_lead == False).order_by(Messages.date_added.desc())
    heading = "Direct Technician Messages"
    url = url_for("add_direct_message")
    return render_template("tech_messages_direct.html", all_messages=all_messages, heading=heading, url=url) 


#displays direct messages and marks as read
@app.route('/directmessagesread/<int:message_id>', methods=['GET', 'POST'])
@login_required
def direct_messages_read(message_id):
    message = Messages.query.get_or_404(message_id)
    message.read = True
    db.session.add(message) #adding the message entry to db
    db.session.commit()
    all_messages =  Messages.query.filter(Messages.direct_message == 'True', Messages.incoming_lead == False).order_by(Messages.date_added.desc())
    heading = "Direct Technician Messages"
    url = url_for("add_direct_message")
    return render_template("tech_messages_direct.html", all_messages=all_messages, heading=heading, url=url) 


#displays a given technician's messages (WITHOUT message form) and marks a given message as "read"
@app.route('/messagesreadshort/tech/<int:tech_id>/<int:message_id>', methods=['GET', 'POST'])
@login_required
def tech_messages_read_short(tech_id, message_id):

    recipient = Technicians.query.get_or_404(tech_id)

    heading = f"Messages for {recipient.name}"

    message_read = Messages.query.get_or_404(message_id)
    message_read.read = True
    db.session.add(message_read) #adding the message entry to db
    db.session.commit()

    all_messages =  Messages.query.filter(Messages.technician_id == tech_id, Messages.incoming_lead == False).order_by(Messages.date_added.desc())
    url = url_for("add_message")
    
    return render_template("tech_messages.html", all_messages=all_messages, heading=heading, url=url) 


#displays a given job's messages (WITHOUT message form) and mark's a given message as "read"
@app.route('/messagesreadshort/job/<int:job_id>/<int:tech_id>/<int:message_id>', methods=['GET', 'POST'])
@login_required
def job_messages_read_short(job_id, tech_id, message_id):

    heading = f"Messages for Job #{job_id}"

    message_read = Messages.query.get_or_404(message_id)
    message_read.read = True
    db.session.add(message_read) #adding the message entry to db
    db.session.commit()

    all_messages =  Messages.query.filter(Messages.job_ref == job_id, Messages.incoming_lead == False).order_by(Messages.date_added.desc())
    url = url_for("add_message")
    
    return render_template("tech_messages.html", all_messages=all_messages, heading=heading, url=url) 


#Updates-to-Database----------------------------------------------------


#UPDATES user table database record
@app.route('/updateuser/<int:id>', methods=['GET', 'POST'])
@login_required
def update_user(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404(id) #queries Users table, or if it doesn't exist give a 404. Pass in user id, which gets passed into function and comes from url
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email'] 
        name_to_update.username = request.form['username']
        try:
            db.session.commit()
            flash("User updated successfully.")
            return render_template("update_user.html", form=form, name_to_update=name_to_update, id=id)
        except:
            db.session.commit()
            flash("Looks like there was a problem, please try again.")
            return render_template("update_user.html", form=form, name_to_update=name_to_update, id=id)
    else:
        return render_template("update_user.html", form=form, name_to_update=name_to_update, id=id)


#UPDATES Technicians table database record
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    form = TechnicianForm()
    name_to_update = Technicians.query.get_or_404(id) #queries Technicians table, or if it doesn't exist give a 404. Pass in user id, which gets passed into function and comes from url
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.phone = request.form['phone'] #DB Slot!
        name_to_update.tech_rate = request.form['tech_rate']
        try:
            db.session.commit()
            flash("Technician updated successfully.")
            return render_template("update_tech.html", form=form, name_to_update=name_to_update, id=id)
        except:
            db.session.commit()
            flash("Looks like there was a problem, please try again.")
            return render_template("update_tech.html", form=form, name_to_update=name_to_update, id=id)
    else:
        return render_template("update_tech.html", form=form, name_to_update=name_to_update, id=id)


#UPDATES Jobs table database record
@app.route('/updatejob/<int:id>', methods=['GET', 'POST'])
@login_required
def update_job(id):
    
    form = JobForm()
    
    job_to_update = Jobs.query.get_or_404(id) #Makes a query object: queries Jobs table, or if it doesn't exist give a 404. Pass in job id, which gets passed into function and comes from url
    
    form.description.data = job_to_update.description

    if request.method == "POST":
        job_to_update.address = request.form['address']
        job_to_update.contact = request.form['contact'] 
        job_to_update.description = request.form['description']
        job_to_update.confirmed = request.form['confirmed']
        job_to_update.open = request.form['open']
        job_to_update.job_time = request.form['job_time']
        job_to_update.notes = request.form['notes']
            
        try:
            db.session.commit()
            flash("Job updated sccessfully.")
            return render_template("update_job.html", form=form, job_to_update=job_to_update, id=id)
        except:
            db.session.commit()
            flash("Error! Looks like there was a problem, please try again.")
            return render_template("update_job.html", form=form, job_to_update=job_to_update, id=id)
    else:
        return render_template("update_job.html", form=form, job_to_update=job_to_update, id=id)


#Deletions-and-Cancelations-from-Database---------------------------------------------


#deletes user from database
@app.route('/deleteuser/<int:id>')
@login_required
def delete_user(id):
    user_to_delete = Users.query.get_or_404(id)
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User deleted successfully.")

        return render_template("dashboard.html") 

    except:
        flash("There was an issue deleting user. Try again.")
    return render_template("dashboard.html") 


#deletes technician from database
@app.route('/deletetech/<int:id>')
@login_required
def delete_tech(id):

    tech_to_delete = Technicians.query.get_or_404(id)

    try:
        db.session.delete(tech_to_delete)
        db.session.commit()
        flash("Technician deleted successfully.")
        our_techs = Technicians.query.order_by(Technicians.date_added.desc()) #returns everything in database
        return render_template("technicians.html", our_techs=our_techs) #form, name, and our_users get passed into template

    except:
        flash("There was an issue deleting user. Try again.")
    return render_template("technicians.html", our_techs=our_techs) #form, name, and our_users get passed into template


#deletes job from database
@app.route('/deletejob/<int:id>')
@login_required
def delete_job(id):
    job_to_delete = Jobs.query.get_or_404(id)
    description = None
    form = JobForm()
    try:
        db.session.delete(job_to_delete)
        db.session.commit()
        flash("Job deleted successfully.")
        all_jobs = Jobs.query.order_by(Jobs.date_added.desc()) #returns everything in database
        return render_template("jobs.html", form=form, description=description, all_jobs=all_jobs, heading="All Jobs") 

    except:
        flash("There was an issue deleting user. Try again.")
    return render_template("jobs.html", form=form, description=description, all_jobs=all_jobs, heading="All Jobs") 


#CANCELS job and notifies tech that it's canceled
@app.route('/cancelnotifyjob/<int:id>/<int:tech_id>')
@login_required
def cancel_notify_job(id, tech_id):
    job_to_cancel = Jobs.query.get_or_404(id)
    try:
        job_to_cancel.canceled = True
        db.session.add(job_to_cancel) 
        db.session.commit()
        flash("This job has been cancelled and the assigned technician was notified of this cancellation.")

        if tech_id != None:
            
            technician = Technicians.query.get_or_404(tech_id)
            job = Jobs.query.get_or_404(id)

            cancel_message(technician, job)

        all_jobs = Jobs.query.order_by(Jobs.date_added.desc()) #returns everything in database
        return render_template("jobs.html", all_jobs=all_jobs, heading="All Jobs") 

    except:
        flash("There was an issue canceling this job. Try again.")
    return render_template("jobs.html", all_jobs=all_jobs, heading="All Jobs") 


#CANCELS job 
@app.route('/canceljob/<int:id>')
@login_required
def cancel_job(id):
    job_to_cancel = Jobs.query.get_or_404(id)
    try:
        job_to_cancel.canceled = True
        db.session.add(job_to_cancel) 
        db.session.commit()
        flash("Job cancelled successfully.")

        all_jobs = Jobs.query.order_by(Jobs.date_added.desc()) #returns everything in database
        return render_template("jobs.html", all_jobs=all_jobs, heading="All Jobs") 

    except:
        flash("There was an issue canceling this job. Try again.")
    return render_template("jobs.html", all_jobs=all_jobs, heading="All Jobs") 


#UNCANCELS job 
@app.route('/uncanceljob/<int:id>')
@login_required
def uncancel_job(id):
    job_to_uncancel = Jobs.query.get_or_404(id)
    try:
        job_to_uncancel.canceled = False
        job_to_uncancel.confirmed = "Unconfirmed"
        job_to_uncancel.open = "Open"
        job_to_uncancel.technician == None
        db.session.add(job_to_uncancel) 
        db.session.commit()
        flash("Job re-established. Please reassign to a technician.")
        all_jobs = Jobs.query.order_by(Jobs.date_added.desc()) #returns everything in database
        return render_template("jobs.html", all_jobs=all_jobs, heading="All Jobs") 

    except:
        flash("There was an issue canceling this job. Try again.")
    return render_template("jobs.html", all_jobs=all_jobs, heading="All Jobs") 


#deletes incoming lead from database
@app.route('/deletelead/<int:message_id>')
@login_required
def delete_lead(message_id):

    lead_to_delete = Messages.query.get_or_404(message_id)

    try:
        db.session.delete(lead_to_delete)
        db.session.commit()
        flash("Lead deleted successfully.")

        all_messages =  Messages.query.filter(Messages.incoming_lead).order_by(Messages.date_added.desc())

        return render_template("incoming_leads.html", all_messages=all_messages, heading="Incoming Leads") #form, name, and our_users get passed into template

    except:
        flash("There was an issue deleting lead. Try again.")

    return render_template("incoming_leads.html", all_messages=all_messages, heading="Incoming Leads") #form, name, and our_users get passed into template


#Assign-And-Notification-of-Jobs---------------------------------------


#assigns job from database
@app.route('/assign/<int:job_id>')
@login_required
def assign_job(job_id):
    all_techs = Technicians.query.order_by(Technicians.date_added.desc()) #returns everything in database

    return render_template("assign_job.html", job_id=job_id, all_techs=all_techs) #form, address, and our_users get passed into template


#notifies technician of incoming job via sms message
@app.route('/jobnotify/<int:tech_id>/<int:job_id>', methods=['GET', 'POST'])
@login_required
def job_notify(tech_id, job_id):

    all_techs = Technicians.query.order_by(Technicians.date_added.desc()) #returns everything in database

    technician = Technicians.query.get_or_404(tech_id)
    job = Jobs.query.get_or_404(job_id)

    confirm_job(technician, job)

    return render_template("assign_job.html", job_id=job_id, all_techs=all_techs)


#Twillio --------------------------------------------------------

def send_message(outgoing_message): 

        account_sid = "AC96e94d05f34599669bf2c8b82558c331"  #os.environ['TWILIO_ACCOUNT_SID']
        auth_token = "e6e9e912578d5163fbef5836c8807d36"  #os.environ['TWILIO_AUTH_TOKEN']

        client = Client(account_sid, auth_token)

        message = client.messages.create(
            to=outgoing_message.phone,
            from_="+13605854201",
            body=outgoing_message.message_body,
            )

        db.session.commit()  #comitting the addition

def confirm_job(technician, job): 

        account_sid = "AC96e94d05f34599669bf2c8b82558c331"  #os.environ['TWILIO_ACCOUNT_SID']
        auth_token = "e6e9e912578d5163fbef5836c8807d36"  #os.environ['TWILIO_AUTH_TOKEN']

        client = Client(account_sid, auth_token)

        message = client.messages.create(
            to=technician.phone,
            from_="+13605854201",
            body=f"Hi {technician.name}. Are you available today for Job #{job.id}?\n\n{job.address}\n{job.description}\n{job.contact}\n{job.job_time}\n{job.notes}\n\nPlease respond '{job.id} yes' or '{job.id} no'.",
            )

        technician.last_sms_auto = message.body
        technician.last_sms_job_ref = job.id

        message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=technician.last_sms_auto, job_ref=technician.last_sms_job_ref) 
        
        db.session.add(message_to_add) #adding the message entry to db
        db.session.commit()  #comitting the addition


def close_job(technician): 

        account_sid = "AC96e94d05f34599669bf2c8b82558c331"  #os.environ['TWILIO_ACCOUNT_SID']
        auth_token = "e6e9e912578d5163fbef5836c8807d36"  #os.environ['TWILIO_AUTH_TOKEN']

        client = Client(account_sid, auth_token)

        message = client.messages.create(
            to=technician.phone,
            from_="+13605854201",
            body=f"Thank you, {technician.name}.\n\nWhat is the total amount charged to the customer for Job #{technician.last_sms_job_ref}?\n\nEnter 'C' followed by amount, e.g. if job cost $250, enter 'C250'.\n\nIf amount was billed, enter 'B250'."
            )

        technician.last_sms_auto = message.body

        message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=technician.last_sms_auto, job_ref=technician.last_sms_job_ref) 
        
        db.session.add(message_to_add) #adding the message entry to db
        db.session.commit()  #comitting the addition


def close_expenses(technician): 

        account_sid = "AC96e94d05f34599669bf2c8b82558c331"  #os.environ['TWILIO_ACCOUNT_SID']
        auth_token = "e6e9e912578d5163fbef5836c8807d36"  #os.environ['TWILIO_AUTH_TOKEN']

        client = Client(account_sid, auth_token)

        message = client.messages.create(
            to=technician.phone,
            from_="+13605854201",
            body=f"Thank you, {technician.name}.\n\nWhat is the total amount for parts/expenses for Job #{technician.last_sms_job_ref}?\n\nEnter 'P' followed by amount, e.g. if parts cost $45.50, enter 'P45.50'.\n\n"
            )

        technician.last_sms_auto = message.body

        message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=technician.last_sms_auto, job_ref=technician.last_sms_job_ref) 
        
        db.session.add(message_to_add) #adding the message entry to db
        db.session.commit()  #comitting the addition


def closing_message(technician): 

        account_sid = "AC96e94d05f34599669bf2c8b82558c331"  #os.environ['TWILIO_ACCOUNT_SID']
        auth_token = "e6e9e912578d5163fbef5836c8807d36"  #os.environ['TWILIO_AUTH_TOKEN']

        client = Client(account_sid, auth_token)

        message = client.messages.create(
            to=technician.phone,
            from_="+13605854201",
            body=f"{technician.name} thank you. Job #{technician.last_sms_job_ref} is now CLOSED."
            )

        technician.last_sms_auto = message.body

        message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=technician.last_sms_auto, job_ref=technician.last_sms_job_ref) 
        
        db.session.add(message_to_add) #adding the message entry to db

        db.session.commit() 


def cancel_message(technician, job): 

        account_sid = "AC96e94d05f34599669bf2c8b82558c331"  #os.environ['TWILIO_ACCOUNT_SID']
        auth_token = "e6e9e912578d5163fbef5836c8807d36"  #os.environ['TWILIO_AUTH_TOKEN']

        client = Client(account_sid, auth_token)

        message = client.messages.create(
            to=technician.phone,
            from_="+13605854201",
            body=f"{technician.name}, unfortunately Job #{job.id} has been canceled. You are no longer on this job."
            )

        technician.last_sms_auto = message.body

        message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=technician.last_sms_auto, job_ref=technician.last_sms_job_ref) 
        
        db.session.add(message_to_add) #adding the message entry to db

        db.session.commit()


def follow_up(job):

        account_sid = "AC96e94d05f34599669bf2c8b82558c331"  #os.environ['TWILIO_ACCOUNT_SID']
        auth_token = "e6e9e912578d5163fbef5836c8807d36"  #os.environ['TWILIO_AUTH_TOKEN']

        client = Client(account_sid, auth_token)

        message = client.messages.create(
            to=job.technician_phone,
            from_="+13605854201",
            body=f"Friendly reminder to please close Job #{job.id}.\n\nText '{job.id} done' to start the process.\n\nThank you."
            )
        
        technician = Technicians.query.get_or_404(job.technician)

        technician.last_sms_auto = message.body

        message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=technician.last_sms_auto, job_ref=job.id) 
        
        db.session.add(message_to_add) #adding the message entry to db

        db.session.commit() 


@app.route('/sms', methods=['GET', 'POST']) 
def confirm_reply():

    resp = MessagingResponse()

    body = request.values.get('Body').lower()

    if bool(Technicians.query.filter_by(phone=request.values.get('From')).first()):

        all_techs = Technicians.query.order_by(Technicians.date_added) #returns all technicians in database

        for tech in all_techs:

            if tech.phone == request.values.get('From'):

                respondant_tech_id = tech.id
                break     

        technician = Technicians.query.get_or_404(respondant_tech_id)

        if technician.last_sms_auto != None and technician.last_sms_auto != None:

            if body.split()[0].isnumeric() and 'yes' in body:

                id_of_job = body.split()[0] 

                job = Jobs.query.get_or_404(id_of_job)

                if bool(Messages.query.filter(Messages.job_ref == job.id, Messages.technician_id == technician.id).first()) and job.confirmed == 'Unconfirmed' and job.open == "Open":

                    technician.last_sms_auto = body

                    message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=body, job_ref=job.id) 
                    
                    db.session.add(message_to_add) #adding the message entry to db
                            
                    db.session.commit()  #comitting the addition

                    response = (f"{technician.name} you are now CONFIRMED for Job #{job.id}.\n\nPlease text '{job.id} done' when you complete Job #{job.id}.\n\n"
                            f"If you are not able to make it, text '{job.id} cancel'.\n\nIf you need to reach out, please text this number and someone will assist you.\n\n")

                    resp.message(response)

                    technician.last_sms_auto = response

                    message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=technician.last_sms_auto, job_ref=job.id) 
                    
                    db.session.add(message_to_add) #adding the message entry to db

                    job.confirmed = "Confirmed"
                    job.open = "Open"
                    job.technician = technician.id
                    job.technician_name = technician.name
                    job.technician_phone = technician.phone

                    db.session.commit()  #comitting the addition

                elif bool(Messages.query.filter(Messages.job_ref == job.id, Messages.technician_id == technician.id).first()) and job.confirmed == 'Confirmed':

                    response = (f"Unfortunately someone else already confirmed Job #{job.id}.")

                    resp.message(response)

                    
            elif body.split()[0].isnumeric() and 'no' in body:

                job = Jobs.query.get_or_404(body.split()[0])

                if job.technician == technician.id:

                    technician.last_sms_auto = body

                    message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=body, job_ref=technician.last_sms_job_ref) 
                    
                    db.session.add(message_to_add) #adding the message entry to db
                            
                    db.session.commit()  #comitting the addition
                            
                    response = f"Do you want to cancel Job #{job.id} that you already confirmed? Text '{job.id} cancel'."
                            
                    resp.message(response)
                            
                    technician.last_sms_auto = response

                    message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=technician.last_sms_auto, job_ref=technician.last_sms_job_ref) 
                        
                    db.session.add(message_to_add) #adding the message entry to db
                            
                    db.session.commit()  #comitting the addition
                
                else:
                                    
                    technician.last_sms_auto = body

                    message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=body, job_ref=technician.last_sms_job_ref) 
                    
                    db.session.add(message_to_add) #adding the message entry to db
                            
                    db.session.commit()  #comitting the addition

                    response = "Got it, thanks for letting us know."
                            
                    resp.message(response)
                            
                    technician.last_sms_auto = response

                    message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=technician.last_sms_auto, job_ref=technician.last_sms_job_ref) 
                        
                    db.session.add(message_to_add) #adding the message entry to db
                            
                    db.session.commit()  #comitting the addition

            elif body.split()[0].isnumeric() and 'cancel' in body:

                job = Jobs.query.get_or_404(body.split()[0])

                if job.open == "Open" and job.technician_phone == technician.phone:

                    technician.last_sms_auto = body

                    message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=body, job_ref=technician.last_sms_job_ref) 
                    
                    db.session.add(message_to_add) #adding the message entry to db
                            
                    db.session.commit()  #comitting the addition

                    response = f"Thank you, we will send Job #{job.id} to someone else."
                            
                    resp.message(response)
                            
                    technician.last_sms_auto = response

                    message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=technician.last_sms_auto, job_ref=technician.last_sms_job_ref) 
                        
                    db.session.add(message_to_add) #adding the message entry to db

                    job.confirmed = "Unconfirmed"
                    job.open = "Open"
                    job.technician = None
                    job.technician_name = None
                    job.technician_phone = None
                            
                    db.session.commit()  #comitting the addition


            elif body.split()[0].isnumeric() and 'done' in body:

                job = Jobs.query.get_or_404(body.split()[0])

                if job.open == "Open" and job.technician_phone == technician.phone:

                    technician.last_sms_auto = body

                    technician.last_sms_job_ref = job.id

                    message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=body, job_ref=job.id) 
                        
                    db.session.add(message_to_add) #adding the message entry to db
                                
                    db.session.commit()  #comitting the addition

                    close_job(technician)

                    exit()
                    
                elif job.open == 'Closed':
                    resp.message(f"Sorry, this job has already been closed.")

                else:
                    resp.message(f"Please enter correct Job #.")


            elif "What is the total amount charged" in technician.last_sms_auto and body[0] == 'c' and body.replace(" ", "")[1].isnumeric():

                job = Jobs.query.get_or_404(tech.last_sms_job_ref)

                if job.technician_phone == technician.phone:

                    technician.last_sms_auto = body

                    message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=body, job_ref=technician.last_sms_job_ref) 
                    
                    db.session.add(message_to_add) #adding the message entry to db

                    job.amt_paid = body[1:]

                    db.session.commit()

                    close_expenses(technician)

                    exit()
                
                else:
                    resp.message("Please enter correct Job #.")

            elif "What is the total amount charged" in technician.last_sms_auto and body[0] == 'b' and body.replace(" ", "")[1].isnumeric():

                job = Jobs.query.get_or_404(tech.last_sms_job_ref)

                if job.technician_phone == technician.phone:

                    technician.last_sms_auto = body

                    message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=body, job_ref=technician.last_sms_job_ref) 
                    
                    db.session.add(message_to_add) #adding the message entry to db

                    job.billed = True

                    job.amt_billed = body[1:]

                    db.session.commit()

                    close_expenses(technician)

                    exit()
                
                else:
                    resp.message("Please enter correct Job #.")

            elif "What is the total amount for parts/expenses" in technician.last_sms_auto and body[0] == 'p' and body.replace(" ", "")[1].isnumeric():

                job = Jobs.query.get_or_404(tech.last_sms_job_ref)

                if job.technician_phone == technician.phone:

                    print("you've made it this far")

                    technician.last_sms_auto = body

                    message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=body, job_ref=technician.last_sms_job_ref) 
                    
                    db.session.add(message_to_add) #adding the message entry to db

                    job.open = "Closed"

                    job.expenses = body[1:]

                    db.session.commit()

                    closing_message(technician)

                    exit()
                
                else:
                    resp.message("Please enter correct Job #.")

            
            elif technician.last_sms_auto != None:

                message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=body, job_ref=technician.last_sms_job_ref, direct_message=True) 

                db.session.add(message_to_add) #adding the message entry to db

                db.session.commit()  #comitting the addition
            
            else:

                message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=body, job_ref=technician.last_sms_job_ref, direct_message=True) 

                db.session.add(message_to_add) #adding the message entry to db

                db.session.commit()  #comitting the addition

        else:

            message_to_add = Messages(technician_id=technician.id, tech_name=technician.name, phone=technician.phone, message_body=body, job_ref=000, direct_message=True) 

            db.session.add(message_to_add) #adding the message entry to db

            db.session.commit()

    else:
        print("INCOMING LEAD!")

        incoming_phone=request.values.get('From')

        message_to_add = Messages(technician_id=000, phone=incoming_phone, message_body=body, job_ref=000, direct_message=True, incoming_lead=True) 

        db.session.add(message_to_add) #adding the message entry to db

        db.session.commit()

    return Response(str(resp)) 

#--------------------------------------------------------

#account_sid = "AC96e94d05f34599669bf2c8b82558c331"  #os.environ['TWILIO_ACCOUNT_SID']
#auth_token = "4887b09be58788f39efdf7bf3346183f"  #os.environ['TWILIO_AUTH_TOKEN']
#client = Client(account_sid, auth_token)
#message = client.messages('SM9c118b48491cefc5e7c2f55bb0db5e07').fetch()

#message = client.messages.list(limit=2)

#for record in message:
 #   last_sms_auto = record.body
  #  print(record.body)
   # print(last_sms_auto)


#home and about pages-----------------------------------------------------

#home page
@app.route('/')
def index(): 
    return render_template("index.html")

#about page
@app.route("/about") #set a route ('/' for homepage)
def about():
    return render_template("about.html")


#Database-Classes-Defined-------------------------------------------------


#create database model for Users table
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False) 
    email = db.Column(db.String(100), nullable=False) 
    username = db.Column(db.String(20), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    #Passwords:
    password_hash = db.Column(db.String(128))

    #user (dispatcher) can have many colleages
    colleagues = db.relationship('Technicians', backref='dispatcher') #creates a sort of fake column in Technicians that keeps track 

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute!')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password) #take password and generate a hash out of it

    def verify_password(self, password): #checks if hash goes w/ password
        return check_password_hash(self.password_hash, password)

    #create a string
    def __repr__(self):
        return '<Name %r>' % self.message_body #will put message on screen


#create database model for Technicians table
class Technicians(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False) #they have to fill out their name
    phone = db.Column(db.String(120), nullable=False, unique=True) #can only sign up once #DB Slot!
    email = db.Column(db.String(120), nullable=True) 
    address = db.Column(db.String(120), nullable=True)
    tech_rate = db.Column(db.Float(5), nullable=True)
    revenue = db.Column(db.Float(20), nullable=True) 
    last_sms_direct = db.Column(db.String(350), nullable=True)
    last_sms_auto = db.Column(db.String(350), nullable=True)
    last_sms_job_ref = db.Column(db.Integer, nullable=True) 
    present_job = db.Column(db.Integer, nullable=True) 
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    #foreign key to link users, which are dispatchers (refers to primary key of the user)
    dispatcher_id = db.Column(db.Integer, db.ForeignKey('users.id')) #associates with Users table in database

    #create a string
    def __repr__(self):
        return '<Name %r>' % self.name #will put name on screen

#create database model for Jobs table
class Jobs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(100), nullable=True) 
    contact = db.Column(db.String(120), nullable=True) #they have to fill out contact info 
    description = db.Column(db.String(350), nullable=False, unique=True) 
    job_time = db.Column(db.String(120), nullable=True) 
    technician = db.Column(db.Integer, nullable=True) 
    technician_name = db.Column(db.String(120), nullable=True) 
    technician_phone = db.Column(db.String(120), nullable=True) 
    confirmed = db.Column(db.String(120), nullable=True, default="Unconfirmed") #they have to fill out confirmed or not confirmed 
    open = db.Column(db.String(120), nullable=True, default="Open") 
    notes = db.Column(db.String(240), nullable=True) 
    amt_paid = db.Column(db.Float(12), nullable=True)
    amt_billed = db.Column(db.Float(12), nullable=True)
    expenses = db.Column(db.Float(12), nullable=True)
    tech_rate = db.Column(db.Float(5), nullable=True)
    billed = db.Column(db.Boolean, default=False)
    source = db.Column(db.String(120), nullable=True)
    canceled = db.Column(db.Boolean, default=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    #create a string
    def __repr__(self):
        return '<Name %r>' % self.address #will put name on screen

#create database model for Messages table
class Messages(db.Model):
    #eastern = timezone('US/Eastern')
    id = db.Column(db.Integer, primary_key=True)
    technician_id = db.Column(db.Integer) #they have to fill out
    tech_name = db.Column(db.String(50))
    phone = db.Column(db.String(15), nullable=False) 
    message_body = db.Column(db.String(500), nullable=False) 
    job_ref = db.Column(db.Integer, nullable=True) 
    sid = db.Column(db.Integer, nullable=True) 
    date_added = db.Column(db.DateTime, default=datetime.now)
    direct_message = db.Column(db.Boolean, default=False) 
    incoming_lead = db.Column(db.Boolean, default=False) 
    read = db.Column(db.Boolean, default=False) 
    
    #create a string
    def __repr__(self):
        return '<Name %r>' % self.username #will put message on screen


#Follow-Text--------------------------------------------------------


#Send follow up messages for jobs that are still open by 9PM

def followup():
    all_jobs = Jobs.query.order_by(Jobs.date_added.desc()) #returns everything in database
    for job in all_jobs:
        if job.open == "Open" and job.confirmed == "Confirmed":
            follow_up(job)

sched = BackgroundScheduler()
sched.add_job(followup, 'cron', day_of_week='mon-fri', hour=20, minute=8)

sched.start()

# Shut down the scheduler when exiting the app
#atexit.register(lambda: sched.shutdown())

#Run----------------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)