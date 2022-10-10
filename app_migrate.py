from distutils.command.install_egg_info import to_filename
from unicodedata import name
from flask import Flask, Response, request
from twilio.twiml.messaging_response import MessagingResponse
from flask import render_template, flash
from twilio import twiml

import os
from twilio.rest import Client

from send_sms import *
from receive_sms import *

from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField 
from wtforms.validators import DataRequired 

from numpy import random

from flask_migrate import Migrate 




app = Flask(__name__) #instance of Flask, creates an app

app.config['SECRET_KEY'] = "Simple Simply Simplifies"

#--------------------------------------------------------
#add database
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

#add database
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://nicoleroberts:Simple0922!@localhost/SimpleDB' #root is MySQL username from download and password likewise. 'users' is my name of db.
#initialize the database
db = SQLAlchemy(app) 
migrate = Migrate(app, db)

#create database model
class Technicians(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False) #they have to fill out their name
    email = db.Column(db.String(120), nullable=False, unique=True) #can only sign up once
    phone = db.Column(db.String(120)) #can only sign up once
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    
    #create a string
    def __repr__(self):
        return '<Name %r>' % self.name #will put name on screen

#create database model
class Users(db.Model):
    jobID = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(50), nullable=False) #they have to fill out address
    contact = db.Column(db.String(120), nullable=False) #they have to fill out contact info 
    description = db.Column(db.String(120), nullable=True) 
    time = db.Column(db.DateTime, default=datetime.utcnow) 
    technician = db.Column(db.String(120), nullable=True) 
    confirmed = db.Column(db.Boolean(120), nullable=False) #they have to fill out confirmed or not confirmed 
    status = db.Column(db.Boolean(120), nullable=True) 
    notes = db.Column(db.String(120), nullable=True) 
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    #create a string
    def __repr__(self):
        return '<Name %r>' % self.name #will put name on screen


#create a form class
class UserForm(FlaskForm):  #inherits FlaskForm
    name = StringField("Technician name:", validators=[DataRequired()])
    email = StringField("Email:", validators=[DataRequired()])
    phone = StringField("Phone:")
    submit = SubmitField("Submit")

#ADDS user to database
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        user = Test.query.filter_by(email=form.email.data).first() #if there is a 'first', this means that this user is already in db
        if user is None:
            user = Test(name=form.name.data, email=form.email.data, phone=form.phone.data) #defining new user to add to db
            db.session.add(user) #adding the user
            db.session.commit()  #comitting the addition
        name = form.name.data
        form.name.data = '' #clearing the form, name box
        form.email.data = '' #clearing the form, email box
        form.phone.data = '' #clearing the form, phone box
        flash("User added successfully!")
    our_users = Test.query.order_by(Test.date_added) #returns everything in database
    return render_template("add_user_migrate.html", form=form, name=name, our_users=our_users) #form, name, and our_users get passed into template

#UPDATES database record
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    form = UserForm()
    name_to_update = Test.query.get_or_404(id) #queries Test table, or if it doesn't exist give a 404. Pass in user id, which gets passed into function and comes from url
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.phone = request.form['phone']
        try:
            db.session.commit()
            flash("User updated sccessfully.")
            return render_template("update_migrate.html", form=form, name_to_update=name_to_update)
        except:
            db.session.commit()
            flash("Error! Looks like there was a problem, please try again.")
            return render_template("update_migrate.html", form=form, name_to_update=name_to_update)
    else:
        return render_template("update_migrate.html", form=form, name_to_update=name_to_update)



#--------------------------------------------------------

@app.route('/')
def index(): 
    return render_template("index.html")

@app.route("/about") #set a route ('/' for homepage)
def about():
    return render_template("about.html")

@app.route('/index2')
def index2():
    list = ["nicole","shelley",3,4,5]  #you can pass in anything, e.g. a DF
    first_name = "Sally"
    stuff = "This is <strong>bold text</strong>."

    return render_template("index2.html", 
        first_name=first_name,
        list=list,
        stuff=stuff)

@app.route('/incoming')
def hello():
    return 'Incoming Texts'

@app.route('/user/<name>')
def user(name):
    return render_template("user.html", user_name=name)

@app.route('/create/', methods=('GET', 'POST'))
def create():
    return render_template('create.html')


#--------------------------------------------------------

friday = False 

#--------------------------------------------------------

if friday:

    account_sid = "AC96e94d05f34599669bf2c8b82558c331"  #os.environ['TWILIO_ACCOUNT_SID']
    auth_token = "4887b09be58788f39efdf7bf3346183f"  #os.environ['TWILIO_AUTH_TOKEN']

    technician_dic = {"Aarchit": '+19179910303'} #13479710623, "Kfir Bar": '+14049335903', "Allen Roberts": '+16023773344'}

    #for technician, phone in technician_dic.items():

    #confirm_job(technician, phone)
    confirm_job("Nicole", "+19179910303")

    @app.route('/sms', methods=['GET', 'POST'])
    def confirm_reply():

        confirmed = False

        body = request.values.get('Body').lower()

        resp = MessagingResponse()

        if body == 'yes' and confirmed == False:

            confirmed = True

            jobID = random.randint(100000)

            print(jobID)

            print(confirmed)

            confirmed_tech = request.values.get('From').lower()

            print(confirmed_tech)

            if confirmed_tech == '+19179910303':
                tech = "Nicole"
                email = 'nlr@19111300.com'
                print(tech)

            if confirmed_tech == '+13479710623':
                tech = "Aarchit"
                email = 'aarchit@1930.com'
                print(tech)

            if confirmed_tech == 'Kfir Bar':
                email = 'kfir@gmail.com'

            if confirmed_tech == 'Allen Roberts':
                email = 'ajr@ajr-industrial.com'

            resp.message(f"{tech} you are now CONFIRMED for Job #{jobID}.\n\nPlease text 'Done' when you complete the job.\n\n"
            "If you are not able to make it, or need to reach out, please text this number and someone will assist you.\n\n")

            user = Test(name=tech, email=email) #defining new user to add to db
            db.session.add(user) #adding the user
            db.session.commit()  #comitting the addition

                         
            
        elif body == "no" and confirmed == False:
                
            #confirmed = False
            resp.message("Got it, thanks for letting us know.")

        elif confirmed == False:

            #confirmed = False
            resp.message("Please respond 'Yes' or 'No'.")

        else:
            return

        return Response(str(resp)) #, mimetype="application/xlml"
    
friday = False
#--------------------------------------------------------

account_sid = "AC96e94d05f34599669bf2c8b82558c331"  #os.environ['TWILIO_ACCOUNT_SID']
auth_token = "4887b09be58788f39efdf7bf3346183f"  #os.environ['TWILIO_AUTH_TOKEN']
client = Client(account_sid, auth_token)
#message = client.messages('SM9c118b48491cefc5e7c2f55bb0db5e07').fetch()

message = client.messages.list(limit=2)

for record in message:
    last_sms = record.body
    print(record.body)
    print(last_sms)




if __name__ == '__main__':
    app.run(debug=True)
