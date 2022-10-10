from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SubmitField, DateField, IntegerField, FloatField, SelectField, PasswordField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length 


#create a search form for searching app
class SearchForm(FlaskForm):  #inherits FlaskForm

    searched = StringField("Searched:", validators=[DataRequired()])
    submit = SubmitField("Submit")

#create a form class for adding users
class UserForm(FlaskForm):  #inherits FlaskForm

    name = StringField("Your Name:", validators=[DataRequired()])
    email = StringField("Your Email:", validators=[DataRequired()])
    username = StringField("Username:", validators=[DataRequired()])
    password_hash = PasswordField("Password:", validators=[DataRequired(), EqualTo('password_hash2', message='Passwords must match.')])
    password_hash2 = PasswordField("Confirm Password:", validators=[DataRequired()])
    submit = SubmitField("Submit")
    
#create a form class for adding technicians
class TechnicianForm(FlaskForm):  #inherits FlaskForm

    name = StringField("Technician Name:", validators=[DataRequired()])
    phone = StringField("Phone:", validators=[DataRequired()])
    tech_rate = FloatField("Rate (numbers only, e.g. 20% should be '20'):", validators=[DataRequired()])
    submit = SubmitField("Submit")

#create a form class for adding jobs
class JobForm(FlaskForm):  #inherits FlaskForm
   
    address = StringField("Address:", validators=[DataRequired()])
    confirmed = SelectField("Confirmed:", choices = [('Unconfirmed', 'Unconfirmed'), ('Confirmed', 'Confirmed')])
    open = SelectField("Status:", choices = [('Open', 'Open'), ('Closed', 'Closed')])
    contact = StringField("Contact Phone:", validators=[DataRequired()])
    description = StringField("Description:", validators=[DataRequired()])
    #technician = SelectField("Technician ID:", choices = list)
    technician = IntegerField("Technician:")
    job_time = StringField("Scheduled time:")
    notes = StringField("Additional notes:")
    submit = SubmitField("Submit")

#create a form class for adding messages to technicians
class MessageForm(FlaskForm):  #inherits FlaskForm

    technician_id = IntegerField("Technician ID:", validators=[DataRequired()])
    job_ref = IntegerField("Job #:", validators=[DataRequired()])
    message_body = StringField("Message:", validators=[DataRequired()])
    submit = SubmitField("Submit")

#create a form class for adding incoming lead messages
class IncomingForm(FlaskForm):  #inherits FlaskForm

    phone = StringField("Contact:", validators=[DataRequired()])
    message_body = StringField("Message:", validators=[DataRequired()])
    submit = SubmitField("Submit")

#create a form class for users and their passwords
class PasswordForm(FlaskForm):  #inherits FlaskForm

    email = StringField("Your email address:", validators=[DataRequired()])
    password_hash = PasswordField("Your password:", validators=[DataRequired()])
    submit = SubmitField("Submit")

#create a form class for login
class LoginForm(FlaskForm):  #inherits FlaskForm

    username = StringField("Username:", validators=[DataRequired()])
    password = PasswordField("Password:", validators=[DataRequired()])
    submit = SubmitField("Submit")