from email.quoprimime import body_check
import os
from twilio.rest import Client

from flask_sqlalchemy import SQLAlchemy


def confirm_job(technician, job): 

        account_sid = "AC96e94d05f34599669bf2c8b82558c331"  #os.environ['TWILIO_ACCOUNT_SID']
        auth_token = "4887b09be58788f39efdf7bf3346183f"  #os.environ['TWILIO_AUTH_TOKEN']

        client = Client(account_sid, auth_token)

        message = client.messages.create(
            to=technician.phone,
            from_="+13605854201",
            body=f"Hi {technician.name}. Are you available today for Job #{job.id}?\n{job.address}\n{job.description}\n{job.contact}\nPlease respond 'Yes' or 'No'.",
            )

        technician.last_sms = message.body
        technician.last_sms_job_ref = job.id

        db.session.commit() 
        
        print(f"The last SMS is: {technician.last_sms} sent to {technician.name} and the job # is {technician.last_sms_job_ref}.")


def job_fee(technician, tech_no): 

    account_sid = "AC96e94d05f34599669bf2c8b82558c331"  #os.environ['TWILIO_ACCOUNT_SID']
    auth_token = "4887b09be58788f39efdf7bf3346183f"  #os.environ['TWILIO_AUTH_TOKEN']

    client = Client(account_sid, auth_token)

    message = client.messages.create(
        to="+19179910303",
        from_="+13605854201",
        body=f"{technician} Thank you for completing the job. What is the total amount paid by the customer?"
    )
    


