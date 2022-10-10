from datetime import datetime
import os
from twilio.rest import Client


# Find your Account SID and Auth Token at twilio.com/console
# and set the environment variables. See http://twil.io/secure
account_sid = "AC96e94d05f34599669bf2c8b82558c331"  #os.environ['TWILIO_ACCOUNT_SID']
auth_token = "4887b09be58788f39efdf7bf3346183f"  #os.environ['TWILIO_AUTH_TOKEN']
client = Client(account_sid, auth_token)


message = client.messages('SM9c118b48491cefc5e7c2f55bb0db5e07').fetch()

print(message.to)