from flask import Flask, Response, request
from twilio.twiml.messaging_response import MessagingResponse

app = Flask(__name__) #instance of Flask, creates an app

@app.route('/sms', methods=['GET', 'POST'])
def sms_reply():
    body = request.values.get('Body').lower()

    resp = MessagingResponse()

    if body == 'yes':
        resp.message("Great, thanks. You are now assigned to the job. Please let us know if you are not able to make it.")
    elif body == "no":
        resp.message("Got it, thanks for letting us know.")
    else:
        resp.message("Please respond 'Yes' or 'No'.")

    return Response(str(resp)) #, mimetype="application/xlml"

if __name__ == '__main__':
    app.run(debug=True)

