from flask import Flask, request
from flask import render_template
from twilio import twiml

app = Flask(__name__)

@app.route('/sms', methods=['POST'])  #calls whenever a post request is sent to /sms url on our app
def sms():   #form encoded body of the request
    number = request.form['From']
    message_body = request.form['Body']

    resp = twiml.Response()
    resp.message('Hello {}, you said: {}'.format(number, message_body))
    return str(resp)

if __name__ == '__main__':
    app.run(debug=True)