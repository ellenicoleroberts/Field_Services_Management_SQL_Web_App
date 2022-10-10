import os
from fastapi import FastAPI, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from uvicorn import run
from twilio.rest import Client
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

origins = ["*"]
methods = ["*"]
headers = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=methods,
    allow_headers=headers
)

@app.get("/", status_code = status.HTTP_200_OK)
async def root():
    return {"message": "Hello!"}

# Below the root endpoint
@app.post("/message/send", status_code = status.HTTP_201_CREATED)
async def post_message(toNumber: str, fromNumber: str, message: str):
    if (toNumber == None or toNumber == "" or fromNumber == None or fromNumber == "" or message == None or message == ""):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing values for query parameters")

    if (toNumber[0] != "+" or fromNumber[0] != "+"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Numbers must have a + sign in front")

    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")

    if (account_sid == None and auth_token == None):
        error_detail = "Missing values for TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN\n" + "SID: " + account_sid + "\n" + "Token: " + auth_token
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_detail)
    elif (account_sid == None):
        error_detail = "Missing value for TWILIO_ACCOUNT_SID\n" + "SID: " + account_sid
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_detail)
    elif (auth_token == None):
        error_detail = "Missing value for TWILIO_AUTH_TOKEN\n" + "Token: " + auth_token
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_detail)

    client = Client(account_sid, auth_token)

    clientMessage = client.messages.create(
        body=message,
        to=toNumber,
        from_=fromNumber,
    )

    return {
        "toNumber": toNumber,
        "fromNumber": fromNumber,
        "message": message,
        "messageBody": clientMessage.body,
    }

# below tests for root endpoint
def test_post_message_success():
    toNumber = "%2B" + "19179910303"
    fromNumber = "%2B" + "13605854201"
    toNumberExpected = "+" + "19179910303"
    fromNumberExpected = "+" + "13605854201"
    message = "Hello, from Twilio and Python!"
    messageBodyExpected = "Sent from your Twilio trial account - Hello, from Twilio and Python!"

    response = client.post("/message/send?toNumber=" + toNumber + "&fromNumber=" + fromNumber + "&message=" + message)
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() == {
        "toNumber": toNumberExpected,
        "fromNumber": fromNumberExpected,
        "message": message,
        "messageBody": messageBodyExpected,
    }

def test_post_message_missing_all_query_parameters():
    response = client.post("/message/send")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

def test_post_message_missing_query_parameter():
    response = client.post("/message/send?fromNumber=01&message=Hello, from Twilio and Python!")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

def test_post_message_missing_values_query_parameters():
    response = client.post("/message/send?toNumber=&fromNumber=&message=")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "Missing values for query parameters"}

def test_post_message_missing_sign_from_number():
    response = client.post("/message/send?toNumber=00&fromNumber=01&message=Hello, from Twilio and Python!")
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "Numbers must have a + sign in front"}

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    run(app, host="0.0.0.0", port=port)