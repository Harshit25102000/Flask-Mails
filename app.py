from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
import os
import json
import urllib.parse
from mongo_connection import *
import base64
from datetime import timezone
import datetime
import pathlib
from googleapiclient.discovery import build
import requests
from flask import Flask, session, abort, redirect, request,render_template
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from utils import *
from celery import shared_task
#from celery_config import *
from tasks import *
app = Flask(__name__)
app.secret_key = "harshit25102000"
#celery = get_celery_app_instance(app)
from celery import Celery
app.config["CELERY_BROKER_URL"] = "redis://localhost:6379"
celery = Celery(app.name, broker=app.config["CELERY_BROKER_URL"])
celery.conf.update(app.config)
celery.autodiscover_tasks(['app.tasks'])
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID="629816902585-j6g98mu7u9uh03rbkp7bh6biv1lu31d3.apps.googleusercontent.com"
#client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file="client_secret.json",
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid","https://www.googleapis.com/auth/gmail.readonly"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if session.get("google_id"):
            return function()
        else:
            return abort(401)  # Authorization required

    return wrapper

@app.route("/login")
def login():
    authorization_url,state=flow.authorization_url()
    session["state"]=state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:  #match both states
        return abort(500)  # State does not match!

    credentials = flow.credentials
    credentials_json = credentials.to_json()
    session['credentials'] = credentials_json
    dt=datetime.datetime.now(timezone.utc)
    utc_time=dt.replace(tzinfo=timezone.utc)
    utc_timestamp=utc_time.timestamp()
    print(utc_timestamp)
    print(utc_time)
    print(session.get('credentials'))
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    print("---------------x-----------------")
    print(id_info)

    session["google_id"] = id_info['sub']
    session["name"] = id_info["name"]
    session["email"] = id_info["email"]
    print("session")
    print(session.get("google_id"))


    #storing in db
    print("creds",credentials_json)
    query=json.loads(credentials_json)
    query["email"]=id_info["email"]
    if cred_db.find_one({'email':id_info['email']}):
        print(cred_db.find({'email':id_info['email']}))
        cred_db.update_one({'email':id_info['email']},{"$set":query})
    else:
        cred_db.insert_one(query)


    return redirect("/protected")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/protected")
@login_is_required
def protected():
    if session.get("google_id"):
        print(session.get("id_info"))
        return render_template('logoutpage.html',name=session.get("name"))
    else:
        return "not allowed"

@app.route("/get_mails")
def get_mails():
    if 'google_id' not in session:
        return "google id missing"
    credentials_info = json.loads(session['credentials'])
    print(credentials_info)
    credentials = Credentials.from_authorized_user_info(credentials_info)
    print(credentials)
    service = build('gmail', 'v1', credentials=credentials)

    # Calculate the date range
    today = datetime.date.today()
    number_days_ago = today - datetime.timedelta(days=1)

    # Format the date range query for the 'q' parameter
    query = f'after:{number_days_ago}'

    # Get a list of the user's emails
    emails = service.users().messages().list(userId='me',maxResults=1).execute()#q=query,

    # Process and display the emails
    email_list = []
    attachment_list=[]
    attachment_db = db['attachments']
    email_content={}
    email_data=[]
    if 'messages' in emails:
        for email in emails['messages']:


            msg = service.users().messages().get(userId='me', id=email['id'],).execute()


            message_subject = ''
            message_from = ''
            message_body = ''
            # Parse the message to get the sender, subject, and body
            for header in msg['payload']['headers']:
                if header['name'] == 'From':
                    message_from = header['value']
                if header['name'] == 'Subject':
                    message_subject = header['value']
                if header['name'] == 'To':
                    message_to = header['value']
                if header['name'] == 'Date':
                    message_date = header['value']
            #print(message_from,message_to,message_date,message_subject)
            #print("message is", msg['payload']['parts'])

            # Retrieve message content
            payload = msg['payload']
            db_entries = dict()
            if 'parts' in payload:
                parts = payload['parts']

                for part in parts:
                    print("outer mime type")
                    if part['mimeType'] == 'text/plain':
                        print("mimetype")
                        data = part['body'].get('data')
                        if data:
                            print("text running")
                            text = base64.urlsafe_b64decode(data).decode('utf-8')
                            print("test",text)
                            email_content['message'] = text

                    elif part['mimeType'] == 'multipart/alternative':
                        sub_parts = part['parts']
                        for sub_part in sub_parts:
                            sub_mime_type = sub_part['mimeType']
                            if sub_mime_type == 'text/plain':
                                data = sub_part['body'].get('data')
                                if data:
                                    text = base64.urlsafe_b64decode(data).decode('utf-8')
                                    email_content['message'] = text

                    else:
                        print("else",part['mimeType'])
                        """filename = part['filename']
                        body = part['body']
                        if 'attachmentId' in body:
                            attachment = service.users().messages().attachments().get(
                                userId='me', messageId=email['id'], id=body['attachmentId']
                            ).execute()
                            file_data = base64.urlsafe_b64decode(attachment['data'])

                       

                            email_content['attachment'] = {
                                'filename': filename,
                                'data': file_data
                            }"""

            # Retrieve attachments
            if 'parts' in payload:
                parts = payload['parts']
                for part in parts:
                    if 'filename' in part:
                        filename = part['filename']
                        body = part['body']
                        if 'attachmentId' in body:


                            attachment = service.users().messages().attachments().get(
                                userId='me', messageId=email['id'], id=body['attachmentId']
                            ).execute()

                            file_data = base64.urlsafe_b64decode(attachment['data'])
                            """f = open('file.jpg', 'wb')
                            f.write(file_data)
                            f.close()"""
                            #print("data",file_data)
                            TEMP={}
                            TEMP['attachment'] = {
                                'filename': filename,
                                #'data': file_data,
                                'attachmentID':body['attachmentId']
                            }
                            attachment_list.append(TEMP)
                            attachment_content={}
                            attachment_content['filename']=filename
                            attachment_content['data']=file_data
                            attachment_content['attachmentID']=body['attachmentId']
                            attachment_content['messageID']=email['id']
                            attachment_content['emailID']=session.get("email")
                            attachment_db.insert_one(attachment_content)

            email_content["attachments"]=attachment_list

            if not email_content in email_data:
                email_data.append(email_content)
            #print("email data is ",email_data)

            #removing multiple attachments


            db_entries["from"]=message_from
            db_entries["to"]=message_to
            db_entries["subject"]=message_subject
            db_entries["date"]=message_date
            db_entries["body"]=email_data
            db_entries["emailID"] = session.get("email")
            db_entries["messageID"] = email["id"]
            mail_db = db["mails"]
            mail_db.insert_one(db_entries)


            email_list.append(msg['snippet'])


    """request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )"""




    #print(db_entries)
    return '<br>'.join(email_list)


@app.route("/refresh_token")
def refresh_token():
    token=refresh_token_function()
    print("token is", token)
    return "sab changa si"

@app.route("/celery")
def celery_test():
    func.delay()
    print("calling")

# @celery.task()
# def task_():
#     print("running")
#     print("----------------------------------------------------------------")
if __name__=="__main__":
    app.run(debug=True)
    app.config['DEBUG'] = True
    app.secret_key = "harshit25102000"
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)