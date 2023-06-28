
import json

import requests
from flask import session



def refresh_token_function():
    url = 'https://www.googleapis.com/oauth2/v4/token'
    credentials_info = json.loads(session['credentials'])
    # Payload data to include in the request body
    data = {
        "client_id": credentials_info["client_id"],
        "client_secret": credentials_info["client_secret"],
        "refresh_token": credentials_info["refresh_token"],
        "grant_type": "refresh_token"
    }

    # Send the POST request
    response = requests.post(url, json=data)

    return response.json()["access_token"]
