import json
import logging
import os

from functools import wraps

from flask import Flask, request, jsonify, _request_ctx_stack, redirect, url_for, session
from flask_cors import cross_origin
from jose import jwt

from .aad_auth import AadAuth

# #-##-##-##-##-##-##-##-##-##-##-##-##-##-##-##
API_AUDIENCE = os.environ["API_AUDIENCE"]
TENANT_ID = os.environ["TENANT_ID"]
TENANT_NAME = os.environ["TENANT_NAME"]
SRV_APP_CLIENT_NAME = os.environ["SRV_APP_CLIENT_NAME"]
SRV_APP_CLIENT_ID = os.environ["SRV_APP_CLIENT_ID"]
SRV_APP_CLIENT_SECRET = os.environ["SRV_APP_CLIENT_SECRET"]
SESSION_SECRET_KEY = os.environ["SESSION_KEY"]
# #-##-##-##-##-##-##-##-##-##-##-##-##-##-##-##

app = Flask(__name__)
app.secret_key = SESSION_SECRET_KEY
session_token_key = "auth_token"

aad_auth = AadAuth(
        flask_app=app, 
        tenant_name= TENANT_NAME, 
        tenant_id=TENANT_ID, 
        api_audience=API_AUDIENCE, 
        srv_app_client_name=SRV_APP_CLIENT_NAME, 
        srv_app_client_id=SRV_APP_CLIENT_ID, 
        srv_app_client_secret=SRV_APP_CLIENT_SECRET
    )

@app.route("/_status", strict_slashes=False)
def status():
    # msg = _request_ctx_stack.top.current_user
    msg = {"version": "1.0.0"}
    return jsonify(message=msg)

# This needs authentication
@app.route("/authenticated")
@cross_origin(headers=['Content-Type', 'Authorization'])
@aad_auth.requires_auth
def authenticated():
    logging.info('/api endpoint')
    current_user = _request_ctx_stack.top.current_user
    user_name = current_user["name"]
    user_unique_name = current_user["unique_name"]
    msg = f"<h1>{user_name}</h1>" + \
        "</br>" + \
        f"<h2>{user_unique_name}</h2>"
    return msg

if __name__ == '__main__':
    app.run()
