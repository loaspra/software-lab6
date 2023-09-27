# Lab 6 (OAuth2 with Okta)
# Path: app.py
# Description:
# Basic web application that exposes a route that redirects to:
# https://dev-<okta-domain>/oauth2/default/v1/authorize?
# The actual url is : https://dev-16281537.okta.com/oauth2/default/v1/authorize?scope={openid-email-profile}&response_type=code&state=abcdefgh&client_id=0oa9dcv4g90yyHGSm5d7&redirect_uri=http://localhost:5000/authorization-code/callback

# Importing the required libraries
import base64
import hashlib
import secrets
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_cors import CORS
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from flask.json import jsonify
import requests
from datetime import timedelta
import os
from dotenv import load_dotenv

from user import User

# Loading the environment variables
load_dotenv()

# Creating the Flask app
app = Flask(__name__)
app.config.update({'SECRET_KEY': secrets.token_hex(64)})
CORS(app)

login_manager = LoginManager()
login_manager.init_app(app)

app.permanent_session_lifetime = timedelta(minutes=5)

# Okta configuration
config = {
    "auth_uri": f"https://{os.environ.get('OPENID')}/oauth2/default/v1/authorize",
    "client_id": f"{os.environ.get('CLIENT_ID')}",
    "client_secret": "fU_2a1TTP7rihO-GNf_vharRj7J_oDVjNlie_PBxrNu9KiuSOSIlDAvudbpzbgIz",
    "redirect_uri": "http://localhost:8080/authorization-code/callback",
    "issuer": f"https://{os.environ.get('OPENID')}/oauth2/default",
    "token_uri": f"https://{os.environ.get('OPENID')}/oauth2/default/v1/token",
    "userinfo_uri": f"https://{os.environ.get('OPENID')}/oauth2/default/v1/userinfo"
}


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)
@app.route("/")
def home():
    return "Hello, World!"

# Defining the login route
@app.route("/signin")
def signin():
    # session.permanent = True
    # store app state and code verifier in session
    session['app_state'] = secrets.token_urlsafe(64)
    session['code_verifier'] = secrets.token_urlsafe(64)

    print(f"Session keys at signin: {session.keys()}")

    # calculate code challenge
    hashed = hashlib.sha256(session['code_verifier'].encode('ascii')).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    code_challenge = encoded.decode('ascii').strip('=')

    # get request params
    query_params = {'client_id': config["client_id"],
                    'redirect_uri': config["redirect_uri"],
                    'scope': "openid email profile",
                    'state': session['app_state'],
                    'code_challenge': code_challenge,
                    'code_challenge_method': 'S256',
                    'response_type': 'code',
                    'response_mode': 'query'}

    # build request_uri
    request_uri = "{base_url}?{query_params}".format(
        base_url=config["auth_uri"],
        query_params=requests.compat.urlencode(query_params)
    )

    return redirect(request_uri)


@app.route("/authorization-code/callback")
def callback():

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    code = request.args.get("code")
    
    app_state = request.args.get("state")

    if app_state != session['app_state']: # Key error here
        return "Invalid state", 403

    if not code:
            return "The code wasn't returned or isn't accessible", 403
    query_params = {'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': request.base_url,
                    'code_verifier': session['code_verifier'],
                    }
    query_params = requests.compat.urlencode(query_params)

    print(f"Exchange with secret: |{config['client_secret']}|")
    exchange = requests.post(
        config["token_uri"],
        headers=headers,
        data=query_params,
        auth=(config["client_id"], config["client_secret"]),
    ).json()

    # Get tokens and validate
    # if not exchange.get("token_type"):
    #         return "Unsupported token type. Should be 'Bearer'.", 403
    print(f"Exchange: {exchange}")
    access_token = exchange["access_token"]
    id_token = exchange["id_token"]
    session['access_token'] = access_token

    # Authorization flow successful, get userinfo and sign in user
    userinfo_response = requests.get(config["userinfo_uri"],
                                    headers={'Authorization': f'Bearer {access_token}'}).json()

    unique_id = userinfo_response["sub"]
    user_email = userinfo_response["email"]
    user_name = userinfo_response["given_name"]

    user = User(
        id_=unique_id, name=user_name, email=user_email
    )

    if not User.get(unique_id):
            User.create(unique_id, user_name, user_email)

    login_user(user)

    return redirect(url_for("profile"))


# Defining the profile route
@app.route("/profile")
def profile():
    return render_template("profile.html", user=current_user)


# Define the logout route
@app.route("/signout", methods=["GET", "POST"])
@login_required
def signout():
    logout_user()
    return redirect(url_for("signin"))


# Running the app
if __name__ == "__main__":
    app.run(debug=True, port=8080)