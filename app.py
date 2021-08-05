from flask import Flask, session, abort, redirect, request
from google_auth_oauthlib.flow import Flow
import os, sys
import  pathlib
import google.auth.transport.requests
from google.oauth2 import id_token
import requests
from pip._vendor import cachecontrol
#import CacheControl

from werkzeug.utils import cached_property

app = Flask("Google login app")
app.secret_key = "TranslatorApp"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "850570751556-1d378gud5qu6dgkimism4cb4e722ji4n.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "store/client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback")

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401) # Authorization required
        else:
            return function()
    return wrapper

@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    #session['google_id'] = "Test"
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session['state'] == request.args['state']:
        abort(500) # State does not match

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    #cached_session = CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials.id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    return id_info

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/')
def index():
    return "Hello World <a href='/login'><button>Login</button></a>"

@app.route('/protected_area')
@login_is_required
def protected_area():
    return "Protected <a href='/logout'><button>Logout</button></a>"

if __name__ == '__main__':
    app.run(debug=True)