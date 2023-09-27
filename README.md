# software-lab6
OAuth2 with Okta

Integrantes:

+ Santiago Madariaga Collado
+ Juan Diego Laredo
+ Miguel Angel Alvarado 
+ Diego Enciso
+ Jean Paul Melendez Cabezas


> Codigo fuente:

En primer lugar, se utilizo un archivo .env para guardar los datos de configuracion de Okta, como se muestra a continuacion:

```python
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
```

La ruta signin redirecciona al usuario al servicio de Okta para que se autentique, y luego redirecciona al usuario a la ruta /authorization-code/callback, donde se obtiene el access token y se almacena en una cookie. Luego, se redirecciona al usuario a la ruta /profile, donde se muestra la informacion del usuario.


Ruta y funcion signin:

```python
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
```


Ruta y funcion callback:

```python
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
    if not exchange.get("token_type"):
            return "Unsupported token type. Should be 'Bearer'.", 403
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
```


Se utilizo el modulo de login de flask para manejar el login y logout del usuario. Ademas, el se creo la clase user para manejar la informacion del usuario.

```python
class User(UserMixin):

    """Custom User class."""

    def __init__(self, id_, name, email):
        self.id = id_
        self.name = name
        self.email = email

    def claims(self):
        """Use this method to render all assigned claims on profile page."""
        return {'name': self.name,
                'email': self.email}.items()

    @staticmethod
    def get(user_id):
        return USERS_DB.get(user_id)

    @staticmethod
    def create(user_id, name, email):
        USERS_DB[user_id] = User(user_id, name, email)
```


> Las evidencias se listan a continuacion

## Acess token:

![image](https://github.com/loaspra/software-lab6/assets/40249960/dc320a9d-6d5c-4815-8e27-7645dc4c92f1)

## Okta sign-in auth:

![image](https://github.com/loaspra/software-lab6/assets/40249960/d3b1f7bf-9cb4-4c08-95eb-e7ed5f8cbbfc)

## Profile information after sucess at signin:

![image](https://github.com/loaspra/software-lab6/assets/40249960/a743576b-90ff-4b96-b111-463e5b495af6)

## Accessing the logout route while not being signed in (this route requires the user to be signed in, so it can sign out. Because, you cannot sign out if you are not signed in)

![image](https://github.com/loaspra/software-lab6/assets/40249960/c43f594f-26b6-413b-a966-c9e6c999f528)
