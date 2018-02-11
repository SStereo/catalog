# To access port variables where keys are stored
import os

# Required to extract data from a json response (e.g. facebook oauth)
import json

# Required for file upload to generate filename with timestamp
from datetime import datetime

# Core application libraries for flask
from flask import Flask, flash, render_template, request, redirect, \
    jsonify, send_from_directory, abort

# required for file upload
from werkzeug.utils import secure_filename

# datamodel definitions
from model import db, Category, Item, User, Role

# to catch exceptions from database operations
from sqlalchemy import exc

# Social login
from oauth2client.client import OAuth2WebServerFlow  # flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests
import random
import string
from flask import session as login_session  # a dictionary to store information

# Required to identify the path within an URL, for referrer after login
# in python 3 use: from urllib.parse import urlparse
from urlparse import urlparse, parse_qs

# own security module
from functools import wraps
# TODO: fix import from security import login_required

app = Flask(__name__)
app.secret_key = "ABC123"
app.config['UPLOAD_FOLDER'] = 'upload'
app.config['ALLOWED_FILE_EXTENSIONS'] = set(
    ['pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///catalog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db.init_app(app)

# Google oauth credentials
GOOGLE_WEB_CLIENT_ID = \
    'your apps google client id'
GOOGLE_CLIENT_SECRET = 'your google client secret'

# Facebook oauth credentials
FACEBOOK_APP_ID = 'facebook app id'
FACEBOOK_SECRET_KEY = 'your facebooks app id'

# default image for items
DEFAULT_ITEM_IMAGE = "https://semantic-ui.com/images/wireframe/image.png"

target_url = ''


def login_required(func):

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if 'user_id' not in login_session:
            return login()
        else:
            return func(*args, **kwargs)
    return decorated_view


def login(*args):
    if args:
        message = args[0]
    else:
        message = None

    # Setup CSRF Protection
    app.jinja_env.globals['csrf_token'] = generate_csrf_token()

    if request.referrer:
        previous_url = urlparse(request.referrer)[2]
    else:
        previous_url = '/'
    target_url = request.url
    if not target_url or previous_url == '/':
        target_url = '/'
    return render_template(
        "login.html",
        G_CLIENT_ID=GOOGLE_WEB_CLIENT_ID,
        F_APP_ID=FACEBOOK_APP_ID,
        redirect_next=target_url,
        message=message)


def validateUser(login_session):
    '''
    After successfuly 3rd party authentication checks if user
    is authorized to access the application. Creates a user object if
    necessary.
    '''
    # Validates if user exists and creates if necessary
    user = getUser(login_session['email'])
    if not user:
        password = None
        user = createUser(login_session, password)

    if not user.active:
        return False  # user is not authorized
    else:
        login_session['user_id'] = user.id
        login_session['provider'] = user.provider
        return True  # user is authorized


def welcome():
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;" \
        "-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    return output


@app.before_first_request
def setup():
    # Checks if database exists and generates it if not
    try:
        categories = Category.query.all()
    except exc.OperationalError as err:
        if err.args[0].find("no such table") > 0:
            db.drop_all()
            db.create_all()
            print "Database generated"
            obj_categories = [
                Category(name="Soccer",
                         image="http://questkermodes.com/"
                         "general/2017-18/soccer_generic.jpg"),
                Category(name="Basketball"),
                Category(name="Baseball"),
                Category(name="Frisbee"),
                Category(name="Snowboarding"),
                Category(name="Rock Climbing"),
                Category(name="Foosball"),
                Category(name="Skating"),
                Category(name="Hockey")
            ]

            obj_items = [
                Item(name="ball",
                     category=obj_categories[0],
                     price=129,
                     description="An excellent leather ball crafted by \
                     adidas in order to score in every game.",
                     image="soccer-ball.jpg"),
                Item(name="cap", category=obj_categories[1],
                     description="Does not matter how hot the sun in shining, \
                     with this cap you allways have a clear sight."),
                Item(name="tools",
                     category=obj_categories[4],
                     description="All tools that you need to wax and \
                     to clean your snowboard."),
                Item(name="bag", category=obj_categories[6]),
                Item(name="magazine", category=obj_categories[3]),
                Item(name="bells", category=obj_categories[2]),
                Item(name="towel", category=obj_categories[1]),
                Item(name="sword", category=obj_categories[1]),
                Item(name="ring", category=obj_categories[0]),
                Item(name="book", category=obj_categories[8]),
                Item(name="DVD", category=obj_categories[2]),
                Item(name="pump", category=obj_categories[3]),
                Item(name="knife", category=obj_categories[3]),
                Item(name="cream", category=obj_categories[3]),
            ]
            db.session.add_all(obj_categories)
            db.session.add_all(obj_items)
            db.session.commit()
            return "DB setup with initial data"


@app.route('/')
def homepage():
    try:
        categories = Category.query.all()
        latest_items = Item.query.order_by(Item.created.desc()).limit(8)
        return render_template(
            "index.html",
            categories=categories,
            latest_items=latest_items,
            loginSession=login_session)
    except exc.OperationalError as err:
        if err.args[0].find("no such table") > 0:
            return redirect('/setup')
        else:
            return err.args


@app.route('/catalog/<string:category>/items', methods=['GET'])
def showCategoryItems(category):
    if request.method == 'GET':
        cat_objs = Category.query.filter_by(
            name=category).first()
        if cat_objs:
            itm_objs = Item.query.filter(
                Item.category_id == cat_objs.id).all()
            return render_template(
                "category.html",
                category=cat_objs,
                items=itm_objs,
                loginSession=login_session)
        else:
            return jsonify({
                'Message': "Category %s does not exist" % category,
                'Status': 'Error'})
    else:
        return "Unsupported method"


@app.route('/catalog/<string:category>/<string:item>',
           methods=['GET'])
def showItem(category, item):
    if request.method == 'GET':
        cat_objs = Category.query.filter_by(
            name=category).first()
        if cat_objs:
            itm_objs = Item.query.filter(
                Item.category_id == cat_objs.id, Item.name == item).first()
        else:
            return jsonify({
                'Message': "Category %s does not exist" % category,
                'Status': 'Error'})
        if itm_objs:
            if not itm_objs.image:
                itm_objs.image = DEFAULT_ITEM_IMAGE
            return render_template(
                "item.html",
                category=cat_objs,
                item=itm_objs,
                loginSession=login_session)
        else:
            return jsonify({
                'Message': "Item %s does not exist" % item,
                'Status': 'Error'})
    else:
        return jsonify({
            'Message': "This http method is not supported",
            'Status': 'Error'})


@app.route('/catalog/items/add', methods=['GET', 'POST'])
@login_required
def showAddItem():
    if request.method == 'GET':
        cat_objs = Category.query.all()
        return render_template(
            "item_add.html",
            categories=cat_objs,
            loginSession=login_session)
    elif request.method == 'POST' and request.form['button'] == 'Save':
        newItem = Item(
            name=request.form['name'],
            category_id=request.form['category_id'],
            description=request.form['description'],
            image=fileHandler(request),
            price=request.form['price'])
        db.session.add(newItem)
        db.session.commit()
        print("Filename %s" % newItem.image)
        return redirect('/')
    else:
        return redirect('/')


@app.route('/catalog/<string:category>/<string:item>/edit',
           methods=['GET', 'POST'])
@login_required
def editItem(category, item):
    if request.method == 'GET':
        cat_objs = Category.query.filter_by(
            name=category).first()
        itm_objs = Item.query.filter(
            Item.category_id == cat_objs.id, Item.name == item).first()
        cat_objs = Category.query.all()
        return render_template(
            "item_edit.html",
            item=itm_objs,
            categories=cat_objs,
            loginSession=login_session)
    elif request.method == 'POST' and request.form['button'] == 'Save':
        cat_objs = Category.query.filter_by(
            name=category).first()
        itm_objs = Item.query.filter(
            Item.category_id == cat_objs.id, Item.name == item).first()
        itm_objs.name = request.form['name']
        itm_objs.description = request.form['description']
        file_name = fileHandler(request)
        if not file_name == '':
            itm_objs.image = file_name
        itm_objs.price = request.form['price']
        itm_objs.category_id = request.form['category_id']
        db.session.commit()
        return redirect('/')
    else:
        return redirect('/')


@app.route('/catalog/<string:item>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteItem(item):
    if request.method == 'GET':
        itm_objs = Item.query.filter(
            Item.name == item).first()
        return render_template(
            "item_delete.html",
            item=itm_objs,
            loginSession=login_session)
    elif request.method == 'POST' and request.form['button'] == 'Yes':
        itm_objs = Item.query.filter(
            Item.name == item).first()
        db.session.delete(itm_objs)
        db.session.commit()
        return redirect('/')
    else:
        return redirect('/')


@app.route('/catalog.json',
           methods=['GET'])
def jsonCatalog():
    cat_objs = Category.query.all()
    return jsonify(Catalog=[o.serialize for o in cat_objs])


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in \
           app.config['ALLOWED_FILE_EXTENSIONS']


def fileHandler(request):
    '''
    Validates file within request, generates a random name for the file
    and stores it in the upload folder and returns the name of the file
    '''
    filename = ""
    if 'file' not in request.files:
        print("no file in request.files")
        return filename

    file = request.files['file']
    # if user does not select file, browser also
    # submit a empty part without filename
    if file.filename == '':
        print('Filename of uploaded file is empty')
        return filename
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        now = datetime.now()
        filename = "%s.%s" % (
            now.strftime("%Y-%m-%d-%H-%M-%S-%f"),
            filename.rsplit('.', 1)[1])
        filepath = os.path.join(
            app.config['UPLOAD_FOLDER'],
            "%s.%s" % (now.strftime("%Y-%m-%d-%H-%M-%S-%f"),
                       file.filename.rsplit('.', 1)[1]))
        print("filename = " + filename)
        file.save(filepath)
        return filename


# ---------------------------------------------
# Security endpoints

@app.route('/register', methods=['GET', 'POST'])
def showRegister():
    if request.method == 'GET':
        return render_template("register.html")
    elif request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if username is None or email is None or password is None:
            abort(400)
        if 'email' in login_session.keys():
            abort(400)  # existing User
        else:
            login_session['username'] = username
            login_session['email'] = email
            login_session['provider'] = 'local'
            user = createUser(login_session, password)
            validateUser(login_session)
    return redirect('/')


@app.route('/login', methods=['GET', 'POST'])
def showLogin():
    if request.method == 'GET':
        return login()
    elif request.method == 'POST':
        login_session['email'] = request.form['email']
        password = request.form['password']
        user = getUser(login_session['email'])
        if not user:
            return login("Unknown username or incorrect password")
        else:
            if user.verify_password(password) and validateUser(login_session):
                flash("User successfully logged in")
                return redirect('/')
            else:
                return login("Unknown username or incorrect password")


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['_csrf_token']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = OAuth2WebServerFlow(
            client_id=GOOGLE_WEB_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            scope='',
            redirect_uri='postmessage')

        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        print("Failed to upgrade the authorization code")
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != GOOGLE_WEB_CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # Validate user against database
    if validateUser(login_session):
        output = welcome()
        flash("Now logged in as %s" % login_session['username'])
        return output
    else:
        flash('User is not authorized to access this application')
        return False


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

        # TODO: Logout / disconnect does not work correctly unless
        # the browser is closed / the cookie is no longer valid
        # at the moment it will show as failed to revoke token
        # with a status 400 from google
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['_csrf_token']:
        response = make_response(json.dumps(
            'Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data.decode("utf-8")
    print("access token: %s" % access_token)
    url = 'https://graph.facebook.com/oauth/access_token?' \
        'grant_type=fb_exchange_token&client_id=%s&' \
        'client_secret=%s&fb_exchange_token=%s' % (FACEBOOK_APP_ID,
                                                   FACEBOOK_SECRET_KEY,
                                                   access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1].decode("utf-8")

    print("Exchange token result: %s" % result)
    # Use token to get user info from API
    # userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token
        exchange we have to split the token first on commas and select the
        first index which gives us the key : value for the server access token
        then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used
        directly in the graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me' \
        '?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print("url sent for API access:%s" % url)
    print("API JSON result: %s" % result)
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture' \
        '?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data["data"]["url"]

    # Validate user against database
    if validateUser(login_session):
        output = welcome()
        flash("Now logged in as %s" % login_session['username'])
        return output
    else:
        flash('User is not authorized to access this application')
        return False


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' \
        % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect based on provider
@app.route('/logout')
def showLogout():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
            del login_session['picture']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
            del login_session['access_token']
            del login_session['picture']
        del login_session['username']
        del login_session['email']
        del login_session['user_id']
        del login_session['provider']
        print("You have successfully been logged out.")
        return redirect('/')
    else:
        print("You were not logged in")
        return redirect('/')


@app.before_request
def csrf_protect():
    '''
    Aborts any post request if csrf token in the form does not match the
    csrf token stored in the session
    '''
    if request.method == "POST":
        token = login_session['_csrf_token']  # .pop('_csrf_token', None)
        # when token submitted from hidden field in forms
        token_from_form = request.form.get('_csrf_token')
        print("token_from_form %s" % token_from_form)
        # when token submitted via ajax post request during 3rd party oauth
        if 'state' in parse_qs(urlparse(request.url).query):
            utoken_from_qs = parse_qs(urlparse(request.url).query)['state']
            token_from_qs = utoken_from_qs[0].encode('ascii', 'ignore')
            print("token_from_qs %s" % token_from_qs)
        else:
            token_from_qs = ''
        if not token:
            abort(403)
        elif (token != token_from_form) and (token != token_from_qs):
            abort(403)


def generate_csrf_token():
    if '_csrf_token' not in login_session:
        login_session['_csrf_token'] = ''.join(
            random.choice(
                string.ascii_uppercase + string.digits) for x in xrange(32))
    return login_session['_csrf_token']

# --------------
# User Functions
def createUser(login_session, password):
    if (login_session['provider'] == 'local'):
        newUser = User(
            name=login_session['username'],
            email=login_session['email'],
            provider=login_session['provider'])
        print('Create new local user')
        newUser.hash_password(password)
        db.session.add(newUser)
        db.session.commit()
    else:
        newUser = User(
            name=login_session['username'],
            email=login_session['email'],
            picture=login_session['picture'],
            provider=login_session['provider'])
        db.session.add(newUser)
        db.session.commit()
    return newUser


# Retrieves the user object
def getUserInfo(user_id):
    user = User.query.filter_by(id=user_id).one()
    return user


# Retrieves the user based on an email
def getUser(email):
    try:
        user = User.query.filter_by(email=email).one()
        return user
    except:
        return None


# Custom Static sub folders
@app.route('/css/<path:filename>')
def css_static(filename):
    return send_from_directory('static/css', filename)


@app.route('/js/<path:filename>')
def js_static(filename):
    return send_from_directory('static/js', filename)


@app.route('/font/<path:filename>')
def font_static(filename):
    return send_from_directory('static/font', filename)


@app.route('/img/<path:filename>')
def img_static(filename):
    return send_from_directory('static/img', filename)


@app.route('/upload/<path:filename>')
def upload_static(filename):
    return send_from_directory('upload', filename)


if __name__ == '__main__':
    app.debug = True
    port = int(os.environ.get('PORT', 8000))
    app.run(host='', port=port)
