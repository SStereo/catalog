# To access port variables where keys are stored
import os

# Required to extract data from a json response (e.g. facebook oauth)
import json

# Core application libraries for flask
from flask import Flask, flash, render_template, request, redirect, \
    jsonify, send_from_directory

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
from urlparse import urlparse

# own security module
from functools import wraps
# TODO: fix import from security import login_required

app = Flask(__name__)
app.secret_key = "ABC123"
app.config['UPLOAD_FOLDER'] = 'upload'
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///catalog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db.init_app(app)

# Google oauth credentials
GOOGLE_WEB_CLIENT_ID = '1036432897212-ssbkhb0al7840u8jqjv9b80124kav6bp.apps.googleusercontent.co'  # os.environ.get('GOOGLE_WEB_CLIENT_ID_TEST')
GOOGLE_CLIENT_SECRET = '92B_5pwhOGc65ymM-0a-Pw0j'  # os.environ.get('GOOGLE_WEB_CLIENT_SECRET_TEST')

# Facebook oauth credentials
FACEBOOK_APP_ID = '608608916144255'  # os.environ.get('FACEBOOK_APP_ID_TEST')
FACEBOOK_SECRET_KEY = '67eb81e39c7ff497899e4f3f56f12c5e'  # os.environ.get('FACEBOOK_SECRET_KEY_TEST')

# default image for items
DEFAULT_ITEM_IMAGE = "https://semantic-ui.com/images/wireframe/image.png"

target_url = ''

def login_required(func):

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if 'username' not in login_session:
            if request.url:
                target_url = request.url
            else:
                target_url = '/'
            print("Required to login before heading to %s" % target_url)
            # TODO: Duplicate code to showLogin, clean up!
            state = ''.join(
                random.choice(
                    string.ascii_uppercase + string.digits) for x in xrange(32))
            login_session['state'] = state
            return render_template(
                "login.html",
                STATE=state,
                G_CLIENT_ID=GOOGLE_WEB_CLIENT_ID,
                F_APP_ID=FACEBOOK_APP_ID,
                redirect_next=target_url)
        else:
            print('User already authenticated')
            return func(*args, **kwargs)
    return decorated_view


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
                     description="An excellent leather ball crafted by the superior \
                     company adidas in order to score in every game.",
                     image="https://images-eu.ssl-images-amazon.com/images/I/91pmr1GielL._SL1500_.jpg"),
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
@login_required
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
            image=request.form['image'],
            price=request.form['price'])
        db.session.add(newItem)
        db.session.commit()
        print "item added with id = %s" % newItem.category_id
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
        return render_template(
            "item_edit.html",
            item=itm_objs,
            loginSession=login_session)
    elif request.method == 'POST' and request.form['button'] == 'Save':
        cat_objs = Category.query.filter_by(
            name=category).first()
        itm_objs = Item.query.filter(
            Item.category_id == cat_objs.id, Item.name == item).first()
        itm_objs.description = request.form['description']
        itm_objs.image = request.form['image']
        itm_objs.price = request.form['price']
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
            login_session['user_id'] = createUser(login_session, password)
    return redirect('/')


@app.route('/login')
def showLogin():
    # Generate a random session id and pass it to the login template
    if request.referrer:
        redirect_next = urlparse(request.referrer)[2]
        print("Previous page was %s" % redirect_next)
        if redirect_next == '':
            redirect_next = '/'
    else:
        redirect_next = '/'

    state = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template(
        "login.html",
        STATE=state,
        G_CLIENT_ID=GOOGLE_WEB_CLIENT_ID,
        F_APP_ID=FACEBOOK_APP_ID,
        redirect_next=redirect_next)


@app.route('/reset')
def forgot_password():
    return render_template("forgot_password.html")


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
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

    # Validates if user already exists in the database
    # if not it creates a new account in the Database

    user_id = getUserID(login_session['email'])

    if not user_id:
        password = None
        login_session['user_id'] = createUser(login_session, password)
    else:
        login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: " \
        "150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])

    # TODO: add code to generate own server token to be send to client
    # token = user.generate_auth_token(600)
    # return jsonify({'token': token.decode('ascii')})

    return output


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
    if request.args.get('state') != login_session['state']:
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

    # see if user exists
    user_id = getUserID(login_session['email'])

    if not user_id:
        password = None
        user_id = createUser(login_session, password)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;" \
        "-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


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

# --------------
# User Functions


def createUser(login_session, password):
    if (login_session['provider'] == 'local'):
        newUser = User(
            name=login_session['username'],
            email=login_session['email'])

        newUser.hash_password(password)
        db.session.add(newUser)
        db.session.commit()
    else:
        newUser = User(
            name=login_session['username'],
            email=login_session['email'],
            picture=login_session['picture'])
        db.session.add(newUser)
        db.session.commit()
    return newUser.id


# Retrieves the user object
def getUserInfo(user_id):
    user = User.query.filter_by(id=user_id).one()
    return user


# Retrieves the user id based on an email
def getUserID(email):
    try:
        user = User.query.filter_by(email=email).one()
        return user.id
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
