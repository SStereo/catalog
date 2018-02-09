# To access port variables where keys are stored
import os

# Core application libraries for flask
from flask import Flask, render_template, request, redirect, \
    jsonify, send_from_directory

# datamodel definitions
from model import db, Category, Item, User, Role

# to catch exceptions from database operations
from sqlalchemy import exc

# Basic authentication via flask-security
from flask_security import Security, SQLAlchemyUserDatastore, login_required, \
    current_user, login_user

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///catalog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db.init_app(app)

# Configurations for flask-security
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
app.config['SECURITY_PASSWORD_SALT'] = '48932hgFDF$mnk345&'
app.config['SECURITY_REGISTER_USER_TEMPLATE'] = 'security/register_user.html'
app.config['SECRET_KEY'] = "ABC123"
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_RECOVERABLE'] = True
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False

# Setup Flask-Security
security_ds = SQLAlchemyUserDatastore(db, User, Role)

app.security = Security(app, security_ds)

# default image for items
DEFAULT_ITEM_IMAGE = "https://semantic-ui.com/images/wireframe/image.png"


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
            current_user=current_user)
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
                current_user=current_user)
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
                item=itm_objs)
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
        return render_template("item_add.html", categories=cat_objs)
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
            item=itm_objs)
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
            item=itm_objs)
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
