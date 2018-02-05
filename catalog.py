import os  # required to have access to the Port environment variable

from flask import Flask, render_template, request, url_for, redirect, \
    flash, jsonify, send_from_directory, abort

from model import Base, Category, Item, User

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)
app.secret_key = "ABC123"

# Database connection
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


DEFAULT_ITEM_IMAGE = "https://semantic-ui.com/images/wireframe/image.png"


@app.route('/')
def homepage():
    categories = session.query(Category).all()
    latest_items = session.query(Item).order_by(Item.created).limit(8)
    return render_template(
        "index.html",
        categories=categories,
        latest_items=latest_items)


@app.route('/catalog/<string:category>/items', methods=['GET'])
def showCategoryItems(category):
    if request.method == 'GET':
        cat_objs = session.query(Category).filter_by(
            name=category).first()
        itm_objs = session.query(Item).filter(
            Item.category_id == cat_objs.id).all()
        return render_template(
            "category.html",
            category=cat_objs,
            items=itm_objs)
    else:
        return "Unsupported method"


@app.route('/catalog/<string:category>/<string:item>',
           methods=['GET'])
def showItem(category, item):
    if request.method == 'GET':
        cat_objs = session.query(Category).filter_by(
            name=category).first()
        itm_objs = session.query(Item).filter(
            Item.category_id == cat_objs.id, Item.name == item).first()
        if not itm_objs.image:
            itm_objs.image = DEFAULT_ITEM_IMAGE
        return render_template(
            "item.html",
            category=cat_objs,
            item=itm_objs)
    else:
        return "Unsupported method"


@app.route('/login', methods=['GET'])
def showLogin():
    return render_template("login.html")


@app.route('/catalog/<string:category>/<string:item>/edit',
           methods=['GET', 'POST'])
def editItem():
    return render_template("edit_item.html")


@app.route('/catalog/<string:category>/<string:item>/delete',
           methods=['GET', 'DELETE'])
def deleteItem():
    return render_template("delete_item.html")


@app.route('/catalog.json',
           methods=['GET'])
def jsonCatalog():
    return render_template("delete_item.html")


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
