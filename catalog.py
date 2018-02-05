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
    latest_items = session.query(Item).order_by(Item.created.desc()).limit(8)
    return render_template(
        "index.html",
        categories=categories,
        latest_items=latest_items)


@app.route('/catalog/<string:category>/items', methods=['GET'])
def showCategoryItems(category):
    if request.method == 'GET':
        cat_objs = session.query(Category).filter_by(
            name=category).first()
        if cat_objs:
            itm_objs = session.query(Item).filter(
                Item.category_id == cat_objs.id).all()
            return render_template(
                "category.html",
                category=cat_objs,
                items=itm_objs)
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
        cat_objs = session.query(Category).filter_by(
            name=category).first()
        if cat_objs:
            itm_objs = session.query(Item).filter(
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


@app.route('/login', methods=['GET'])
def showLogin():
    return render_template("login.html")


@app.route('/catalog/items/add', methods=['GET', 'POST'])
def showAddItem():
    if request.method == 'GET':
        cat_objs = session.query(Category).all()
        return render_template("item_add.html", categories=cat_objs)
    elif request.method == 'POST' and request.form['button'] == 'Save':
        newItem = Item(
            name=request.form['name'],
            category_id=request.form['category_id'],
            description=request.form['description'],
            image=request.form['image'],
            price=request.form['price'])
        session.add(newItem)
        session.commit
        return redirect('/')
    else:
        return redirect('/')


@app.route('/catalog/<string:category>/<string:item>/edit',
           methods=['GET', 'POST'])
def editItem(category, item):
    if request.method == 'GET':
        cat_objs = session.query(Category).filter_by(
            name=category).first()
        itm_objs = session.query(Item).filter(
            Item.category_id == cat_objs.id, Item.name == item).first()
        return render_template(
            "item_edit.html",
            item=itm_objs)
    elif request.method == 'POST' and request.form['button'] == 'Save':
        cat_objs = session.query(Category).filter_by(
            name=category).first()
        itm_objs = session.query(Item).filter(
            Item.category_id == cat_objs.id, Item.name == item).first()
        itm_objs.description = request.form['description']
        itm_objs.image = request.form['image']
        itm_objs.price = request.form['price']
        session.commit
        return redirect('/')
    else:
        return redirect('/')


@app.route('/catalog/<string:item>/delete',
           methods=['GET', 'POST'])
def deleteItem(item):
    if request.method == 'GET':
        itm_objs = session.query(Item).filter(
            Item.name == item).first()
        return render_template(
            "item_delete.html",
            item=itm_objs)
    elif request.method == 'POST' and request.form['button'] == 'Yes':
        itm_objs = session.query(Item).filter(
            Item.name == item).first()
        session.delete(itm_objs)
        session.commit
        return redirect('/')
    else:
        return redirect('/')


@app.route('/catalog.json',
           methods=['GET'])
def jsonCatalog():
    cat_objs = session.query(Category).all()
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
