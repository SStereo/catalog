import datetime

# Recommended library when using sqlalchemy with flask
from flask_sqlalchemy import SQLAlchemy

# Required to encrypt and validate passwords for local user accounts
from passlib.apps import custom_app_context as pwd_context

# Base = declarative_base()
db = SQLAlchemy()


roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))


class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    name = db.Column(db.String(250), nullable=False)
    provider = db.Column(db.String(250), nullable=True)
    password_hash = db.Column(db.String(255))
    active = db.Column(db.Boolean(), default=True)
    confirmed_at = db.Column(db.DateTime())
    picture = db.Column(db.String(250), nullable=True)
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

# TODO: Understand properties based on Flask-login
    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
            return str(self.id)


class Category(db.Model):
    # __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    image = db.Column(db.String, nullable=True)
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    items = db.relationship(
        "Item",
        back_populates="category",
        cascade="save-update, merge, delete")

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'image': self.image,
            'created': self.created,
            'items': [o.serialize for o in self.items]
        }


class Item(db.Model):
    # __tablename__ = 'ingredients'
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(
        db.Integer,
        db.ForeignKey('category.id'),
        nullable=False)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(250), nullable=True)
    image = db.Column(db.String, nullable=True)
    price = db.Column(db.Integer, nullable=True)

    created = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    category = db.relationship('Category', back_populates='items')

    @property
    def serialize(self):
        return {
            'id': self.id,
            'category_id': self.category_id,
            'name': self.name,
            'description': self.description,
            'image': self.image,
            'price': self.price,
            'created': self.created,
        }
