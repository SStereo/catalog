import datetime
# from sqlalchemy import create_engine
# from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
# from sqlalchemy.ext.declarative import declarative_base
# from sqlalchemy.orm import relationship

# password encryption into hash

from flask_sqlalchemy import SQLAlchemy
from flask_security import UserMixin, RoleMixin

# Base = declarative_base()
db = SQLAlchemy()


roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))


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
