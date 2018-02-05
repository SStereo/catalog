import datetime
from sqlalchemy import create_engine
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
# password encryption into hash
from passlib.apps import custom_app_context as pwd_context

# libraries for token generation
import random
import string
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer,
                          BadSignature,
                          SignatureExpired)

# secret key required for encrypting a token
secret_key = ''.join(
    random.choice(
        string.ascii_uppercase + string.digits) for x in range(32))

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250), nullable=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(250))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            # decrypt token using secret key
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        return user_id


class Category(Base):
    __tablename__ = 'categories'
    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    image = Column(String, nullable=True)
    created = Column(DateTime, default=datetime.datetime.utcnow)

    items = relationship(
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


class Item(Base):
    __tablename__ = 'ingredients'
    id = Column(Integer, primary_key=True)
    category_id = Column(Integer, ForeignKey('categories.id'), nullable=False)
    name = Column(String(80), nullable=False)
    description = Column(String(250), nullable=True)
    image = Column(String, nullable=True)
    price = Column(Integer, nullable=True)

    created = Column(DateTime, default=datetime.datetime.utcnow)

    category = relationship("Category", back_populates="items")

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

# insert at end of file


engine = create_engine('sqlite:///catalog.db')


Base.metadata.create_all(engine)
