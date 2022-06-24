from app import db
from flask_login import UserMixin
import jwt
import os
from time import time


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False, unique=True)
    role = db.Column(db.String(20))
    age = db.Column(db.String(3))

    def __repr__(self):
        return '<User %r>' % self.username

    def get_reset_token(self, expires=500):
        return jwt.encode({'reset_password': self.email, 'exp': time() + expires},
                          key=os.getenv('SECRET_KEY_FLASK'), algorithm="HS256")

    @staticmethod
    def verify_reset_token(token):
        try:
            email = jwt.decode(token, key=os.getenv('SECRET_KEY_FLASK'), algorithms="HS256")['reset_password']
            print(email)
        except Exception as e:
            print(e)
            return
        return User.query.filter_by(email=email).first()


class Product(db.Model):
    __tablename__ = "product"

    id = db.Column(db.Integer, primary_key=True)
    img_file_name = db.Column(db.String)
    name = db.Column(db.String)
    price = db.Column(db.Float)
    category = db.Column(db.String(50))
    short_description = db.Column(db.String(100))
    long_description = db.Column(db.String)
    stock = db.Column(db.Integer)
