from app import db
from flask_login import UserMixin
import jwt
import os
import base64
import onetimepass
import secrets
from time import time


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False, unique=True)
    pfpfilename = db.Column(db.String(85))
    two_factor_enabled = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    otp_secret = db.Column(db.String(32))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(secrets.token_bytes(20)).decode('utf-8')

    role = db.Column(db.String(20))
    age = db.Column(db.String(3))
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(40))
    gender = db.Column(db.String(10))
    date_joined = db.Column(db.String(50))
    doc = db.Column(db.String(60), unique=False)
    time = db.Column(db.String(30))
    remarks = db.Column(db.String(30))
    consultstate = db.Column(db.Boolean)

    card_name = db.Column(db.String(300))
    card_no = db.Column(db.Integer)
    card_exp_month = db.Column(db.Integer)
    card_exp_year = db.Column(db.Integer)

    banned = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    verified = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())

    def __repr__(self):
        return '<User %r>' % self.username

    def get_reset_token(self, expires=500):
        return jwt.encode({'reset_password': self.email, 'exp': time() + expires},
                          key=os.getenv('SECRET_KEY_FLASK'), algorithm="HS256")

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Appsec:{0}?secret={1}&issuer=2FA-Appsec' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

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
    img_file_name = db.Column(db.String(50))
    name = db.Column(db.String(100))
    price = db.Column(db.Float)
    category = db.Column(db.String(50))
    short_description = db.Column(db.String(100))
    long_description = db.Column(db.String(3000))
    stock = db.Column(db.Integer)
    
    
    
class graph(db.Model):
    __tablename__ = 'graph'

    id = db.Column(db.Integer, primary_key=True)
    gra = db.Column(db.Boolean, nullable = True)
    DATE1 = db.Column(db.String(30), nullable=True)
    DATE2 = db.Column(db.String(30), nullable=True)
    DATE3 = db.Column(db.String(30), nullable=True)
    DATE4 = db.Column(db.String(30), nullable=True)
    DATE5 = db.Column(db.String(30), nullable=True)
    COVID1 = db.Column(db.Integer, nullable = True)
    COVID2 = db.Column(db.Integer, nullable = True)
    COVID3 = db.Column(db.Integer, nullable = True)
    COVID4 = db.Column(db.Integer, nullable = True)
    COVID5 = db.Column(db.Integer, nullable = True)


