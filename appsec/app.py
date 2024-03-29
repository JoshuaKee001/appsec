from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
import os
from flask_jwt_extended import JWTManager
from functools import wraps
from flask_wtf.csrf import CSRFProtect
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required,
)
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

string_key = os.getenv('encryption_key')
key = string_key.encode()

login_manager = LoginManager()
login_manager.session_protection = "strong"
login_manager.login_view = "login"
login_manager.login_message_category = "info"

db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
limiter = Limiter(key_func=get_remote_address)
mail = Mail()
jwt = JWTManager()
csrf = CSRFProtect()
f = Fernet(key)


def create_app():
    app = Flask(__name__)

    app.secret_key = os.getenv('secret_key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('MYSQL_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    app.config['MAIL_SERVER'] = 'smtp.mailtrap.io'
    app.config['MAIL_USERNAME'] = os.environ['MAIL_USERNAME']
    app.config['MAIL_PASSWORD'] = os.environ['MAIL_PASSWORD']
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
    )
    app.config['UPLOAD_FOLDER'] = 'static/uploads/'

    login_manager.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    limiter.init_app(app)
    mail.init_app(app)
    jwt.init_app(app)
    csrf.init_app(app)

    return app


def required_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                return render_template('errors/error401.html'), 401
            return f(*args, **kwargs)
        return wrapped
    return wrapper
