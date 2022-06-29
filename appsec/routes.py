from hashlib import new
from sre_constants import CH_LOCALE
from flask import (
    Flask,
    render_template,
    redirect,
    flash,
    url_for,
    session
)

from datetime import timedelta
from sqlalchemy.exc import (
    IntegrityError,
    DataError,
    DatabaseError,
    InterfaceError,
    InvalidRequestError,
)
from werkzeug.routing import BuildError


from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash

from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required,
)

from app import create_app, db, login_manager, bcrypt, limiter, mail, jwt, required_roles
from models import User, Product
from forms import LoginForm, SignUpForm, ChangePasswordForm, EditInfoForm, ForgotPasswordForm, ResetPasswordForm, CreateProductForm, createConsultationForm
from functions import send_password_reset_email


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


app = create_app()


@app.before_request
def session_handler():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=1)


@app.after_request
def add_header(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response


@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("home.html")


@app.route('/login' , methods=["GET", "POST"])
@limiter.limit("2/second")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()

    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data.lower()).first()
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash("Invalid Username or password!", "danger")
        except Exception as e:
            flash("Wrong username or password", "danger")

    return render_template('user/guest/login.html', form=form)


@app.route('/signup', methods=["GET", "POST"])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        try:
            username = form.username.data
            email = form.email.data.lower()
            password = form.password.data

            newuser = User(username=username, email=email, password=bcrypt.generate_password_hash(password))

            db.session.add(newuser)
            db.session.commit()
            flash(f"Account Succesfully created", "success")
            return redirect(url_for("login"))

        except InvalidRequestError:
            db.session.rollback()
            flash(f"Something went wrong!", "danger")
        except IntegrityError:
            db.session.rollback()
            flash(f"User already exists!.", "warning")
        except DataError:
            db.session.rollback()
            flash(f"Invalid Entry", "warning")
        except InterfaceError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except DatabaseError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except BuildError:
            db.session.rollback()
            flash(f"An error occured !", "danger")

    return render_template('user/guest/signup.html', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/user', methods=['GET', 'POST'])
@login_required
def user():
    return render_template('user/loggedin/useraccount.html', name=current_user)


@app.route('/change_password', methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        user = current_user
        old_password = form.old_password.data
        new_password = form.new_password.data

        if check_password_hash(user.password, old_password) and not check_password_hash(user.password, new_password):

            user.password = bcrypt.generate_password_hash(new_password)
            db.session.commit()
            flash(f"Password has been changed, please log in again", "success")
            logout_user()
            return redirect(url_for('login'))
        
        elif check_password_hash(user.password, new_password):
            flash(f"New password cant be same as old password", "warning")

        elif not check_password_hash(user.password, old_password):
            flash(f"Old password is wrong", "warning")

    return render_template('/user/loggedin/user_password_edit.html', form=form)


@app.route('/edit_info', methods=["GET", "POST"])
@login_required
def edit_info():
    form = EditInfoForm()

    if form.validate_on_submit():
        try:
            user = current_user
            user.email = form.new_email.data
            user.username = form.new_username.data
            db.session.commit()
            flash(f"Info has been updated", "success")
            return redirect(url_for('user'))

        except InvalidRequestError:
            db.session.rollback()
            flash(f"Something went wrong!", "danger")
        except IntegrityError:
            db.session.rollback()
            flash(f"User already exists!.", "warning")
        except DataError:
            db.session.rollback()
            flash(f"Invalid Entry", "warning")
        except InterfaceError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except DatabaseError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except BuildError:
            db.session.rollback()
            flash(f"An error occured !", "danger")

    return render_template('user/loggedin/user_info_edit.html', form=form)


@app.route('/forgot_password', methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            send_password_reset_email(user)
        else:
            pass

        flash(f"Email sent", "info")

    return render_template('user/guest/passwordforget.html', form=form)


@app.route('/reset_password/<token>', methods=["GET", "POST"])
def reset_password(token):
    form = ResetPasswordForm()

    user = User.verify_reset_token(token)

    if user:

        if form.validate_on_submit():
            try:
                user.password = bcrypt.generate_password_hash(form.new_password.data)
                db.session.commit()
                flash(f"Password has been reset", "info")
                return redirect(url_for('login'))

            except InvalidRequestError:
                db.session.rollback()
                flash(f"Something went wrong!", "danger")
            except IntegrityError:
                db.session.rollback()
                flash(f"User already exists!.", "warning")
            except DataError:
                db.session.rollback()
                flash(f"Invalid Entry", "warning")
            except InterfaceError:
                db.session.rollback()
                flash(f"Error connecting to the database", "danger")
            except DatabaseError:
                db.session.rollback()
                flash(f"Error connecting to the database", "danger")
            except BuildError:
                db.session.rollback()
                flash(f"An error occured !", "danger")

    return render_template('/user/guest/passwordreset.html', form=form, user=user)


@app.route('/staffinvent/<int:page>', methods=["GET", "POST"])
@login_required
@required_roles('admin')
def staffinvent(page=1):
    products = Product.query.paginate(page=page, per_page=10)

    return render_template('user/staff/joshua/StaffInventory/staffinventory.html', products=products, page=page)


@app.route('/consultatioPg1')
def consultatioPg1():
    return render_template('user/guest/xuzhi/consultatioPg1.html')

@app.route('/retrieveConsultation')
def retrieveConsultation():
    if current_user.is_authenticated:

        users_dict ={}
        db = User

        try:
            if 'Users' in db:
                users_dict = db['Users']
            else:
                db["Users"] = users_dict
        except:
            print("Error in retrieving User from staff.db")


        UserName =  User.username




        if current_user.is_authenticated:
            customers_dict = {}
            db = User
            try:
                if 'Customers' in db:
                    customers_dict = db['Customers']
                else:
                    db['Customers'] = customers_dict
            except:
                print("Error in retrieving Customers from customer.db.")



            customers_list = User


            for key in customers_dict:
                customer = customers_dict.get(key)
                print(customer)
                print(customer.get_us())
                print(customer.get_consult())
                customers_list.append(customer)
            """
            for customer in customers_list:
                bonk = customer.get_us()
                bonk = str(bonk)
                print("The id is" + bonk)
            """
            return render_template('user/guest/xuzhi/retrieveConsultation.html')
        else:
            session.clear()
            return redirect(url_for('home'))
    elif User.role == "admin":
        StaffName = session["staff"]

        customers_dict = {}
        db = User
        try:
                if 'Customers' in db:
                    customers_dict = db['Customers']
                else:
                    db['Customers'] = customers_dict
        except:
                print("Error in retrieving Customers from customer.db.")
        db.close()

        customers_list = []
        var = session["staff"]
        print(var)
        for key in customers_dict:
                customer = customers_dict.get(key)
                print(customer)
                print(customer.get_us())
                print(customer.get_consult())
                customers_list.append(customer)
                return render_template('user/guest/xuzhi/retrieveConsultation.html', count=len(customers_list), customers_list=customers_list, var = var, staff = StaffName, consultactive = True, staffsession = True)

    else:

        return redirect(url_for('login'))

@app.route('/createConsultation', methods=['GET', 'POST'])
def create_consultation():
    if current_user.is_authenticated:
     form = createConsultationForm()
     user = current_user

     if form.validate_on_submit():
        try:
            first_name = form.first_name.data.lower()
            last_name = form.last_name.data.lower()
            email = form.email.data.lower()
            gen = form.gender.data.lower()
            doc = form.doc.data.lower()
            time = form.time.data.lower()
            remarks = form.remarks.data.lower()
            print('here')

            newconsult = User(first_name = first_name, email=email, last_name = last_name,gender = gen,doc = doc, time = time, remarks = remarks)
            print('here2')
            db.session.add(newconsult)
            db.session.commit()
            print('here3')

            return render_template('user/guest/xuzhi/retrieveConsultation.html')

        except InvalidRequestError:
            db.session.rollback()
            flash(f"Something went wrong!", "danger")
        except IntegrityError:
            db.session.rollback()
            flash(f"User already exists!.", "warning")
        except DataError:
            db.session.rollback()
            flash(f"Invalid Entry", "warning")
        except InterfaceError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except DatabaseError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except BuildError:
            db.session.rollback()
            flash(f"An error occured !", "danger")

    return render_template('user/guest/xuzhi/createConsultation.html', form=form)


@app.route('/create_product', methods=["GET", "POST"])
@login_required
@required_roles('admin')
def create_product():
    form = CreateProductForm()
    if form.validate_on_submit():
        try:
            product = Product(name=form.name.data,
                              price=form.price.data,
                              category=form.category.data,
                              short_description=form.short_description.data,
                              long_description=form.long_description.data,
                              stock=form.stock.data)
            db.session.add(product)
            db.session.commit()
            flash(f"Product has been added", "success")
            return redirect(url_for('staffinvent'))

        except InvalidRequestError:
            db.session.rollback()
            flash(f"Something went wrong!", "danger")
        except IntegrityError:
            db.session.rollback()
            flash(f"User already exists!.", "warning")
        except DataError:
            db.session.rollback()
            flash(f"Invalid Entry", "warning")
        except InterfaceError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except DatabaseError:
            db.session.rollback()
            flash(f"Error connecting to the database", "danger")
        except BuildError:
            db.session.rollback()
            flash(f"An error occured !", "danger")

    return render_template('user/staff/joshua/StaffInventory/CRUDProducts/create_product.html', form=form)


@app.route('/News')
def news():
    return render_template('user/guest/xuzhi/News.html')

@app.route('/MOHNews')
def MOHnews():
    return render_template('user/guest/xuzhi/MOHnews.html')

@app.route("/Omni")
def Omni():
    return render_template('user/guest/xuzhi/Omni.html')

@app.route("/Measure")

def Measure():
    return render_template('user/guest/xuzhi/Measure.html')
@app.route('/Vac')
def Vac():
    return render_template('user/guest/xuzhi/Vac.html')

@app.route('/Background')
def Background():
    return render_template('user/guest/xuzhi/Background.html')
@app.route('/help')
def Help():
    return render_template('user/guest/Alisa/help.html')



if __name__ == "__main__":
    app.run(debug=True)
