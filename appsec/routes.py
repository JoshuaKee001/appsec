from hashlib import new
from sre_constants import CH_LOCALE
import os
import pyqrcode
import datetime
from io import BytesIO
from cryptography.fernet import Fernet
from flask import (
    Flask,
    render_template,
    redirect,
    flash,
    url_for,
    session,
    request
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

from app import create_app, db, login_manager, bcrypt, limiter, mail, jwt, required_roles, f
from models import User, Product, graph, feedback
from forms import LoginForm, SignUpForm, ChangePasswordForm, EditEmailForm, ForgotPasswordForm, \
    ResetPasswordForm, CreateProductForm, createConsultationForm, EmptyForm, Quantity, FeedbackForm, CardInfoForm, \
    Login2Form, FiltersAndSorting, AccountListSearchForm, EditNameForm, AddressForm, Gform
from functions import send_password_reset_email, send_ban_email, send_unban_email, send_verification_email, \
    allowed_file, ALLOWED_EXTENSIONS, encrypt, decrypt
from wtforms import ValidationError

# done by joshua
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


app = create_app()


@app.before_request
def session_handler():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)


@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response


@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("home.html")


@app.route('/login', methods=["GET", "POST"])
@limiter.limit("2/second")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()

    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data.lower()).first()
            if check_password_hash(user.password, form.password.data):
                if not user.banned:
                    if user.two_factor_enabled:
                        return redirect(url_for('login_2', username=user.username))
                    else:
                        login_user(user)
                        return redirect(url_for('home'))
                else:
                    flash("User has been banned", 'danger')
            else:
                flash("Invalid Username or password!", "danger")
        except Exception as e:
            flash("Invalid Username or password!", "danger")

    return render_template('user/guest/login.html', form=form)


@app.route('/login_2/<username>', methods=["GET", "POST"])
@limiter.limit("2/second")
def login_2(username):
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = Login2Form()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=username).first()
            if user.verify_totp(form.otp.data):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash('invalid code', 'danger')
        except Exception as e:
            flash('invalid code', 'danger')

    return render_template('user/guest/login2.html', form=form)


@app.route('/signup', methods=["GET", "POST"])
@limiter.limit("2/second")
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        try:
            appointment = True
            username = form.username.data
            email = form.email.data.lower()
            password = form.password.data

            excluded_chars = "*?!'^+%&/()=}][{$#"




            if excluded_chars in username:
                appointment = False
                raise ValidationError

            else:
                appintment = True
            if excluded_chars in email:
                appointment = False
                raise ValidationError

            else:
                appointment = True


            consultstate = False
            if appointment == True:

              newuser = User(username=username, email=email, password=bcrypt.generate_password_hash(password),
                           consultstate=consultstate, pfpfilename='default.png', failedaccess = 0)

              db.session.add(newuser)
              db.session.commit()
              flash(f"Account Succesfully created", "success")
              return redirect(url_for("login"))

            else:
                return redirect(url_for('home'))

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
    session.clear()
    return redirect(url_for("home"))


@app.route('/user', methods=['GET', 'POST'])
@login_required
def user():
    form = EmptyForm()

    return render_template('user/loggedin/useraccount.html', name=current_user, form=form)


@app.route('/uploadProfilePic', methods=["GET", "POST"])
@login_required
def uploadPic():
    if request.method == "POST":
        if "profilePic" not in request.files:
            flash('No file sent', 'info')
            return redirect(url_for("user"))

        file = request.files['profilePic']
        filename = file.filename

        if filename != '':
            if file and allowed_file(filename):
                extension = file.filename.split('.')[1]
                filename = ("%s.%s" % (current_user.username, extension))
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                # now implement logic to get html to show profile pic
                current_user.pfpfilename = filename
                db.session.commit()
                flash(f'Profile Pic has been uploaded', 'success')
                return redirect(url_for('user'))
            else:
                flash(f'Image not correct format', 'warning')
                return redirect(url_for('user'))
        else:
            flash(f'No file inputted', 'info')
            return redirect(url_for('user'))


@app.route('/resetProfilePic', methods=["GET", "POST"])
@login_required
def resetPfp():
    current_user.pfpfilename = 'default.png'
    db.session.commit()
    flash('Profile pic has been reset', 'info')
    return redirect(url_for('user'))


@app.route('/enable_2fa', methods=["GET", "POST"])
@login_required
def enable_2fa():
    user = current_user
    user.two_factor_enabled = True

    db.session.commit()
    flash(f'2fa has been enabled', 'success')

    return redirect(url_for('user'))


@app.route('/disable_2fa', methods=["GET", "POST"])
@login_required
def disable_2fa():
    user = current_user
    user.two_factor_enabled = False

    db.session.commit()
    flash(f'2fa has been disabled', 'info')

    return redirect(url_for('user'))


@app.route('/2fa-setup', methods=['GET', 'POST'])
@login_required
def twofactor_setup():
    return render_template('user/loggedin/2fa-setup.html')


@app.route('/qrcode', methods=["GET", "POST"])
@login_required
def qrcode():
    user = current_user
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue()


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


@app.route('/edit_name', methods=["GET", "POST"])
@login_required
def edit_name():
    form = EditNameForm()

    if request.method == "GET":
        form.new_username.data = current_user.username

    if form.validate_on_submit():
        try:
            user = current_user
            new_username = form.new_username.data
            if new_username == user.username:
                return redirect(url_for('user'))
            user.username = form.new_username.data
            db.session.commit()
            flash(f"Username has been updated", "success")
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

    return render_template('user/loggedin/user_name_edit.html', form=form)


@app.route('/edit_email', methods=["GET", "POST"])
@login_required
def edit_email():
    form = EditEmailForm()

    if request.method == "GET":
        form.new_email.data = current_user.email

    if form.validate_on_submit():
        try:
            user = current_user
            new_email = form.new_email.data
            if new_email == user.email:
                return redirect(url_for('user'))
            user.email = form.new_email.data
            user.verified = False
            db.session.commit()
            flash(f"Email has been updated", "success")
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

    return render_template('user/loggedin/user_email_edit.html', form=form)


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


@app.route('/verifyEmail/<id>', methods=['GET', "POST"])
@login_required
def verifyEmail(id):
    user = User.query.filter_by(id=id).first()

    if user:
        send_verification_email(user)
    else:
        pass

    flash(f'email verification email sent', 'info')
    return redirect(url_for('user'))


@app.route('/emailVerification/<token>', methods=['GET', "POST"])
def emailVerification(token):
    user = User.verify_reset_token(token)

    if user:
        user.verified = True
        db.session.commit()
        flash(f'email has been verified', 'success')
        return redirect(url_for('home'))


@app.route('/staffinvent/<int:page>', methods=["GET", "POST"])
@login_required
@required_roles('admin')
def staffinvent(page=1):
    products = Product.query.paginate(page=page, per_page=10)

    return render_template('user/staff/joshua/StaffInventory/staffinventory.html', products=products, page=page)


@app.route('/create_product', methods=["GET", "POST"])
@login_required
@required_roles('admin')
def create_product():
    form = CreateProductForm()
    if form.validate_on_submit():
        if "productPic" not in request.files:
            flash(f'no file sent', 'info')
            return redirect(url_for("create_product"))

        file = request.files['productPic']
        filename = file.filename

        if filename != '':
            if file and allowed_file(filename):
                extension = file.filename.split('.')[1]
                filename = ("%s.%s" % (form.name.data, extension))
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
            else:
                flash(f'Image not correct format', 'warning')
                return redirect(url_for('create_product'))
        else:
            flash(f'No file inputted', 'info')
            return redirect(url_for('create_product'))

        product = Product(name=form.name.data,
                          price=form.price.data,
                          category=form.category.data,
                          short_description=form.short_description.data,
                          long_description=form.long_description.data,
                          stock=form.stock.data,
                          img_file_name=filename,
                          no_sold=0)
        db.session.add(product)
        db.session.commit()
        flash(f"Product has been added", "success")
        return redirect(url_for('staffinvent', page=1))

    return render_template('user/staff/joshua/StaffInventory/CRUDProducts/create_product.html', form=form)


@app.route('/edit_product', methods=["GET", "POST"])
@login_required
@required_roles('admin')
def edit_product():
    id = request.args.get('id')
    product = Product.query.filter(Product.id.contains(id)).first()
    form = CreateProductForm(request.form)

    if request.method == 'POST' and form.validate_on_submit():
        if "productPic" not in request.files:
            flash(f'no file sent', 'info')
            return redirect(url_for("create_product"))

        file = request.files['productPic']
        filename = file.filename

        if filename != '':
            if file and allowed_file(filename):
                extension = file.filename.split('.')[1]
                filename = ("%s.%s" % (form.name.data, extension))
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
            else:
                flash(f'Image not correct format', 'warning')
                return redirect(url_for('create_product'))
        else:
            flash(f'No file inputted', 'info')
            return redirect(url_for('create_product'))
        product.name = form.name.data
        product.price = form.price.data
        product.category = form.category.data
        product.short_description = form.short_description.data
        product.long_description = form.long_description.data
        product.stock = form.stock.data
        product.img_file_name = filename

        db.session.commit()
        return redirect(url_for('staffinvent', page=1))

    elif request.method == 'GET' and product:
        form.name.data = product.name
        form.price.data = product.price
        form.category.data = product.category
        form.short_description.data = product.short_description
        form.long_description.data = product.long_description
        form.stock.data = product.stock

    elif request.method == "POST":
        db.session.delete(product)
        db.session.commit()

        return redirect(url_for('staffinvent', page=1))

    return render_template('user/staff/joshua/StaffInventory/CRUDProducts/edit_product.html', product=product, form=form)


@app.route('/staffprod', methods=["GET", "POST"])
@login_required
@required_roles('admin')
def staffprod():
    products = Product.query.all()
    data = []
    for product in products:
        if product.no_sold > 0:
            new = (product.name, product.no_sold)
            data.append(new)

    labels = [row[0] for row in data]
    values = [row[1] for row in data]
    current = datetime.date.today()
    current = current.strftime("%d/%m/%Y %H:%M:%S")

    return render_template('user/staff/staffproduct.html', labels=labels, values=values, current=current)


@app.route('/staffaccountlist/<int:page>', methods=["GET", "POST"])  # list member accounts
@login_required
@required_roles('admin')
def staffaccountlist(page=1):
    form = AccountListSearchForm()
    user_list = User.query.filter_by(role=None).all()
    if form.validate_on_submit():
        search = form.search.data
        return redirect(url_for('staffaccountlist_search', search=search))

    return render_template('user/staff/staffaccountlist_2.html', form=form, user_list=user_list, page=page)


@app.route('/stafflist/<int:page>', methods=["GET", "POST"])  # list staff accounts
@login_required
@required_roles('admin')
def stafflist(page=1):
    form = AccountListSearchForm()
    staff_list = User.query.filter_by(role='admin').all()
    if form.validate_on_submit():
        search = form.search.data
        return redirect(url_for('stafflist_search', search=search))

    return render_template('user/staff/stafflist2.html', form=form, staff_list=staff_list, page=page)


@app.route('/staffaccountlist/search/<search>', methods=["GET", "POST"])  # list member accounts
@login_required
@required_roles('admin')
def staffaccountlist_search(search):
    form = AccountListSearchForm()
    user_list = User.query.filter_by(role=None).all()
    filtered_user_list = []
    for user in user_list:
        if search in user.username or user.id:
            filtered_user_list.append(user)

    return render_template('user/staff/staffaccountlist_2.html', form=form, user_list=filtered_user_list, page=1)


@app.route('/stafflist/search/<search>', methods=["GET", "POST"])  # list staff accounts
@login_required
@required_roles('admin')
def stafflist_search(search):
    form = AccountListSearchForm()
    staff_list = User.query.filter_by(role='admin').all()
    filtered_staff_list = []
    for staff in staff_list:
        if search in staff.username or staff.id:
            filtered_staff_list.append(staff)

    return render_template('user/staff/stafflist2.html', form=form, staff_list=filtered_staff_list, page=1)


@app.route('/deletestaff/<id>', methods=["GET", "POST"])
@login_required
@required_roles('admin')
def deleteStaff(id):
    staff = User.query.filter_by(id=id).first()
    db.session.delete(staff)
    db.session.commit()

    flash(f"staff has been deleted", 'success')
    return redirect(url_for('stafflist', page=1))


@app.route('/unadmin/<id>', methods=["GET", "POST"])
@login_required
@required_roles('admin')
def unadmin(id):
    staff = User.query.filter_by(id=id).first()
    staff.role = None
    db.session.commit()

    flash("admin privileges have been revoked", 'info')
    return redirect(url_for('stafflist', page=1))


@app.route('/make_admin/<id>', methods=["GET", "POST"])
@login_required
@required_roles('admin')
def make_admin(id):
    user = User.query.filter_by(id=id).first()
    user.role = 'admin'
    db.session.commit()

    flash("A user has been made admin", 'info')
    return redirect(url_for('staffaccountlist', page=1))


@app.route('/banUser/<id>', methods=['GET', 'POST'])
@login_required
@required_roles('admin')
def banUser(id):
    user = User.query.filter_by(id=id).first()
    user.banned = True
    db.session.commit()

    send_ban_email(user)
    flash(f'user %s has been banned' % user.username, 'info')

    return redirect(url_for("staffaccountlist", page=1))


@app.route('/unbanUser/<id>', methods=['GET', 'POST'])
@login_required
@required_roles('admin')
def unbanUser(id):
    user = User.query.filter_by(id=id).first()
    user.banned = False
    db.session.commit()

    send_unban_email(user)
    flash(f'user %s has been unbanned' % user.username, 'info')

    return redirect(url_for("staffaccountlist", page=1))


@app.route('/delete_account', methods=["GET", "POST"])
@login_required
def delete_account():
    if request.method == "POST":
        db.session.delete(current_user)
        db.session.commit()
        flash(f'Account has been deleted', 'info')

        return redirect(url_for('home'))


@app.route('/usercard', methods=["GET", "POST"])
@login_required
def usercard():
    form = CardInfoForm()

    if request.method == 'GET' and current_user.card_name is not None:
        user = current_user
        form.card_name.data = user.card_name
        form.card_no.data = decrypt(user.card_no)
        form.card_expiry_month.data = decrypt(user.card_exp_month)
        form.card_expiry_year.data = decrypt(user.card_exp_year)

    if form.validate_on_submit():
        if not form.valid_card_number(form.card_no.data):
            flash('Please provide a valid credit card number', 'warning')
            return redirect(url_for('usercard'))
        user = current_user
        user.card_name = form.card_name.data

        user.card_no = encrypt(form.card_no.data)
        user.card_exp_month = encrypt(form.card_expiry_month.data)
        user.card_exp_year = encrypt(form.card_expiry_year.data)

        db.session.commit()
        flash(f'card info has been updated', 'info')
        return redirect(url_for('user'))

    return render_template('user/loggedin/user_cardinfo.html', form=form)


@app.route('/deletecard', methods=["GET", "POST"])
@login_required
def deletecard():
    user = current_user
    user.card_name = None
    user.card_no = None
    user.card_exp_month = None
    user.card_exp_year = None
    user.card_CVV = None

    db.session.commit()
    flash(f'card info has been deleted', 'info')

    return redirect(url_for('user'))


@app.route('/useraddress', methods=["GET", "POST"])
@login_required
def useraddress():
    form = AddressForm()
    if request.method == 'GET' and current_user.shipping_address is not None:
        user = current_user
        form.shipping_address.data = user.shipping_address
        form.postal_code.data = user.postal_code

        unit_no = user.unit_no
        unit_no = unit_no.replace('#', '')
        unit_no1 = unit_no.split('-')[0]
        unit_no2 = unit_no.split('-')[1]

        form.unit_number1.data = unit_no1
        form.unit_number2.data = unit_no2
        form.phone_no.data = user.phone_no

    if form.validate_on_submit():
        user = current_user
        user.shipping_address = form.shipping_address.data
        user.postal_code = form.postal_code.data
        user.unit_no = '#' + str(form.unit_number1.data) + '-' + str(form.unit_number2.data)
        user.phone_no = form.phone_no.data

        db.session.commit()
        flash(f'address has been updated', 'info')
        return redirect(url_for('user'))

    return render_template('user/loggedin/user_address.html', form=form)


@app.route('/deleteaddress', methods=["GET", "POST"])
@login_required
def deleteaddress():
    user = current_user
    user.shipping_address = None
    user.postal_code = None
    user.unit_no = None
    user.phone_no = None

    db.session.commit()
    flash(f'address info has been deleted', 'info')

    return redirect(url_for('user'))


@app.route('/store', methods=["GET", "POST"])
def store():
    page = request.args.get('page', 1, type=int)
    products = Product.query.paginate(page=page, per_page=8)

    return render_template('user/guest/joshua/GuestStore/store.html', products=products)


@app.route('/search', methods=["GET", "POST"])
def search():
    query = request.args.get('query')
    page = request.args.get('page', 1, type=int)
    form = FiltersAndSorting()

    if query:
        products = Product.query.filter(Product.name.contains(query) |
                                        Product.short_description.contains(query) |
                                        Product.long_description.contains(query) |
                                        Product.category.contains(query)).paginate(page=page, per_page=8)
    else:
        products = Product.query.paginate(page=page, per_page=8)

    return render_template('user/guest/joshua/GuestStore/search.html', products=products, form=form)
# done by joshua end


@app.route('/view_product', methods=["GET", "POST"])
def view_product():
    not_enough = False
    id = request.args.get('id')
    products = Product.query.filter(Product.id.contains(id))
    quantity_form = Quantity()
    if request.method == "POST" and quantity_form.validate_on_submit():
        if "cart" in session:
            cart = session["cart"]
            for s in products:
                if quantity_form.quantity.data <= s.stock:
                    for i in cart:
                        if i == s.name:
                            if cart[i] + quantity_form.quantity.data <= s.stock:
                                cart[i] = cart[i] + quantity_form.quantity.data
                else:
                    not_enough = True
            session["cart"] = cart
        else:
            cart = {}
            for i in products:
                if quantity_form.quantity.data <= i.stock:
                    cart[i.name] = quantity_form.quantity.data
                    session["cart"] = cart

        return render_template('user/guest/joshua/GuestStore/view_product.html', products=products, usersession = True, storeactive = True, form = quantity_form, not_enough = not_enough)
    else:
        return render_template('user/guest/joshua/GuestStore/view_product.html', products=products, usersession = True, storeactive = True, form = quantity_form, not_enough = not_enough)


@app.route('/cart',methods=['GET', 'POST'])
def cart():
    form = EmptyForm()
    if current_user.is_authenticated:
        if "cart" in session:
            total = 0
            cart = session["cart"]
            products = Product.query.all()
            for item in cart:
                for product in products:
                    if item == product.name:
                        total += cart.get(item) * product.price

            session["total"] = total
            noitem = len(cart)
            return render_template('user/guest/cart_feedback/cart.html', usersession = True, cart = cart, products = products, total = total, num = noitem, form=form)
        else:
            empty = True
            return render_template('user/guest/cart_feedback/cart.html',empty = empty)


    else:
        if "cart" in session:
            total = 0
            cart = session["cart"]
            products = Product.query.all()
            for item in cart:
                for product in products:
                    if item == product.name:
                        total += cart.get(item) * product.price
            session["total"] = total
            noitem = len(cart)
            return render_template('user/guest/cart_feedback/cart.html', cart = cart, products = products, total = total, num = noitem)

        else:
            empty = True
            return render_template('user/guest/cart_feedback/cart.html',empty = empty)

#remove product from cart
@app.route('/removeprod/<id>',methods=['GET', 'POST'])
def removeprod(id):
    cart = session["cart"]
    cart.pop(id)

    if len(cart) == 0:
        session.pop("cart", None)
    else:
        session["cart"] = cart

    return redirect(url_for('cart'))

#add quantity in cart
@app.route('/addprod/<id>', methods = ["GET","POST"])
def addprod(id):
    cart = session["cart"]
    cart[id] += 1
    session["cart"] = cart
    return redirect(url_for('cart'))

#minus quantity in cart
@app.route('/minusprod/<id>', methods = ["GET","POST"])
def minusprod(id):
    cart = session["cart"]
    cart[id] -= 1
    if cart[id] == 0:
        cart.pop(id)
    if len(cart) == 0:
        session.pop("cart", None)
    else:
        session["cart"] = cart
    return redirect(url_for('cart'))

@app.route('/checkItems', methods=['GET','POST'])
def checkItems():
    form = EmptyForm()
    if "cart" in session:
        cart = session["cart"]
        products = Product.query.all()
        noitem = len(cart)
        return render_template('user/guest/alisa/checkItems.html', usersession = True, cart = cart, products = products, num = noitem, form=form)
    else:
        empty = True
        return render_template('user/guest/cart_feedback/cart.html', usersession = True, empty = empty)

@app.route('/shippingAddress', methods=["GET", "POST"])
def shippingAddress():
    form = AddressForm()

    if request.method == 'GET' and current_user.shipping_address is not None:
        user = current_user
        form.shipping_address.data = user.shipping_address
        form.postal_code.data = user.postal_code

        unit_no = user.unit_no
        unit_no = unit_no.replace('#', '')
        unit_no1 = unit_no.split('-')[0]
        unit_no2 = unit_no.split('-')[1]

        form.unit_number1.data = unit_no1
        form.unit_number2.data = unit_no2
        form.phone_no.data = user.phone_no

    if form.validate_on_submit():
        user = current_user
        user.shipping_address = form.shipping_address.data
        user.postal_code = form.postal_code.data
        user.unit_no = '#' + str(form.unit_number1.data) + '-' + str(form.unit_number2.data)
        user.phone_no = form.phone_no.data

        db.session.commit()
        return redirect(url_for('paymentDetails'))

    return render_template('user/guest/alisa/user/guest/alisa/guest_ShippingAddress.html', form = form)


@app.route('/paymentDetails', methods=["GET", "POST"])
def paymentDetails():
    form = CardInfoForm()

    if request.method == 'GET' and current_user.card_name is not None:
        user = current_user
        form.card_name.data = decrypt(user.card_name)
        form.card_no.data = decrypt(user.card_no)
        form.card_expiry_month.data = decrypt(user.card_exp_month)
        form.card_expiry_year.data = decrypt(user.card_exp_year)

    if form.validate_on_submit():
        user = current_user
        user.card_name = encrypt(form.card_name.data)
        user.card_no = encrypt(form.card_no.data)
        user.card_exp_month = encrypt(form.card_expiry_month.data)
        user.card_exp_year = encrypt(form.card_expiry_year.data)

        db.session.commit()
        return redirect(url_for('shoppingComplete'))

    return render_template('user/guest/alisa/user/guest/alisa/guest_paymentDetail.html', form = form)

@app.route('/shoppingComplete', methods=["GET","POST"])
def shoppingComplete():
    if "cart" in session and "total" in session:
            cart = session["cart"]
            total = session["total"]
            products = Product.query.all()

            for i in cart:
                for s in products:
                    if i == s.name:
                        s.stock = s.stock - cart[i]
                        s.no_sold += cart[i]
                        db.session.commit()

            session.pop('cart', None)
            session.pop('total', None)
            return render_template('user/guest/alisa/shoppingComplete.html', usersession = True, cart = cart, total=total)


@app.route('/News', methods=['GET', 'POST'])
def News():


    labels = []
    values = []

    if current_user.is_authenticated:
        labels = []
        values = []
        if current_user.role == "admin":
          Gdb  = graph.query.all()

          for x in Gdb:
            dat1 = x.DATE1
            dat2 = x.DATE2
            dat3 = x.DATE3
            dat4 = x.DATE4
            dat5 = x.DATE5
            COVID1 = x.COVID1
            COVID2 = x.COVID2
            COVID3 = x.COVID3
            COVID4 = x.COVID4
            COVID5 = x.COVID5


            data=[
                (dat1,COVID1),
                (dat2,COVID2),
                (dat3,COVID3),
                (dat4,COVID4),
                (dat5,COVID5),
                ]

            labels = [row[0] for row in data]
            values = [row[1] for row in data]


          return render_template('user/guest/xuzhi/News.html',labels = labels, values = values, staffsession = True, newsactive = True  )

        else:
          Gdb  = graph.query.all()
          for x in Gdb:
            date1 = x.DATE1
            date2 = x.DATE2
            date3 = x.DATE3
            date4 = x.DATE4
            date5 = x.DATE5
            COVID1 = x.COVID1
            COVID2 = x.COVID2
            COVID3 = x.COVID3
            COVID4 = x.COVID4
            COVID5 = x.COVID5




            data=[
                (date1,COVID1),
                (date2,COVID2),
                (date3,COVID3),
                (date4,COVID4),
                (date5,COVID5),
                ]

            labels = [row[0] for row in data]
            values = [row[1] for row in data]


          return render_template('user/guest/xuzhi/News.html',labels = labels, values = values, staffsession = False, newsactive = True  )


    else:

        Gdb  = graph.query.all()
        for x in Gdb:
            date1 = x.DATE1
            date2 = x.DATE2
            date3 = x.DATE3
            date4 = x.DATE4
            date5 = x.DATE5
            COVID1 = x.COVID1
            COVID2 = x.COVID2
            COVID3 = x.COVID3
            COVID4 = x.COVID4
            COVID5 = x.COVID5




            data=[
                (date1,COVID1),
                (date2,COVID2),
                (date3,COVID3),
                (date4,COVID4),
                (date5,COVID5),
                ]

            labels = [row[0] for row in data]
            values = [row[1] for row in data]


        return render_template('user/guest/xuzhi/News.html',labels = labels, values = values, staffsession = False, newsactive = True  )

@app.route('/UpGraphform', methods=['GET', 'POST'])
def UpGraphform():
   print("1")
   form = Gform()
   if current_user.is_authenticated:

    if current_user.role == 'admin':
       print("Im here")

       if form.validate_on_submit()  :
           print("validated")
           grap = graph.query.all()
           check = False


           if check != True:


            for gra in grap:
              gra.id = 1
              gra.COVID1 = str(form.COVID1.data)
              gra.COVID2 = str(form.COVID2.data)
              gra.COVID3 = str(form.COVID3.data)
              gra.COVID4 = str(form.COVID4.data)
              gra.COVID5 = str(form.COVID5.data)
              gra.DATE1 = form.DATE1.data
              gra.DATE2 = form.DATE2.data
              gra.DATE3 = form.DATE3.data
              gra.DATE4 = form.DATE4.data
              gra.DATE5 = form.DATE5.data

              db.session.commit()
              check = True
              return render_template('user/guest/xuzhi/News.html', form = form, staffsession = True )




           else:
              print("ERROR!")
              return redirect(url_for('home'))
       return render_template('user/guest/xuzhi/Graphform.html', form = form, staffsession = False)


    else:
        user = current_user
        Cval = user.failedaccess
        Nval = int(Cval) + 1
        user.failedacess = Nval

        return redirect(url_for('home'))

@app.route('/Graphform', methods=['GET', 'POST'])
def Graphform():
    if current_user.is_authenticated:
     print("1")
     form = Gform()


     if current_user.role == 'admin':
       print("Im here")

       if form.validate_on_submit()  :
           print("validated")
           gra = graph.query.all()
           check = False
           print(gra)



           if check != True:





            main_graph = graph(gra = True,
                               COVID1 = str(form.COVID1.data),
                               COVID2 = str(form.COVID2.data),
                               COVID3 = str(form.COVID3.data) ,
                               COVID4 = str(form.COVID4.data),
                               COVID5 = str(form.COVID5.data),
                               DATE1 = form.DATE1.data,
                               DATE2 = form.DATE2.data,
                               DATE3 = form.DATE3.data,
                               DATE4 = form.DATE4.data,
                               DATE5 = form.DATE5.data)
            db.session.add(main_graph)
            db.session.commit()
            check = True
            return render_template('user/guest/xuzhi/News.html', form = form, staffsession = True )




           else:
              print("ERROR!")
              return redirect(url_for('home'))
       return render_template('user/guest/xuzhi/Graphform.html', form = form, staffsession = False)

     else:
        session.clear()
        user = current_user
        Cval = user.failedaccess
        Nval = int(Cval) + 1
        user.failedacess = Nval
        db.session.commit()

    else:
        return redirect(url_for('login'))












@app.route('/consultatioPg1')
def consultatioPg1():

    if current_user.is_authenticated:
        return render_template('user/guest/xuzhi/consultatioPg1.html', notloggedin = False )

    else:
        return render_template('user/guest/xuzhi/consultatioPg1.html', notloggedin = True )

@app.route('/retrieveConsultation', methods=['GET', 'POST'])
def retrieveConsultation():
    if current_user.is_authenticated:


        form = createConsultationForm()
        if current_user.role == 'admin':
            return redirect('retrieveConsultationAd')

        elif current_user.is_authenticated:


            z=0
            remarks = "Empty"
            user = current_user
            i = current_user.id
            customers_list = User
            test = user
            print('test' ,test )
            empty = " "
            info = user.query.filter_by(id=user.id).limit(1).first()
            if info.consultstate == True:
                print("All Good ")
                key = info.ferkey
                fernet  = Fernet(key)
                finam = info.first_name
                lanam = info.last_name


                first =  fernet.decrypt(finam).decode()
                last = fernet.decrypt(lanam).decode()
                return render_template('user/guest/xuzhi/retrieveConsultation.html', count=1,  consultactive = True, info = info, form = form, first = first, last = last )



            elif info.consultstate == False:

                info.first_name = empty
                info.last_name = empty
                info.date_joined = empty
                info.doc = empty
                info.time = empty
                info.remarks = empty

                return render_template('user/guest/xuzhi/retrieveConsultation.html', count=0,  consultactive = True, info = info, form = form, first = empty, last = empty )
        else:
            session.clear()

            return redirect(url_for('home'))


    else:

        return redirect(url_for('login'))

@app.route('/retrieveConsultationAd', methods=['GET', 'POST'])
def retrieveConsultationAd():
    if current_user.is_authenticated:

        form = createConsultationForm()
        if current_user.role == 'admin':
          print('placeholder')


          z=0
          remarks = "Empty"
          user = current_user
          i = current_user.id
          customers_list = User
          test = user
          print('test' ,test )
          empty = " "
          consultation = user.query.all()
          f = []
          L = []
          namelist = []
          keylist = []


          for i in consultation:
              if i.consultstate == True:

                key = i.ferkey
                fernet  = Fernet(key)
                finam = i.first_name
                lanam = i.last_name

                first =  fernet.decrypt(finam).decode()
                last = fernet.decrypt(lanam).decode()
                print(first)
                f.append(first)
                L.append(last)
                namelist.append(first + ' ' + last )
              else:
                  namelist.append("null")




          return render_template('user/guest/xuzhi/retrieveConsultationAd.html',form = form, consultation = consultation, flist = f, llist = L, namelist = namelist, zip = zip )
        else:
            session.clear()
            user = current_user
            Cval = user.failedaccess
            Nval = int(Cval) + 1
            user.failedacess = Nval

            db.session.commit()


            return redirect(url_for('home'))


    else:

        return redirect(url_for('login'))


@app.route('/createConsultation', methods=['GET', 'POST'])
def create_consultation():
    form = createConsultationForm()
    print("here1")
    if current_user.is_authenticated:
      print('here2')

      user = current_user
      id = current_user.id
      appoint = user


      all = user.query.all()


      print(str(form.date_joined.data))


      if form.validate_on_submit()  :


            print('here3')

            appointment = False
            fname = form.first_name.data.lower()
            lname = form.last_name.data.lower()
            date = form.date_joined.data
            rem = form.remarks.data.lower()
            gen = form.gender.data.lower()
            doc = form.doc.data.lower()
            time = form.time.data.lower()

            excluded_chars = "*?!'^+%&/()=}][{$#"

            all = user.query.all()


            if excluded_chars in fname:
                appointment = False
                raise ValidationError

            else:
                appintment = True
            if excluded_chars in lname:
                appointment = False
                raise ValidationError

            else:
                appointment = False

            try :
                datetime.strptime(date, '%Y-%m-%d')
                appointment = True
            except:
                appointment = False


            if str(doc) == 't' or 't' or 'm' 'l':
                appointment = True


            else:
                appointment = False
                raise ValidationError

            if  str(time) == '9.00am - 9.30am'  '10.00am - 10.30am' or '11.00am - 11.30am' or '12.00pm -12.30pm' or '3.00pm - 3.30pm' or '4.00pm - 4.30pm'  or  '5.00pm -5.30pm':
                appointment = True


            else:
                appointment = False
                raise ValidationError



            for i in all:


              print("form " + str(form.date_joined.data))
              print("database " + str(i.date_joined))

              if str(i.date_joined) == str(form.date_joined.data):
                samedate = True
                print('SAMEDATE')
                print("baseddoc" + str(i.doc))


                if str(i.doc) == str(form.doc.data):
                  samedoc = True
                  print("SAMEDOC")


                  if str(i.time) == str(form.time.data):
                      sametime = True
                      faliure = True
                      print("FALURE")
                      appointment = False
                      return render_template('user/guest/xuzhi/ErrorDate.html', timelistval = str(form.time.data), datelistval = str(form.date_joined.data) )

                  else:
                      appointment = True
                else:
                  appointment = True
              else:

                appointment = True



            if appointment == True:

              key = Fernet.generate_key()
              fernet = Fernet(key)

              print("hey ")
              appoint.user = id
              appoint.consultstate = True
              fnam = form.first_name.data.lower()

              Efname = fernet.encrypt(fnam.encode())

              lnam = form.last_name.data.lower()

              Elname = fernet.encrypt(lnam.encode())
              print(Efname)
              print(Elname)

              appoint.ferkey = key

              appoint.first_name =Efname
              appoint.last_name = Elname
              date = str(form.date_joined.data)
              appoint.date_joined = date
              gen = str(form.gender.data.lower())
              appoint.gender = gen
              doc = str(form.doc.data.lower())
              appoint.doc = doc
              time = str(form.time.data.lower())
              appoint.time = time
              rem = str(form.time.data.lower())
              appoint.remarks = rem


              db.session.commit()

              i = current_user.id





              return redirect(url_for('retrieveConsultation'))



            else:
               print('Danger! Error!')

               session.clear()
               user = current_user
               Cval = user.failedaccess
               Nval = int(Cval) + 1
               user.failedacess = Nval

               db.session.commit()

               return render_template('user/guest/xuzhi/createConsultation.html', form = form)
      else:
          print(form.errors)




      return render_template('user/guest/xuzhi/createConsultation.html', form = form)

    else:
        return redirect(url_for('login'))





@app.route('/delete_consultation', methods=['GET', 'POST'])
def delete_consultation():


    if current_user.is_authenticated:


      user = current_user
      id = current_user.id
      appoint = user

      print("deleting ")
      empty = " "
      empty = " "
      byte = b''



      appoint.key = byte
      appoint.user = id


      appoint.user = id
      appoint.consultstate = False
      appoint.first_name = byte
      appoint.last_name = byte
      appoint.date_joined = empty
      appoint.gender = empty
      appoint.doc = empty
      appoint.time = empty
      appoint.remarks = empty

      db.session.commit()
      return redirect(url_for('retrieveConsultation' ))


    else:
        return redirect(url_for('login'))

@app.route('/help', methods=['GET', 'POST'])
def help():
    return render_template('user/guest/alisa/help.html')


@app.post('/<int:user_id>/delete/')
def delete_consultationAd(user_id):
    n = user_id



    if current_user.role == 'admin':
     if current_user.is_authenticated:



      appoint = User.query.get_or_404(n)
      id = appoint.id

      print("deleting ")
      empty = " "
      byte = b''



      appoint.key = byte
      appoint.user = id
      appoint.consultstate = False
      appoint.first_name = byte
      appoint.last_name = byte
      appoint.date_joined = empty
      appoint.gender = empty
      appoint.doc = empty
      appoint.time = empty
      appoint.remarks = empty

      db.session.commit()
      return redirect(url_for('retrieveConsultation' ))


     else:
         return redirect(url_for('login'))


    else:
        return redirect(url_for('login'))



@app.route('/stafffeed/1', methods=["GET", "POST"])
def retrievefeedback():

    if current_user.is_authenticated:


        users_dict ={}
        db = User
        UserName =  User.username
        form = createConsultationForm()
        if current_user.role == 'admin':

          users_dict ={}
          db = User
          UserName =  User.username
          form = createConsultationForm()

          print('placeholder')


          z=0
          remarks = "Empty"
          user = current_user
          i = current_user.id

          test = user
          print('test' ,test )
          empty = " "
          feed = feedback.query.all()





          return render_template('user/staff/REfeedback.html',form = form, feedback = feed)



        else:
            session.clear()


            return redirect(url_for('home'))


    else:

        return redirect(url_for('login'))


@app.post('/<int:user_id>/deleteFed/')
def delete_feedback(user_id):
    n = user_id



    if current_user.role == 'admin':
     if current_user.is_authenticated:



      feed = feedback.query.get_or_404(n)
      db.session.delete(feed)
      id = feed.id
      db.session.commit()
      return redirect(url_for('retrievefeedback' ))

     else:
         return redirect(url_for('login'))


    else:
        return redirect(url_for('login'))
@app.route('/feedback', methods=["GET", "POST"])
def feedform():
    if current_user.is_authenticated:
      form = FeedbackForm()
      if form.validate_on_submit():
          user = current_user

          tday = str(datetime.date.today())
          excluded_chars = "*?!'^+%&/()=}][{$#"
          appointment = False

          ema = form.email.data.lower()
          sub = form.subject.data.lower()
          descrip = form.description.data.lower()

          FEform = feedback(
              username=user.username,
              date=tday,
              email=form.email.data.lower(),
              subject=form.subject.data.lower(),
              description=form.description.data.lower())

          db.session.add(FEform)
          db.session.commit()

          return redirect(url_for('fb_submit'))
      else:
        return render_template('user/guest/alisa/feedback.html', usersession = True, form = form)

    else:
        return redirect(url_for('login'))

    
@app.route('/securitycheck', methods=['GET', 'POST'])
def securitycheck():
    if current_user.is_authenticated:
        user = current_user
        if current_user.role == "admin":


            use = user.query.all()
            return render_template("user/staff/Security.html", use = use)

        else:
          session.clear()

          Cval = user.failedaccess
          Nval = int(Cval) + 1
          user.failedacess = Nval

          db.session.commit()
          return redirect(url_for('home'))
    else:
        return redirect(url_for('home'))



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



#feedback submit button
@app.route('/feedback_submit', methods=["GET", "POST"])
def fb_submit():
    return render_template('user/guest/alisa/feedback_submit.html', usersession = True, contactactive = True)


if __name__ == "__main__":
    app.run(debug=True)
"""
if __name__ == "__main__":
    app.run(ssl_context=('localhost.pem', 'localhost-key.pem'))
"""
