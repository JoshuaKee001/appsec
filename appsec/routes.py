from hashlib import new
from sre_constants import CH_LOCALE
import os
import pyqrcode
from io import BytesIO
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

from app import create_app, db, login_manager, bcrypt, limiter, mail, jwt, required_roles
from models import User, Product
from forms import LoginForm, SignUpForm, ChangePasswordForm, EditInfoForm, ForgotPasswordForm, \
    ResetPasswordForm, CreateProductForm, createConsultationForm, EmptyForm, Quantity, FeedbackForm, CardInfoForm, \
    Login2Form, FiltersAndSorting, AccountListSearchForm
from functions import send_password_reset_email, send_ban_email, send_unban_email, send_verification_email, \
    encrypt, decrypt


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


app = create_app()


@app.before_request
def session_handler():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)


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
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        try:
            username = form.username.data
            email = form.email.data.lower()
            password = form.password.data
            consultstate = False  
        

            newuser = User(username=username, email=email, password=bcrypt.generate_password_hash(password), consultstate = consultstate)

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
    form = EmptyForm()

    return render_template('user/loggedin/useraccount.html', name=current_user, form=form)


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
            return redirect(url_for('staffinvent', page=1))

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


@app.route('/edit_product', methods=["GET", "POST"])
@login_required
@required_roles('admin')
def edit_product():
    id = request.args.get('id')
    product = Product.query.filter(Product.id.contains(id)).first()
    form = CreateProductForm(request.form)

    if request.method == 'POST' and form.validate_on_submit():
        product.name = form.name.data
        product.price = form.price.data
        product.category = form.category.data
        product.short_description = form.short_description.data
        product.long_description = form.long_description.data
        product.stock = form.stock.data

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


@app.route('/staffaccountlist/<int:page>', methods=["GET", "POST"])  # list member accounts
@login_required
@required_roles('admin')
def staffaccountlist(page=1):
    form = AccountListSearchForm()
    user_list = User.query.filter_by(role=None).all()

    return render_template('user/staff/staffaccountlist_2.html', form=form, user_list=user_list, page=page)


@app.route('/stafflist/<int:page>', methods=["GET", "POST"])  # list staff accounts
@login_required
@required_roles('admin')
def stafflist(page=1):
    form = AccountListSearchForm()
    staff_list = User.query.filter_by(role='admin').all()

    return render_template('user/staff/stafflist2.html', form=form, staff_list=staff_list, page=page)


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

    if request.method == 'GET':
        user = current_user
        form.card_name.data = user.card_name
        form.card_no.data = user.card_no
        form.card_expiry_month.data = user.card_exp_month
        form.card_expiry_year.data = user.card_exp_year
        form.card_CVV.data = user.card_CVV

    if form.validate_on_submit():
        user = current_user
        user.card_name = form.card_name.data
        user.card_no = form.card_no.data
        user.card_exp_month = form.card_expiry_month.data
        user.card_exp_year = form.card_expiry_year.data
        user.card_CVV = form.card_CVV.data

        db.session.commit()
        flash(f'card info has been edited', 'info')
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


@app.route('/view_product', methods=["GET", "POST"])
def view_product():
    not_enough = False
    id = request.args.get('id')
    products = Product.query.filter(Product.id.contains(id))
    quantity_form = Quantity(request.form)
    if request.method == "POST" and quantity_form.validate_on_submit():
        if"cart" in session:
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
    # else:
    #     session.clear()
    #     return redirect(url_for("login"))

@app.route('/cart',methods=['GET', 'POST'])
def cart():
    if current_user.is_authenticated:
        # users_dict = db['Users']
        # db["Users"] = users_dict

        # need to figure out how to store & retrieve user purchases
        # purchases = users_dict[idNumber].get_purchases()
        # db.close()

        if "cart" in session:
            # if valid_session:
            total = 0
            cart = session["cart"]
            products = Product.query.all()
            for item in cart:
                for product in products:
                    if item == product.name:
                        total += cart.get(item) * product.price

            original_total = total

            # discount = False
            # if purchases == 5:
            #     discount = True
            #     total = total * 0.9
            # elif purchases == 10:
            #     discount = True
            #     total = total * 0.8
            # elif purchases == 15:
            #     discount = True
            #     total = total * 0.7
            # elif purchases == 20:
            #     discount = True
            #     total = total * 0.5

            session["total"] = total
            noitem = len(cart)
            return render_template('user/guest/cart_feedback/cart.html', usersession = True, cart = cart, products = products, total = total, num = noitem, original_total = original_total)
        else:
            return redirect(url_for('home'))

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
def removeprod():
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
    if "cart" in session:
        cart = session["cart"]
        products = Product.query.all()
        noitem = len(cart)
        return render_template('user/guest/alisa/checkItems.html', usersession = True, cart = cart, products = products, num = noitem)
    else:
        empty = True
        return render_template('user/guest/cart_feedback/cart.html', usersession = True, empty = empty)


@app.route('/consultatioPg1')
def consultatioPg1():
    return render_template('user/guest/xuzhi/consultatioPg1.html')
@app.route('/retrieveConsultation', methods=['GET', 'POST'])
def retrieveConsultation():
    if current_user.is_authenticated:

        users_dict ={}
        db = User
        UserName =  User.username
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
          for i in consultation:
              f.append(i.first_name)
              L.append(i.last_name)






          return render_template('user/guest/xuzhi/retrieveConsultationAd.html',form = form, consultation = consultation, flist = f, llist = L)




        elif current_user.is_authenticated:



            z=0
            remarks = "Empty"
            user = current_user
            i = current_user.id
            customers_list = User
            test = user
            print('test' ,test )
            empty = " "
            info = user.query.filter_by(id=user.id).first()
            if info.consultstate == True:
                print("All Good ")
                return render_template('user/guest/xuzhi/retrieveConsultation.html', count=1,  consultactive = True, info = info, form = form )



            elif info.consultstate == False:

                info.first_name = empty
                info.last_name = empty
                info.date_joined = empty
                info.doc = empty
                info.time = empty
                info.remarks = empty

                return render_template('user/guest/xuzhi/retrieveConsultation.html', count=0,  consultactive = True, info = info, form = form )
        else:
            session.clear()


            return redirect(url_for('home'))


    else:

        return redirect(url_for('login'))


'''shift down FOR  down '''
@app.route('/createConsultation', methods=['GET', 'POST'])
def create_consultation():
    form = createConsultationForm()
    if current_user.is_authenticated:

      user = current_user
      id = current_user.id
      appoint = user


      all = user.query.all()


      print(str(form.date_joined.data))


      if form.validate_on_submit()  :


          try:
            appointment = False


            all = user.query.all()
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

                  else:
                      appointment = True
                else:
                  appointment = True
              else:

                appointment = True

            if appointment == True:
              print("hey ")
              appoint.user = id
              appoint.consultstate = True
              appoint.first_name = form.first_name.data.lower()
              appoint.last_name = form.last_name.data.lower()
              appoint.date_joined = form.date_joined.data
              appoint.gender = form.gender.data.lower()
              appoint.doc = form.doc.data.lower()
              appoint.time = form.time.data.lower()
              appoint.remarks = form.remarks.data.lower()


              db.session.commit()

              i = current_user.id



              info = user.query.filter_by(first_name=form.first_name.data.lower()).first()
              print(i)
              print('info',info)


              return render_template('user/guest/xuzhi/retrieveConsultation.html', count =1, consultactive = True, info = info, form = form )
            else:
              return render_template('user/guest/xuzhi/ErrorDate.html', timelistval = str(form.time.data), datelistval = str(form.date_joined.data) )


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

      return render_template('user/guest/xuzhi/createConsultation.html', form = form)



@app.route('/delete_consultation', methods=['GET', 'POST'])
def delete_consultation():





    if current_user.is_authenticated:


      user = current_user
      id = current_user.id
      appoint = user

      print("deleting ")
      empty = " "

      appoint.user = id
      appoint.consultstate = False
      appoint.first_name = empty
      appoint.last_name = empty
      appoint.date_joined = empty
      appoint.gender = empty
      appoint.doc = empty
      appoint.time = empty
      appoint.remarks = empty

      db.session.commit()
      return redirect(url_for('retrieveConsultation' ))


    else:
        return redirect(url_for('login'))


@app.post('/<int:user_id>/delete/')
def delete_consultationAd(user_id):
    n = user_id



    if current_user.role == 'admin':
     if current_user.is_authenticated:



      appoint = User.query.get_or_404(n)
      id = appoint.id

      print("deleting ")
      empty = " "

      appoint.user = id
      appoint.consultstate = False
      appoint.first_name = empty
      appoint.last_name = empty
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
def help():
    return render_template('user/guest/alisa/help.html')

#feedback form
@app.route('/feedback', methods=["GET", "POST"])
def feedback():
    form = FeedbackForm()
    if form.validate_on_submit():
        user = current_user
        feedback = user

        feedback.user = id
        feedback.name = form.name.data.lower()
        feedback.email = form.email.data.lower()
        feedback.subject = form.subject.data.lower()
        feedback.description = form.description.data.lower()

        return redirect(url_for('fb_submit'))
    else:
        return render_template('user/guest/alisa/feedback.html', usersession = True, form = form,  contactactive = True)

#feedback submit button
@app.route('/feedback_submit', methods=["GET", "POST"])
def fb_submit():
    return render_template('user/guest/alisa/feedback_submit.html', usersession = True, contactactive = True)


if __name__ == "__main__":
    app.run(debug=True, ssl_context=('server.crt', 'server.key'))
