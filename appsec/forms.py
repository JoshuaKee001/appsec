from wtforms import StringField, PasswordField, BooleanField, IntegerField, DateField, \
    TextAreaField, SelectField, FloatField, EmailField, RadioField, SubmitField, DecimalField
from wtforms_components import DateRange
from flask_wtf import FlaskForm
from wtforms.validators import InputRequired, Length, EqualTo, Email, Regexp, Optional, NumberRange
import email_validator
from flask_login import current_user
from wtforms import ValidationError, validators
from models import User
from datetime import date


class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    password = PasswordField(validators=[InputRequired(), Length(8, 72)])


class Login2Form(FlaskForm):
    otp = StringField(validators=[InputRequired(), Length(6, 6)])


class EmptyForm(FlaskForm):
    fake_field = StringField()


class SignUpForm(FlaskForm):
    username = StringField("", validators=[
        InputRequired(),
        Length(3, 20, message="Please provide a valid name"),
        Regexp("^[A-Za-z][A-Za-z0-9_.]*$", 0, "Usernames must have only letters, " "numbers, dots or underscores", ),
    ])
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    password = PasswordField(validators=[
        InputRequired(),
        Length(8, 72),
        Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,72}$", 0,
               "Password not strong enough")
    ])
    password_confirm = PasswordField(validators=[
        InputRequired(),
        Length(8, 72),
        EqualTo("password", message="Passwords must match !")
    ])

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError("Email already registered!")

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("Username already taken!")


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField(validators=[InputRequired(), Length(8, 72)])
    new_password = PasswordField(validators=[
        InputRequired(),
        Length(8, 72),
        Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,72}$", 0,
               "Password not strong enough")
    ])
    confirm_new_password = PasswordField(validators=[
        InputRequired(),
        Length(8, 72),
        EqualTo("new_password", message="Passwords must match")
    ])


class EditNameForm(FlaskForm):
    new_username = StringField("", validators=[
        InputRequired(),
        Length(3, 20, message="Please provide a valid name"),
        Regexp("^[A-Za-z][A-Za-z0-9_.]*$", 0, "Usernames must have only letters, " "numbers, dots or underscores", ),
    ])

    def validate_username(self, new_username):
        if User.query.filter_by(new_username=new_username.data).first():
            raise ValidationError("Username already taken!")


class EditEmailForm(FlaskForm):
    new_email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])

    def validate_email(self, new_email):
        if User.query.filter_by(new_email=new_email.data).first():
            raise ValidationError("Email already registered!")


class ForgotPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])


class ResetPasswordForm(FlaskForm):
    new_password = PasswordField(validators=[
        InputRequired(),
        Length(8, 72),
        Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,72}$", 0,
               "Password not strong enough")
    ])
    confirm_new_password = PasswordField(validators=[
        InputRequired(),
        Length(8, 72),
        EqualTo("new_password", message="Passwords must match")
    ])


class createConsultationForm(FlaskForm):
    first_name = StringField('First Name', [validators.Length(min=1, max=150), validators.DataRequired()])

    last_name = StringField('Last Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    gender = SelectField('Gender', [validators.DataRequired()],
                         choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    date_joined = DateField('Date of appointment(YY-MM-DD)', format='%Y-%m-%d',
                            validators=[DateRange(min=date.today())])
    time = SelectField('Appointment time', [validators.DataRequired()],
                       choices=[('9.00am - 9.30am', '9.00am - 9.30am'), ('10.00am - 10.30am', '10.00am - 10.30am'),
                                ('11.00am - 11.30am', '11.00am - 11.30am'), ('12.00pm -12.30pm', '12.00pm -12.30pm'),
                                ('3.00pm - 3.30pm', '3.00pm - 3.30pm'), ('4.00pm - 4.30pm', '4.00pm - 4.30pm'),
                                ('5.00pm -5.30pm', ' 5.00pm -5.30pm')], default='9.00am - 9.30am')
    remarks = TextAreaField('Additional request', [validators.Optional()])

    def validate_remarks(self, remarks):
        excluded_chars = "*?!'^+%&/()=}][{$#"
        for char in self.remarks.data:
            if char in excluded_chars:
                raise ValidationError(
                    f"Character {char} is not allowed in username.")

    doc = RadioField('Choice of doctor', choices=[('t', 'Dr Tan'), ('m', 'Dr Mok'), ('l', 'Dr Lim')], default='t')


class CreateProductForm(FlaskForm):
    categories = [('Medicine', 'Medicine'), ('Test Kit', 'Test Kit'), ('Supplement', 'Supplement'),
                  ('First Aid', 'First Aid')]
    category = SelectField(u"Product Category", choices=categories)

    name = StringField("Product Name", validators=[InputRequired()])
    price = FloatField("Product Price($)", validators=[InputRequired()])
    short_description = StringField("Short Description:", validators=[InputRequired()])
    long_description = TextAreaField("Long Description:", validators=[InputRequired()])
    stock = IntegerField("Stock:", validators=[InputRequired()])


class CardInfoForm(FlaskForm):
    card_name = StringField("Name On Card:", validators=[InputRequired(), Length(max=300)])
    card_no = StringField("Card Number:", validators=[InputRequired()])
    card_expiry_month = IntegerField("", [validators.NumberRange(min=0, max=12)])
    card_expiry_year = IntegerField("", [validators.NumberRange(min=0, max=99)])
    card_CVV = IntegerField("CVV:", [validators.NumberRange(min=0, max=999)])

    def valid_card_number(self, card_no):
        card_number = list(card_no)
        check_digit = card_number.pop()
        card_number.reverse()
        processed_digits = []

        for index, digit in enumerate(card_number):
            if index % 2 == 0:
                doubled_digit = int(digit) * 2

                if doubled_digit > 9:
                    doubled_digit = doubled_digit - 9

                processed_digits.append(doubled_digit)
            else:
                processed_digits.append(int(digit))

        total = int(check_digit) + sum(processed_digits)

        if total % 10 == 0:
            return True
        else:
            return False


class AddressForm(FlaskForm):
    shipping_address = StringField('', validators=[InputRequired()])
    postal_code = IntegerField("", validators=[InputRequired()])
    unit_number1 = IntegerField("", validators=[InputRequired()])
    unit_number2 = IntegerField("", validators=[InputRequired()])
    phone_no = IntegerField("", validators=[InputRequired()])


class Quantity(FlaskForm):
    quantity = IntegerField("Quantity:", [validators.DataRequired()])


class FeedbackForm(FlaskForm):
    name = StringField("Name:", [validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    subject = SelectField('Subject', [validators.DataRequired()],
                          choices=[('Website Design', 'Website Design'), ('Website Functions', 'Website Functions'),
                                   ('General', 'General'), ('Content', 'Content'), ('Copyright', 'Copyright'),
                                   ('Others', 'Others')], default='General')
    description = TextAreaField(validators=[InputRequired(), Length(max=300)])


class FiltersAndSorting(FlaskForm):
    Medicine_category = BooleanField("Medicine")
    TestKit_category = BooleanField("Test Kit")
    Supplement_category = BooleanField("Supplement")
    FirstAid_category = BooleanField("First Aid")

    sorting_methods = [('Price (Descending)', 'Price (Descending)'), ('Price (Ascending)', 'Price (Ascending)'),
                       ('Name (A to Z)', 'Name (A to Z)')]
    sort_by = SelectField(u'Sort By', choices=sorting_methods)

    price_range_lower = FloatField("From($)")
    price_range_upper = FloatField("To($):")

    apply_filters = SubmitField("Apply Filters")


class AccountListSearchForm(FlaskForm):
    search = StringField("")


class Gform(FlaskForm):
    DATE1 = DateField('Date 1:', [validators.DataRequired()], format='%Y-%m-%d')
    DATE2 = DateField('Date 2:', [validators.DataRequired()], format='%Y-%m-%d')
    DATE3 = DateField('Date 3:', [validators.DataRequired()], format='%Y-%m-%d')
    DATE4 = DateField('Date 4:', [validators.DataRequired()], format='%Y-%m-%d')
    DATE5 = DateField('Date 5:', [validators.DataRequired()], format='%Y-%m-%d')
    COVID1 = DecimalField('DATE1 Cases:', [validators.DataRequired()])
    COVID2 = DecimalField('DATE2 Cases:', [validators.DataRequired()])
    COVID3 = DecimalField('DATE3 Cases:', [validators.DataRequired()])
    COVID4 = DecimalField('DATE4 Cases:', [validators.DataRequired()])
    COVID5 = DecimalField('DATE5 Cases:', [validators.DataRequired()])
