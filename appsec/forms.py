from wtforms import StringField, PasswordField, BooleanField, IntegerField, DateField, TextAreaField, SelectField, FloatField, EmailField, RadioField
from wtforms_components import DateRange
from flask_wtf import FlaskForm
from wtforms.validators import InputRequired, Length, EqualTo, Email, Regexp, Optional
import email_validator
from flask_login import current_user
from wtforms import ValidationError, validators
from models import User
from datetime import date


class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    password = PasswordField(validators=[InputRequired(), Length(8, 72)])


class EmptyForm(FlaskForm):
    fake_field = StringField()


class SignUpForm(FlaskForm):
    username = StringField("", validators=[
        InputRequired(),
        Length(3, 20, message="Please provide a valid name"),
        Regexp("^[A-Za-z][A-Za-z0-9_.]*$", 0, "Usernames must have only letters, " "numbers, dots or underscores",),
    ])
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    password = PasswordField(validators=[
        InputRequired(), 
        Length(8, 72),
        Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,72}$", 0, "Password not strong enough")
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
        Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,72}$", 0, "Password not strong enough")
    ])
    confirm_new_password = PasswordField(validators=[
        InputRequired(), 
        Length(8, 72), 
        EqualTo("new_password", message="Passwords must match")
    ])


class EditInfoForm(FlaskForm):
    new_username = StringField("", validators=[
        InputRequired(),
        Length(3, 20, message="Please provide a valid name"),
        Regexp("^[A-Za-z][A-Za-z0-9_.]*$", 0, "Usernames must have only letters, " "numbers, dots or underscores",),
    ])
    new_email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])

    def validate_email(self, new_email):
        if User.query.filter_by(new_email=new_email.data).first():
            raise ValidationError("Email already registered!")

    def validate_username(self, new_username):
        if User.query.filter_by(new_username=new_username.data).first():
            raise ValidationError("Username already taken!")


class ForgotPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])


class ResetPasswordForm(FlaskForm):
    new_password = PasswordField(validators=[
        InputRequired(),
        Length(8, 72),
        Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,72}$", 0, "Password not strong enough")
    ])
    confirm_new_password = PasswordField(validators=[
        InputRequired(),
        Length(8, 72),
        EqualTo("new_password", message="Passwords must match")
    ])

    
class createConsultationForm(FlaskForm):
    first_name = StringField('First Name', [validators.Length(min=1, max=150), validators.DataRequired(), ])
    last_name = StringField('Last Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    gender = SelectField('Gender', [validators.DataRequired()], choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    date_joined = DateField('Date of appointment(YY-MM-DD)', format='%Y-%m-%d',validators=[DateRange(min=date.today())])
    time = SelectField('Appointment time', [validators.DataRequired()], choices=[('9.00am - 9.30am','9.00am - 9.30am'),('10.00am - 10.30am', '10.00am - 10.30am'), ('11.00am - 11.30am', '11.00am - 11.30am'),('12.00pm -12.30pm','12.00pm -12.30pm'),('3.00pm - 3.30pm','3.00pm - 3.30pm'),('4.00pm - 4.30pm', '4.00pm - 4.30pm'),('5.00pm -5.30pm',' 5.00pm -5.30pm')], default = '9.00am - 9.30am')
    remarks = TextAreaField('Additional request', [validators.Optional()])
    doc=RadioField('Choice of doctor', choices=[('T', 'Dr Tan'), ('M', 'Dr Mok'), ('L', 'Dr Lim')], default='T')


class CreateProductForm(FlaskForm):
    categories = [('Medicine', 'Medicine'), ('Test Kit', 'Test Kit'), ('Supplement', 'Supplement'), ('First Aid', 'First Aid')]
    category = SelectField(u"Product Category", choices=categories)

    name = StringField("Product Name", validators=[InputRequired()])
    price = FloatField("Product Price($)", validators=[InputRequired()])
    short_description = StringField("Short Description:", validators=[InputRequired()])
    long_description = TextAreaField("Long Description:", validators=[InputRequired()])
    stock = IntegerField("Stock:", validators=[InputRequired()])

class Quantity(FlaskForm):
    quantity = IntegerField("Quantity:", [validators.DataRequired()])

class FeedbackForm(FlaskForm):
    name = StringField("Name:", [validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    subject = SelectField('Subject', [validators.DataRequired()], choices=[('Website Design','Website Design'),('Website Functions','Website Functions'),('General','General'),('Content','Content'),('Copyright','Copyright'),('Others','Others')], default = 'General')
    description = TextAreaField()
