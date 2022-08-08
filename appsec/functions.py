from flask import render_template
from flask_mail import Message
from app import mail
import os

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


def send_password_reset_email(user):
    token = user.get_reset_token()

    msg = Message()
    msg.subject = "Password Reset"
    msg.sender = os.getenv('MAIL_USERNAME')
    msg.recipients = [user.email]
    msg.html = render_template('user/guest/reset_email.html', user=user, token=token)

    mail.send(msg)


def send_ban_email(user):
    msg = Message()
    msg.subject = "Ban alert"
    msg.sender = os.getenv('MAIL_USERNAME')
    message = "Dear %s! You have been banned from DoctorOnTheGo. Do contact one of our staff if you feel this was an unfair ban. Have a nice day!" % user.username
    msg.body = message
    msg.recipients = [user.email]

    mail.send(msg)


def send_unban_email(user):
    msg = Message()
    msg.subject = "Unban alert"
    msg.sender = os.getenv('MAIL_USERNAME')
    message = "Dear %s! You have been unbanned from DoctorOnTheGo. We apologise for the inconvenience. Have a nice day!" % user.username
    msg.body = message
    msg.recipients = [user.email]

    mail.send(msg)


def send_verification_email(user):
    token = user.get_reset_token()

    msg = Message()
    msg.subject = "Email verification"
    msg.sender = os.getenv('MAIL_USERNAME')
    msg.recipients = [user.email]
    msg.html = render_template('user/guest/verify_email.html', user=user, token=token)

    mail.send(msg)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
