from flask import render_template
from flask_mail import Message
from app import mail
import os


def send_password_reset_email(user):
    token = user.get_reset_token()

    msg = Message()
    msg.subject = "Password Reset"
    msg.sender = os.getenv('MAIL_USERNAME')
    msg.recipients = [user.email]
    msg.html = render_template('user/guest/reset_email.html', user=user, token=token)

    mail.send(msg)
