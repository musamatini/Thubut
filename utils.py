from flask_mail import Message
from flask import current_app, url_for
from threading import Thread
# REMOVED: from app import mail # Remove this from the top

def send_async_email(app, msg):
    # Import mail here, only when the function is called
    from app import mail
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            # Use app.logger for proper logging in Flask
            app.logger.error(f"Failed to send email: {e}")

def send_email(subject, recipients, text_body, html_body):
    app = current_app._get_current_object()
    msg = Message(subject, sender=app.config['MAIL_DEFAULT_SENDER'], recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    Thread(target=send_async_email, args=(app, msg)).start()

def send_confirmation_email(user):
    token = user.get_email_confirmation_token()
    confirm_url = url_for('confirm_email', token=token, _external=True) # Changed route name
    subject = "Confirm Your Email Address for Thubut"
    text_body = f"""Dear {user.fullname},

Welcome to Thubut!

To complete your registration and activate your account, please confirm your email address by clicking the following link:
{confirm_url}

If you did not sign up for a Thubut account, please ignore this email.

This link will expire in 1 hour.

Sincerely,
The Thubut Team
"""
    html_body = f"""
<p>Dear {user.fullname},</p>
<p>Welcome to <strong>Thubut</strong>!</p>
<p>To complete your registration and activate your account, please confirm your email address by clicking the button below:</p>
<p><a href="{confirm_url}" style="display: inline-block; padding: 10px 20px; font-size: 16px; color: #ffffff; background-color: #4CAF50; border-radius: 5px; text-decoration: none;">Confirm Email Address</a></p>
<p>If the button doesn't work, copy and paste the following link into your web browser:</p>
<p><a href="{confirm_url}">{confirm_url}</a></p>
<p>If you did not sign up for a Thubut account, please ignore this email.</p>
<p>This link will expire in 1 hour.</p>
<p>Sincerely,<br>The Thubut Team</p>
"""
    send_email(subject, [user.email], text_body, html_body)