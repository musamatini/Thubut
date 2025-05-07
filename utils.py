# utils.py
import os
import requests
from threading import Thread
from flask import current_app, url_for
from requests.auth import HTTPBasicAuth
import logging
# Removed Mail import as it's no longer used

# --- API Sending Function (using app context) ---
# _send_mailgun_api_email_sync remains largely the same, ensure it's robust.
# I'll assume it's fine from your provided code.

def _send_mailgun_api_email_sync(app, subject, sender, recipients, text_body, html_body):
    api_key = app.config.get('MAILGUN_API_KEY')
    domain = app.config.get('MAILGUN_DOMAIN')
    base_url = app.config.get('MAILGUN_API_BASE_URL', 'https://api.mailgun.net/v3')

    if not api_key or not domain:
        app.logger.error("Mailgun API key or domain not configured.")
        return

    api_url = f"{base_url}/{domain}/messages"
    if isinstance(recipients, str): recipients = [recipients]

    app.logger.info(f"Attempting to send email via Mailgun API to: {recipients} Subject: {subject}")
    try:
        response = requests.post(
            api_url,
            auth=HTTPBasicAuth("api", api_key),
            data={
                "from": sender,
                "to": recipients,
                "subject": subject,
                "text": text_body,
                "html": html_body
            },
            timeout=20
        )
        response.raise_for_status()
        app.logger.info(f"Mailgun email sent successfully to {recipients}! Status: {response.status_code}, Response ID: {response.json().get('id', 'N/A')}")
    except requests.exceptions.Timeout:
         app.logger.error(f"Mailgun API request timed out sending to {recipients}.")
    except requests.exceptions.HTTPError as e:
         error_message = f"Mailgun API HTTP error sending to {recipients}: {e}"
         if e.response is not None: error_message += f" | Status: {e.response.status_code} | Response: {e.response.text}"
         app.logger.error(error_message)
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Mailgun API request failed sending to {recipients}: {e}")
    except Exception as e:
        app.logger.error(f"Unexpected error in _send_mailgun_api_email_sync for {recipients}: {e}", exc_info=True)


def send_email(subject, recipients, text_body, html_body):
    app = current_app._get_current_object()
    sender_name = app.config.get('MAILGUN_SENDER_NAME', 'Thubut Team')
    mailgun_domain = app.config.get('MAILGUN_DOMAIN')
    if not mailgun_domain:
        app.logger.error("MAILGUN_DOMAIN not configured. Cannot determine sender.")
        return
    sender_email = f"{sender_name} <mailgun@{mailgun_domain}>" # mailgun@ or postmaster@ often works

    thread = Thread(target=_send_mailgun_api_email_sync,
                    args=(app, subject, sender_email, recipients, text_body, html_body))
    thread.daemon = True
    thread.start()
    app.logger.debug(f"Started background email thread for recipients: {recipients}")


def send_email_verification_code(user, code):
    """Prepares and sends the email verification code to the user."""
    app = current_app._get_current_object()
    app_name = app.config.get('MAILGUN_SENDER_NAME', 'Thubut')

    with app.app_context():
        # Link to a page where they can enter the code, pre-filling email if possible or just generic
        verify_url = url_for('verify_email', _external=True) # We'll create this route

    subject = f"Your Email Verification Code for {app_name}"
    text_body = f"""Dear {user.fullname or user.username},

Welcome to {app_name}!

Your email verification code is: {code}

Please enter this code on our website to activate your account. You can go to: {verify_url}
If you did not sign up for an account, please ignore this email.
This code will expire in 1 hour.

Sincerely,
The {app_name} Team
"""

    html_body = f"""
<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
    <h2 style="color: #0056b3; text-align: center;">Welcome to {app_name}!</h2>
    <p>Dear {user.fullname or user.username},</p>
    <p>Thank you for signing up. To complete your registration, please use the verification code below:</p>
    <p style="text-align: center; font-size: 28px; font-weight: bold; margin: 25px 0; letter-spacing: 3px; color: #28a745;">
        {code}
    </p>
    <p>You can enter this code on our verification page:</p>
    <p style="text-align: center; margin: 20px 0;">
        <a href="{verify_url}" style="display: inline-block; padding: 12px 25px; font-size: 16px; font-weight: bold; color: #ffffff; background-color: #007bff; border-radius: 5px; text-decoration: none;">Go to Verification Page</a>
    </p>
    <p>If the button doesn't work, copy and paste the following link into your web browser:</p>
    <p><a href="{verify_url}">{verify_url}</a></p>
    <p>If you did not sign up for an account, please ignore this email. This code will expire in 1 hour.</p>
    <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
    <p style="font-size: 0.9em; color: #777;">Sincerely,<br>The {app_name} Team</p>
</div>
"""
    send_email(subject=subject, recipients=[user.email], text_body=text_body, html_body=html_body)
    app.logger.info(f"Email verification code {code} sent to {user.email}")


def send_phone_verification_sms(user, code): # Placeholder
    """
    Placeholder for sending SMS.
    You'll need to integrate an SMS provider like Twilio here.
    """
    app = current_app._get_current_object()
    app.logger.info(f"SIMULATING SMS: To {user.phone_number}, Code: {code}")
    # Example with Twilio (conceptual, needs proper setup)
    # from twilio.rest import Client
    # account_sid = app.config['TWILIO_ACCOUNT_SID']
    # auth_token = app.config['TWILIO_AUTH_TOKEN']
    # client = Client(account_sid, auth_token)
    # try:
    #     message = client.messages.create(
    #         body=f"Your Thubut verification code is: {code}",
    #         from_=app.config['TWILIO_PHONE_NUMBER'],
    #         to=user.phone_number # Assumes E.164 format
    #     )
    #     app.logger.info(f"SMS sent to {user.phone_number}, SID: {message.sid}")
    # except Exception as e:
    #     app.logger.error(f"Failed to send SMS to {user.phone_number}: {e}")
    pass


def send_password_reset_email(user, token):
    app = current_app._get_current_object()
    app_name = app.config.get('MAILGUN_SENDER_NAME', 'Thubut')
    reset_url = url_for('reset_password_token_route', token=token, _external=True) # We'll create this route

    subject = f"Password Reset Request for {app_name}"
    text_body = f"""Dear {user.fullname or user.username},

You requested a password reset for your {app_name} account.
Click the link below to set a new password:
{reset_url}

If you did not request this, please ignore this email. This link is valid for 10 minutes.

Sincerely,
The {app_name} Team
"""
    html_body = f"""
<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
    <h2 style="color: #0056b3; text-align: center;">Password Reset Request</h2>
    <p>Dear {user.fullname or user.username},</p>
    <p>We received a request to reset the password for your {app_name} account associated with this email address.</p>
    <p>To reset your password, please click the button below:</p>
    <p style="text-align: center; margin: 20px 0;">
        <a href="{reset_url}" style="display: inline-block; padding: 12px 25px; font-size: 16px; font-weight: bold; color: #ffffff; background-color: #dc3545; border-radius: 5px; text-decoration: none;">Reset Your Password</a>
    </p>
    <p>If the button doesn't work, copy and paste the following link into your web browser:</p>
    <p><a href="{reset_url}">{reset_url}</a></p>
    <p>This link is valid for 10 minutes. If you did not request a password reset, please ignore this email or contact us if you have concerns.</p>
    <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
    <p style="font-size: 0.9em; color: #777;">Sincerely,<br>The {app_name} Team</p>
</div>
"""
    send_email(subject, [user.email], text_body, html_body)
    app.logger.info(f"Password reset email sent to {user.email}")