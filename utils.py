# utils.py
import os
import requests
from threading import Thread
from flask import current_app, url_for
from requests.auth import HTTPBasicAuth
import logging

# --- API Sending Function (using app context) ---
def _send_mailgun_api_email_sync(app, subject, sender, recipients, text_body, html_body):
    """
    Synchronous function to send email via Mailgun API.
    Intended to be run in a background thread. Requires app context.
    """
    # Prefer app.config, fall back to os.environ just in case
    api_key = app.config.get('MAILGUN_API_KEY') or os.environ.get('MAILGUN_API_KEY')
    domain = app.config.get('MAILGUN_DOMAIN') or os.environ.get('MAILGUN_DOMAIN')
    base_url = app.config.get('MAILGUN_API_BASE_URL', 'https://api.mailgun.net/v3') # Default to US

    if not api_key:
        app.logger.error("MAILGUN_API_KEY not configured. Cannot send email.")
        return
    if not domain:
        app.logger.error("MAILGUN_DOMAIN not configured. Cannot send email.")
        return

    api_url = f"{base_url}/{domain}/messages"

    # Ensure recipients is a list
    if isinstance(recipients, str):
        recipients = [recipients]
    if not recipients:
         app.logger.error("No recipients provided for email.")
         return

    app.logger.info(f"Attempting to send email via Mailgun API to: {recipients} Subject: {subject}")

    try:
        # No need for extra app.app_context() here, as this function
        # should already be running within one provided by the thread caller.
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
            timeout=20 # Slightly longer timeout for network operations
        )

        # Check for HTTP errors (4xx or 5xx)
        response.raise_for_status()

        # Log success with details
        app.logger.info(f"Mailgun email sent successfully to {recipients}! Status: {response.status_code}, Response ID: {response.json().get('id', 'N/A')}")

    except requests.exceptions.Timeout:
         app.logger.error(f"Mailgun API request timed out sending to {recipients}.")
    except requests.exceptions.HTTPError as e:
         # Log HTTP errors specifically, including response body if possible
         error_message = f"Mailgun API HTTP error sending to {recipients}: {e}"
         if e.response is not None:
             error_message += f" | Status: {e.response.status_code} | Response: {e.response.text}"
         app.logger.error(error_message)
    except requests.exceptions.RequestException as e:
        # Log other requests-related errors (DNS, connection, etc.)
        app.logger.error(f"Mailgun API request failed sending to {recipients}: {e}")
    except Exception as e:
        # Catch any other unexpected errors during the process
        app.logger.error(f"Unexpected error in _send_mailgun_api_email_sync for {recipients}: {e}", exc_info=True)


# --- Function to Initiate Background Email Sending ---
def send_email(subject, recipients, text_body, html_body):
    """
    Starts a background thread to send an email using the Mailgun API.
    """
    # Get the current app instance safely for the thread context
    app = current_app._get_current_object()

    # Construct the sender address using config values
    sender_name = app.config.get('MAILGUN_SENDER_NAME', 'Your App') # Default name
    mailgun_domain = app.config.get('MAILGUN_DOMAIN')
    if not mailgun_domain:
        app.logger.error("MAILGUN_DOMAIN not configured. Cannot determine sender for email.")
        return
    sender_email = f"{sender_name} <postmaster@{mailgun_domain}>"

    # Pass necessary args to the sync function running in the thread
    thread = Thread(target=_send_mailgun_api_email_sync,
                    args=(app, subject, sender_email, recipients, text_body, html_body))
    thread.daemon = True # Allow app to exit even if threads are running
    thread.start()
    app.logger.debug(f"Started background email thread for recipients: {recipients}")


# --- Function to Send Confirmation Email (Content unchanged, uses new send_email) ---
def send_confirmation_email(user):
    """Prepares and sends the email confirmation email for a user."""
    app = current_app._get_current_object() # Required for url_for

    # Generate token and URL within app context
    with app.app_context():
        token = user.get_email_confirmation_token()
        # *** IMPORTANT: Use the correct route name from app.py ***
        # If your route is @app.route('/confirm/<token>'), use 'confirm_email'
        # If it was in a blueprint named 'auth', you'd use 'auth.confirm_email'
        confirm_url = url_for('confirm_email', token=token, _external=True)

    subject = f"Confirm Your Email Address for {app.config.get('MAILGUN_SENDER_NAME', 'Thubut')}" # Use configured name

    # Prepare email bodies
    text_body = f"""Dear {user.fullname or user.username},

Welcome to {app.config.get('MAILGUN_SENDER_NAME', 'Thubut')}!

To complete your registration and activate your account, please confirm your email address by clicking the following link:
{confirm_url}

If you did not sign up for an account, please ignore this email.

This link will expire in 1 hour.

Sincerely,
The {app.config.get('MAILGUN_SENDER_NAME', 'Thubut')} Team
"""

    html_body = f"""
<p>Dear {user.fullname or user.username},</p>
<p>Welcome to <strong>{app.config.get('MAILGUN_SENDER_NAME', 'Thubut')}</strong>!</p>
<p>To complete your registration and activate your account, please confirm your email address by clicking the button below:</p>
<p style="margin: 20px 0;">
    <a href="{confirm_url}" style="display: inline-block; padding: 12px 25px; font-size: 16px; font-weight: bold; color: #ffffff; background-color: #28a745; border-radius: 5px; text-decoration: none;">Confirm Email Address</a>
</p>
<p>If the button doesn't work, copy and paste the following link into your web browser:</p>
<p><a href="{confirm_url}">{confirm_url}</a></p>
<p>If you did not sign up for an account, please ignore this email.</p>
<p>This link will expire in 1 hour.</p>
<p>Sincerely,<br>The {app.config.get('MAILGUN_SENDER_NAME', 'Thubut')} Team</p>
"""

    # Call the main send_email function (which now uses the API via background thread)
    # Ensure user.email is passed as a list
    send_email(subject=subject,
               recipients=[user.email],
               text_body=text_body,
               html_body=html_body)
    app.logger.info(f"Confirmation email queued for {user.email}")