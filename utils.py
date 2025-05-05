import os
import requests
from threading import Thread
from flask import current_app, url_for
from requests.auth import HTTPBasicAuth
import logging # Use standard logging

# Configure logging (if not already done elsewhere in your app)
# logging.basicConfig(level=logging.INFO) # Or use Flask's app.logger

# --- New Function to Send Email via Mailgun API ---
def send_mailgun_api_email(app, subject, sender, recipients, text_body, html_body):
    """
    Sends an email using the Mailgun API.
    Runs within the Flask app context provided.
    """
    # Get Mailgun credentials from environment/config
    # Use app.config for consistency if you set them there, otherwise os.environ
    api_key = app.config.get('MAILGUN_API_KEY') or os.environ.get('MAILGUN_API_KEY')
    domain = app.config.get('MAILGUN_DOMAIN') or os.environ.get('MAILGUN_DOMAIN')
    # Optional: Define base URL or determine from domain/region if needed
    base_url = app.config.get('MAILGUN_API_BASE_URL', "https://api.mailgun.net/v3")

    if not api_key or not domain:
        app.logger.error("Mailgun API Key or Domain not configured. Cannot send email.")
        return

    api_url = f"{base_url}/{domain}/messages"

    # Ensure recipients is a list of strings
    if isinstance(recipients, str):
        recipients = [recipients]

    try:
        with app.app_context(): # Ensure context for logging, etc.
            response = requests.post(
                api_url,
                auth=HTTPBasicAuth("api", api_key), # Use 'api' username and the key
                data={
                    "from": sender,
                    "to": recipients, # requests handles lists here
                    "subject": subject,
                    "text": text_body,
                    "html": html_body
                },
                timeout=15 # Add a timeout
            )

            # Check for HTTP errors (4xx or 5xx)
            response.raise_for_status()

            app.logger.info(f"Mailgun email sent successfully to {recipients}! Status: {response.status_code}, Response: {response.text[:100]}...") # Log success

    except requests.exceptions.RequestException as e:
        # Log detailed error information
        error_message = f"Mailgun API request failed: {e}"
        if e.response is not None:
            error_message += f" | Status: {e.response.status_code} | Response: {e.response.text}"
        app.logger.error(error_message)
    except Exception as e:
        # Catch any other unexpected errors
        app.logger.error(f"Unexpected error sending email via Mailgun API: {e}")

# --- Modified Function to Initiate Sending ---
# This function now prepares data for the API call and starts the thread
def send_email(subject, recipients, text_body, html_body):
    app = current_app._get_current_object() # Get the current app instance safely

    # Get the sender email address.
    # Option 1: Use MAIL_DEFAULT_SENDER from config if set
    # sender = app.config.get('MAIL_DEFAULT_SENDER')
    # Option 2: Construct it using the Mailgun domain (often preferred for API)
    mailgun_domain = app.config.get('MAILGUN_DOMAIN') or os.environ.get('MAILGUN_DOMAIN')
    if not mailgun_domain:
        app.logger.error("MAILGUN_DOMAIN not set, cannot determine sender.")
        return
    # You might want a specific sender name too:
    sender = f"Thubut Team <postmaster@{mailgun_domain}>"
    # Or just: sender = f"postmaster@{mailgun_domain}"

    if not sender:
         app.logger.error("Sender email address could not be determined.")
         return

    # Start the background thread to send the email via API
    # Pass all necessary arguments to the target function
    thread = Thread(target=send_mailgun_api_email,
                    args=(app, subject, sender, recipients, text_body, html_body))
    thread.start()
    app.logger.info(f"Started background thread to send email to {recipients}") # Log thread start

# --- Your Existing Function (No changes needed here) ---
def send_confirmation_email(user):
    app = current_app._get_current_object() # Need app context for url_for
    with app.app_context():
        token = user.get_email_confirmation_token()
        confirm_url = url_for('auth.confirm_email', token=token, _external=True) # Make sure 'auth.confirm_email' is your blueprint/route name
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
    # Ensure user.email is passed as a list
    send_email(subject, [user.email], text_body, html_body)