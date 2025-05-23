# utils.py
import eventlet
eventlet.monkey_patch()
import os
import requests
from threading import Thread
# Added current_app import explicitly, also url_for is fine here
from flask import current_app, url_for
from requests.auth import HTTPBasicAuth
import logging
import datetime # Ensure datetime is imported for phone_verification_code_expires_at

# Assuming models.py and db are correctly set up for User query and db.session
from models import db, User # Import db and User for use in _send_rapidapi_sms_and_update_user_record

# --- Email Sending ---
def _send_mailgun_api_email_sync(app_context, subject, sender, recipients, text_body, html_body):
    # This function now expects app_context to be passed if it's called from a thread needing it
    # For direct calls from routes, current_app can be used.
    # However, since this is run in a thread by send_email, app_context is more robust.
    with app_context.app_context(): # Ensure app context for config access
        api_key = current_app.config.get('MAILGUN_API_KEY')
        domain = current_app.config.get('MAILGUN_DOMAIN')
        base_url = current_app.config.get('MAILGUN_API_BASE_URL', 'https://api.mailgun.net/v3')

        if not api_key or not domain:
            current_app.logger.error("Mailgun API key or domain not configured.")
            return

        api_url = f"{base_url}/{domain}/messages"
        if isinstance(recipients, str): recipients = [recipients]

        current_app.logger.info(f"Attempting to send email via Mailgun API to: {recipients} Subject: {subject}")
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
            current_app.logger.info(f"Mailgun email sent successfully to {recipients}! Status: {response.status_code}, Response ID: {response.json().get('id', 'N/A')}")
        except requests.exceptions.Timeout:
             current_app.logger.error(f"Mailgun API request timed out sending to {recipients}.")
        except requests.exceptions.HTTPError as e:
             error_message = f"Mailgun API HTTP error sending to {recipients}: {e}"
             if e.response is not None: error_message += f" | Status: {e.response.status_code} | Response: {e.response.text}"
             current_app.logger.error(error_message)
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Mailgun API request failed sending to {recipients}: {e}")
        except Exception as e: # Catch any other unexpected errors
            current_app.logger.error(f"Unexpected error in _send_mailgun_api_email_sync for {recipients}: {e}", exc_info=True)


def send_email(subject, recipients, text_body, html_body):
    app_instance = current_app._get_current_object() # Get app instance for the thread
    sender_name = app_instance.config.get('MAILGUN_SENDER_NAME', 'Thubut Team')
    mailgun_domain = app_instance.config.get('MAILGUN_DOMAIN')

    if not mailgun_domain:
        app_instance.logger.error("MAILGUN_DOMAIN not configured. Cannot determine sender.")
        return
    sender_email = f"{sender_name} <mailgun@{mailgun_domain}>"

    # Pass the app instance (or specifically its context) to the thread
    thread = Thread(target=_send_mailgun_api_email_sync,
                    args=(app_instance, subject, sender_email, recipients, text_body, html_body))
    thread.daemon = True
    thread.start()
    app_instance.logger.debug(f"Started background email thread for recipients: {recipients}")


def send_email_verification_code(user, code):
    app = current_app._get_current_object() # url_for needs app context if not in request
    app_name = app.config.get('MAILGUN_SENDER_NAME', 'Thubut')

    # url_for is called here, likely within a request context from a Flask route.
    # If this function were ever called outside a request context, it would need app.app_context().
    verify_url = url_for('verify_email', _external=True)

    subject = f"Your Email Verification Code for {app_name}"
    text_body = f"""Dear {user.fullname or user.username},
Welcome to {app_name}!
Your email verification code is: {code}
Please enter this code on our website: {verify_url}
This code will expire in 1 hour.
Sincerely,
The {app_name} Team"""
    html_body = f"""
<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
    <h2 style="color: #0056b3; text-align: center;">Welcome to {app_name}!</h2>
    <p>Dear {user.fullname or user.username},</p>
    <p>Your email verification code is: <strong style="font-size: 1.2em;">{code}</strong></p>
    <p>Enter this code at: <a href="{verify_url}">{verify_url}</a></p>
    <p>This code will expire in 1 hour.</p>
    <p>Sincerely,<br>The {app_name} Team</p>
</div>"""
    send_email(subject=subject, recipients=[user.email], text_body=text_body, html_body=html_body)
    app.logger.info(f"Email verification code {code} sent to {user.email}")


def send_password_reset_email(user, token):
    app = current_app._get_current_object()
    app_name = app.config.get('MAILGUN_SENDER_NAME', 'Thubut')
    reset_url = url_for('reset_password_token_route', token=token, _external=True)

    subject = f"Password Reset Request for {app_name}"
    text_body = f"""Dear {user.fullname or user.username},
To reset your password, visit: {reset_url}
If you did not request this, please ignore this email. This link is valid for 10 minutes.
Sincerely,
The {app_name} Team"""
    html_body = f"""
<div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
    <h2 style="color: #0056b3; text-align: center;">Password Reset Request</h2>
    <p>Dear {user.fullname or user.username},</p>
    <p>To reset your password, click the link: <a href="{reset_url}">{reset_url}</a></p>
    <p>This link is valid for 10 minutes. If you did not request this, please ignore this email.</p>
    <p>Sincerely,<br>The {app_name} Team</p>
</div>"""
    send_email(subject, [user.email], text_body, html_body)
    app.logger.info(f"Password reset email sent to {user.email}")


# --- Phone SMS Sending (RapidAPI) ---
def _send_rapidapi_sms_and_update_user_record(app_context, user_id_to_update):
    """
    Synchronous function to send SMS via RapidAPI and update the user's verification code.
    This function runs within the app_context provided by the thread caller.
    The RapidAPI /send-numeric-verify endpoint is expected to generate its own code
    and return it in the response.
    """
    with app_context.app_context(): # Ensure app context for config and DB access
        api_key = current_app.config.get('RAPIDAPI_KEY')
        api_host = current_app.config.get('RAPIDAPI_SMS_VERIFY_HOST')
        # MODIFIED: Correct endpoint URL based on docs if host didn't include path
        # Assuming api_host is just the hostname, this is correct.
        api_url = f"https://{api_host}/send-numeric-verify"


        if not api_key or not api_host:
            current_app.logger.error("RapidAPI key or host not configured. Cannot send SMS.")
            # db.session.rollback() # No session changes to roll back yet
            return False

        user = db.session.get(User, user_id_to_update) # Use db.session.get for SQLAlchemy 2.0+
        if not user:
            current_app.logger.error(f"User with ID {user_id_to_update} not found for SMS.")
            # db.session.rollback()
            return False
        
        # Added check for confirmed phone number to prevent resending if already confirmed
        if user.phone_confirmed:
             current_app.logger.info(f"Phone number {user.phone_number} for user {user.id} is already confirmed. Skipping SMS.")
             # db.session.rollback()
             return True # Indicate success from the perspective of not needing to send

        if not user.phone_number or not user.phone_number.startswith('+'):
            current_app.logger.error(f"Cannot send SMS to user {user.id}: Invalid phone number format '{user.phone_number}'. Needs E.164.")
            # db.session.rollback()
            return False

        headers = {
            "content-type": "application/json",
            "x-rapidapi-host": api_host,
            "x-rapidapi-key": api_key
        }
        # MODIFIED: Correct payload for "Send Verify SMS" - remove "estimate": True
        payload = {
            "target": user.phone_number
        }

        current_app.logger.info(f"Attempting to send verification SMS to: {user.phone_number} via RapidAPI.")
        current_app.logger.debug(f"SMS Payload for send-numeric-verify: {payload}")

        try:
            response = requests.post(api_url, json=payload, headers=headers, timeout=25)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            response_data = response.json()
            current_app.logger.info(f"RapidAPI SMS request successful for {user.phone_number}! Status: {response.status_code}, Response: {response_data}")

            # ---- CRITICAL: Extract API-generated code from response_data ----
            # Based on the documentation provided for the "Send Verify SMS" endpoint,
            # the code is returned in the 'verify_code' key.
            
            api_generated_code = response_data.get('verify_code')
            
            if api_generated_code:
                # MODIFIED: Use the dedicated method in the User model
                user.set_phone_verification_code_details(api_generated_code, expiry_minutes=10)
                db.session.commit()
                current_app.logger.info(f"User {user.id} phone_verification_code updated with API-generated code.")
                return True
            else:
                # This means the API call was 200 OK, but 'verify_code' was not in the response.
                # This shouldn't happen based on the docs for the Send endpoint, but log it.
                current_app.logger.error(f"RapidAPI 'Send Verify SMS' succeeded (200 OK) but 'verify_code' key was missing or empty in response for {user.phone_number}. Response: {response_data}. "
                                         "The user's phone_verification_code in DB will NOT be updated.")
                # db.session.rollback() # No session changes to roll back
                return False # Indicate failure to get/store the code

        except requests.exceptions.Timeout:
            current_app.logger.error(f"RapidAPI SMS request timed out for {user.phone_number}.")
            # db.session.rollback()
        except requests.exceptions.HTTPError as e:
            error_message = f"RapidAPI SMS HTTP error for {user.phone_number}: {e}"
            if e.response is not None:
                error_message += f" | Status: {e.response.status_code} | Response: {e.response.text}"
                current_app.logger.debug(f"RapidAPI Error Response Body: {e.response.text}")
            current_app.logger.error(error_message)
            # db.session.rollback()
        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"RapidAPI SMS request failed for {user.phone_number}: {e}")
            # db.session.rollback()
        except Exception as e:
            current_app.logger.error(f"Unexpected error in _send_rapidapi_sms_and_update_user_record for {user.phone_number}: {e}", exc_info=True)
            # db.session.rollback()
        
        # If any exception occurred before commit, the session is likely not clean.
        # It's generally safer to rollback on any API call failure that might leave the session in a partial state,
        # *unless* you're explicitly handling retries or partial updates.
        # Given this is in a thread, rollback is safest.
        with app_context.app_context():
             # Check if a transaction is active before rolling back
             if db.session.dirty or db.session.new or db.session.deleted:
                  db.session.rollback()
                  current_app.logger.warning("Rolled back DB session in _send_rapidapi_sms_and_update_user_record due to error.")


        return False # Indicate failure to send/process SMS


def send_phone_verification_sms(user_for_sms):
    app_instance = current_app._get_current_object()

    if not app_instance.config.get('RAPIDAPI_KEY'):
        app_instance.logger.warning("SMS sending skipped: RAPIDAPI_KEY not configured.")
        return

    # Use user_for_sms.id for safety in the thread
    if not user_for_sms or not hasattr(user_for_sms, 'id') or not user_for_sms.phone_number:
        app_instance.logger.error(f"Invalid user or no phone number for send_phone_verification_sms. User: {user_for_sms}")
        return

    # Pass app_instance (which is the app object) and user_id to the thread.
    thread = Thread(target=_send_rapidapi_sms_and_update_user_record, args=(app_instance, user_for_sms.id))
    thread.daemon = True
    thread.start()
    app_instance.logger.info(f"Phone verification SMS process queued for user ID: {user_for_sms.id}, phone: {user_for_sms.phone_number}")