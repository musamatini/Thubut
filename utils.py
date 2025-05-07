# utils.py
import os
import requests
from threading import Thread
from flask import current_app
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


def _send_rapidapi_sms_and_update_user_record(app_context, user_id_to_update):
    """
    Synchronous function to send SMS via RapidAPI and update the user's verification code.
    This function is designed to be run in a background thread WITH an app_context.
    It assumes the RapidAPI /send-numeric-verify endpoint generates its own code.
    """
    # This function now operates within the app_context provided by the thread caller
    
    api_key = current_app.config.get('RAPIDAPI_KEY') # Use current_app since we have context
    api_host = current_app.config.get('RAPIDAPI_SMS_VERIFY_HOST')
    api_url = f"https://{api_host}/send-numeric-verify"

    if not api_key or not api_host:
        current_app.logger.error("RapidAPI key or host not configured. Cannot send SMS.")
        return False

    # Fetch the user within this thread's context to ensure fresh session
    user = User.query.get(user_id_to_update)
    if not user:
        current_app.logger.error(f"User with ID {user_id_to_update} not found for SMS.")
        return False
    
    if not user.phone_number or not user.phone_number.startswith('+'):
        current_app.logger.error(f"Cannot send SMS to user {user.id}: Invalid phone number format '{user.phone_number}'. Needs E.164.")
        return False

    headers = {
        "content-type": "application/json",
        "x-rapidapi-host": api_host,
        "x-rapidapi-key": api_key
    }
    payload = {
        "target": user.phone_number,
        "estimate": True # As per your cURL example
    }

    current_app.logger.info(f"Attempting to send verification SMS to: {user.phone_number} via RapidAPI.")
    current_app.logger.debug(f"SMS Payload: {payload}")

    try:
        response = requests.post(api_url, json=payload, headers=headers, timeout=25) # Increased timeout slightly
        response.raise_for_status()
        response_data = response.json()
        current_app.logger.info(f"RapidAPI SMS request successful for {user.phone_number}! Status: {response.status_code}, Response: {response_data}")

        # ---- CRITICAL PART: Extract API-generated code ----
        # You MUST inspect the actual JSON response from the API to find the field containing the code.
        # Common names could be "pin", "code", "verification_code", "otp", etc.
        # Example: if response_data = {"status": "success", "pin": "123456", "transaction_id": "xyz"}
        
        api_generated_code = None
        if isinstance(response_data, dict):
            # Try common keys, adjust based on actual API response
            possible_code_keys = ['pin', 'code', 'verificationCode', 'otp', 'numeric_code']
            for key in possible_code_keys:
                if key in response_data:
                    api_generated_code = str(response_data[key]) # Ensure it's a string
                    break
            
            if not api_generated_code and 'message' in response_data and 'id' in response_data: # Fallback for some APIs
                 current_app.logger.warning(f"API response for {user.phone_number}: {response_data}. No clear code field. Check 'message' or 'id'. You may need to adjust parsing.")
                 # This is a guess if the API is less direct.
                 # Some APIs might return a message like "Verification code 123456 sent."
                 # Or the 'id' might be the code. This is unlikely for 'send-numeric-verify'.

        if api_generated_code:
            user.phone_verification_code = api_generated_code
            user.phone_verification_code_expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10) # Reset expiry
            db.session.commit()
            current_app.logger.info(f"User {user.id} phone_verification_code updated to API-generated: {api_generated_code}")
            return True
        else:
            current_app.logger.error(f"Could not extract verification code from RapidAPI response for {user.phone_number}. Response: {response_data}")
            return False

    except requests.exceptions.Timeout:
        current_app.logger.error(f"RapidAPI SMS request timed out for {user.phone_number}.")
    except requests.exceptions.HTTPError as e:
        error_message = f"RapidAPI SMS HTTP error for {user.phone_number}: {e}"
        if e.response is not None:
            error_message += f" | Status: {e.response.status_code} | Response: {e.response.text}"
            # Log the actual response text for debugging
            current_app.logger.debug(f"RapidAPI Error Response Body: {e.response.text}")
        current_app.logger.error(error_message)
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"RapidAPI SMS request failed for {user.phone_number}: {e}")
    except Exception as e:
        current_app.logger.error(f"Unexpected error in _send_rapidapi_sms_and_update_user_record for {user.phone_number}: {e}", exc_info=True)
    
    # If an error occurred before committing, rollback to be safe,
    # though individual commits are preferred inside the try block.
    # db.session.rollback() # Be cautious with rollback in a shared session context.
    return False


def send_phone_verification_sms(user_for_sms):
    """
    Starts a background thread to send a phone verification SMS using RapidAPI.
    The API is expected to generate the code, which will then update the user's record.
    """
    app_instance = current_app._get_current_object() # Get the current app instance for the thread

    if not app_instance.config.get('RAPIDAPI_KEY'):
        app_instance.logger.warning("SMS sending skipped: RAPIDAPI_KEY not configured.")
        return

    if not user_for_sms or not hasattr(user_for_sms, 'id'):
        app_instance.logger.error("Invalid user object passed to send_phone_verification_sms.")
        return

    # We pass user_for_sms.id to avoid passing the SQLAlchemy User object directly
    # across thread boundaries if it's not thread-safe or to avoid detached instance issues.
    # The target function will re-fetch the user by ID.
    thread = Thread(target=_send_rapidapi_sms_with_context, args=(app_instance, user_for_sms.id))
    thread.daemon = True
    thread.start()
    app_instance.logger.info(f"Phone verification SMS process queued for user ID: {user_for_sms.id}, phone: {user_for_sms.phone_number}")

def _send_rapidapi_sms_with_context(app, user_id):
    """Helper to run the SMS sending function within an app context in the thread."""
    with app.app_context():
        _send_rapidapi_sms_and_update_user_record(app, user_id)