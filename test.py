import os
import requests
import socket
import sys
from requests.auth import HTTPBasicAuth

# --- Configuration ---
# Reading from your specific environment variables
# !! IMPORTANT ASSUMPTION: MAIL_PASSWORD contains your Mailgun *API Key* !!
MAIL_API_KEY = os.environ.get("MAIL_PASSWORD")
MAIL_SMTP_SERVER = os.environ.get("MAIL_SERVER")
# We don't strictly need MAIL_USERNAME for API auth, but good to check if set
MAIL_USERNAME = os.environ.get("MAIL_USERNAME")

# Determine Mailgun API Base URL based on MAIL_SERVER
MAILGUN_API_BASE_URL = None
EXPECTED_MAILGUN_API_HOST = None

# --- Helper Function for Status ---
def print_status(message, success=True):
    """Prints a formatted status message."""
    prefix = "[ OK ]" if success else "[FAIL]"
    print(f"{prefix} {message}")

# --- Main Test Logic ---
def test_mailgun_connection():
    """Runs tests to check Mailgun API connectivity and authentication using provided env vars."""
    global MAILGUN_API_BASE_URL, EXPECTED_MAILGUN_API_HOST # Allow modification

    print("-" * 30)
    print("Starting Mailgun Connection Test (using Flask-Mail like env vars)...")
    print("-" * 30)

    # 1. Check if Credentials are Set
    print("1. Checking Configuration...")
    if not MAIL_API_KEY:
        print_status("MAIL_PASSWORD environment variable not found.", success=False)
        print("   This script assumes MAIL_PASSWORD holds your Mailgun API Key.")
        # Optionally hardcode for quick local testing, but REMOVE before deploying
        # MAIL_API_KEY = "key-YOUR_ACTUAL_API_KEY"
        # if not MAIL_API_KEY: # Check again if hardcoded
        #     sys.exit(1)
    else:
        # Basic sanity check if it looks like an API key
        if MAIL_API_KEY.startswith("key-"):
             print_status(f"MAIL_PASSWORD found (looks like API Key, starts with: {MAIL_API_KEY[:8]}...).")
        else:
             print_status(f"MAIL_PASSWORD found, but it doesn't start with 'key-'.")
             print(f"   !! Make sure this variable ('{MAIL_API_KEY[:5]}...') actually holds your Mailgun *API* Key for this test !!")


    if not MAIL_SMTP_SERVER:
        print_status("MAIL_SERVER environment variable not found.", success=False)
        # Optionally hardcode for quick local testing, but REMOVE before deploying
        # MAIL_SMTP_SERVER = "smtp.mailgun.org" # Or smtp.eu.mailgun.org
        # if not MAIL_SMTP_SERVER: # Check again if hardcoded
        #      sys.exit(1)
    else:
        print_status(f"MAIL_SERVER found: {MAIL_SMTP_SERVER}")
        # Infer API URL
        if "eu.mailgun.org" in MAIL_SMTP_SERVER.lower():
            MAILGUN_API_BASE_URL = "https://api.eu.mailgun.net/v3"
            EXPECTED_MAILGUN_API_HOST = "api.eu.mailgun.net"
            print(f"   -> Inferred EU Region API Base URL: {MAILGUN_API_BASE_URL}")
        elif "mailgun.org" in MAIL_SMTP_SERVER.lower():
             MAILGUN_API_BASE_URL = "https://api.mailgun.net/v3"
             EXPECTED_MAILGUN_API_HOST = "api.mailgun.net"
             print(f"   -> Inferred US Region API Base URL: {MAILGUN_API_BASE_URL}")
        else:
            print_status(f"Could not determine Mailgun region from MAIL_SERVER: {MAIL_SMTP_SERVER}", success=False)
            print("   Please ensure MAIL_SERVER is set to 'smtp.mailgun.org' or 'smtp.eu.mailgun.org'.")
            print("   Cannot proceed without determining API endpoint.")
            sys.exit(1)

    # Optional: Check MAIL_USERNAME just for info
    if MAIL_USERNAME:
        print_status(f"MAIL_USERNAME found: {MAIL_USERNAME}")
    else:
        print_status("MAIL_USERNAME environment variable not found (Informational).")


    if not MAIL_API_KEY or not MAILGUN_API_BASE_URL:
        print("\n[ERROR] Missing critical configuration derived from MAIL_PASSWORD or MAIL_SERVER.")
        sys.exit(1)

    # 2. Basic Network Connectivity Test (Socket Connection to API Host)
    print("\n2. Testing Basic Network Connection to Mailgun API Host...")
    hostname = EXPECTED_MAILGUN_API_HOST
    port = 443 # HTTPS port
    print(f"   Attempting to connect to {hostname}:{port}...")
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            print_status(f"Successfully connected to {hostname} on port {port}.")
    except socket.gaierror as e:
        print_status(f"DNS lookup failed for {hostname}: {e}", success=False)
        print("   Check your DNS configuration or if the hostname derived from MAIL_SERVER is correct.")
        sys.exit(1)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print_status(f"Failed to connect to {hostname}:{port}: {e}", success=False)
        print("   Check network connectivity, firewalls (less likely on Render outbound), or Mailgun API status.")
        sys.exit(1)
    except Exception as e:
        print_status(f"An unexpected error occurred during network test: {e}", success=False)
        sys.exit(1)


    # 3. Mailgun API Authentication Test (Using a generic endpoint)
    print(f"\n3. Testing Mailgun API Authentication...")
    # We'll use the '/domains' endpoint which requires auth but not a specific domain name
    # This avoids needing a separate MAILGUN_DOMAIN env var if not present
    test_url = f"{MAILGUN_API_BASE_URL}/domains"
    print(f"   Making GET request to: {test_url}")
    print(f"   Using 'api' as username and content of MAIL_PASSWORD as the API Key.")

    try:
        response = requests.get(
            test_url,
            auth=HTTPBasicAuth('api', MAIL_API_KEY), # Use 'api' user, key from MAIL_PASSWORD
            timeout=15 # Set a reasonable timeout
        )

        print(f"   HTTP Status Code: {response.status_code}")

        if response.status_code == 200:
            print_status("Authentication successful! Able to connect and authenticate with the Mailgun API.")
            try:
                # Try to show how many domains were found, as confirmation
                domain_count = len(response.json().get('items', []))
                print(f"   Successfully listed domains (found {domain_count}).")
            except Exception as json_e:
                print_status(f"   Successfully authenticated, but failed to parse JSON response: {json_e}", success=False)
        elif response.status_code == 401:
            print_status("Authentication failed (Unauthorized).", success=False)
            print("   Check the value of your MAIL_PASSWORD environment variable.")
            print("   Ensure it contains the correct Mailgun *API Key* (starting with 'key-').")
            print(f"   Response body: {response.text[:200]}...") # Show beginning of error
        elif response.status_code == 404:
             print_status("API endpoint not found.", success=False)
             print(f"   The URL {test_url} seems incorrect.")
             print(f"   This might happen if MAIL_SERVER ('{MAIL_SMTP_SERVER}') led to the wrong API region.")
             print(f"   Response body: {response.text[:200]}...")
        else:
            print_status(f"Received unexpected HTTP status code: {response.status_code}", success=False)
            print(f"   Response body: {response.text[:500]}...") # Show more body for other errors

    except requests.exceptions.Timeout:
        print_status("API request timed out.", success=False)
        print("   The connection was established, but Mailgun didn't respond in time.")
        print("   Could be a temporary Mailgun issue or network latency.")
    except requests.exceptions.ConnectionError as e:
        print_status("API request failed due to a connection error.", success=False)
        print(f"   Error details: {e}")
        print("   This indicates a deeper network issue, possibly beyond the basic socket test.")
    except requests.exceptions.RequestException as e:
        print_status(f"An error occurred during the API request: {e}", success=False)
        print(f"   Response (if any): {getattr(e, 'response', 'N/A')}")
    except Exception as e:
         print_status(f"An unexpected error occurred during API test: {e}", success=False)


    print("-" * 30)
    print("Mailgun Connection Test Finished.")
    print("-" * 30)


if __name__ == "__main__":
    test_mailgun_connection()