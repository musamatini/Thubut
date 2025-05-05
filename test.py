import os
import requests
import socket
import sys
from requests.auth import HTTPBasicAuth

# --- Configuration ---
# !! BEST PRACTICE: Use Environment Variables !!
# Set these in your Render environment settings
MAILGUN_API_KEY = os.environ.get("MAILGUN_API_KEY")
MAILGUN_DOMAIN = os.environ.get("MAILGUN_DOMAIN")
# Optional: Set if you are using the EU region
MAILGUN_API_BASE_URL = os.environ.get("MAILGUN_API_BASE_URL", "https://api.mailgun.net/v3")
# --- End Configuration ---

# --- Helper Function for Status ---
def print_status(message, success=True):
    """Prints a formatted status message."""
    prefix = "[ OK ]" if success else "[FAIL]"
    print(f"{prefix} {message}")

# --- Main Test Logic ---
def test_mailgun_connection():
    """Runs tests to check Mailgun connectivity and authentication."""
    print("-" * 30)
    print("Starting Mailgun Connection Test...")
    print("-" * 30)

    # 1. Check if Credentials are Set
    print("1. Checking Configuration...")
    if not MAILGUN_API_KEY:
        print_status("MAILGUN_API_KEY environment variable not found.", success=False)
        # Optionally hardcode for quick local testing, but REMOVE before deploying
        # MAILGUN_API_KEY = "key-YOUR_ACTUAL_API_KEY"
        # if not MAILGUN_API_KEY.startswith("key-"): # Basic sanity check
        #    print_status("MAILGUN_API_KEY does not look like a valid key.", success=False)
        #    sys.exit(1) # Exit if critical config is missing
    else:
        print_status(f"MAILGUN_API_KEY found (starts with: {MAILGUN_API_KEY[:8]}...).") # Show only prefix

    if not MAILGUN_DOMAIN:
        print_status("MAILGUN_DOMAIN environment variable not found.", success=False)
        # Optionally hardcode for quick local testing, but REMOVE before deploying
        # MAILGUN_DOMAIN = "YOUR_MAILGUN_DOMAIN" # e.g., mg.yourdomain.com or yourdomain.com
        # if not MAILGUN_DOMAIN:
        #     print_status("MAILGUN_DOMAIN is missing.", success=False)
        #     sys.exit(1) # Exit if critical config is missing
    else:
        print_status(f"MAILGUN_DOMAIN found: {MAILGUN_DOMAIN}")

    print(f"Using Mailgun API Base URL: {MAILGUN_API_BASE_URL}")

    if not MAILGUN_API_KEY or not MAILGUN_DOMAIN:
        print("\n[ERROR] Missing critical configuration. Please set environment variables.")
        sys.exit(1)

    # 2. Basic Network Connectivity Test (Socket Connection)
    print("\n2. Testing Basic Network Connection to Mailgun API Host...")
    try:
        # Extract hostname from the base URL
        hostname = MAILGUN_API_BASE_URL.split('//')[1].split('/')[0]
        port = 443 # HTTPS port
        print(f"   Attempting to connect to {hostname}:{port}...")
        with socket.create_connection((hostname, port), timeout=10) as sock:
            print_status(f"Successfully connected to {hostname} on port {port}.")
    except socket.gaierror as e:
        print_status(f"DNS lookup failed for {hostname}: {e}", success=False)
        print("   Check your DNS configuration or if the hostname is correct.")
        sys.exit(1)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print_status(f"Failed to connect to {hostname}:{port}: {e}", success=False)
        print("   Check network connectivity, firewalls (less likely on Render outbound), or Mailgun status.")
        sys.exit(1)
    except Exception as e:
        print_status(f"An unexpected error occurred during network test: {e}", success=False)
        sys.exit(1)


    # 3. Mailgun API Authentication and Domain Check Test
    print(f"\n3. Testing Mailgun API Authentication & Domain Access ({MAILGUN_DOMAIN})...")
    # We'll use the '/domains/<your_domain>' endpoint which requires auth
    test_url = f"{MAILGUN_API_BASE_URL}/domains/{MAILGUN_DOMAIN}"
    print(f"   Making GET request to: {test_url}")

    try:
        response = requests.get(
            test_url,
            auth=HTTPBasicAuth('api', MAILGUN_API_KEY),
            timeout=15 # Set a reasonable timeout
        )

        print(f"   HTTP Status Code: {response.status_code}")

        if response.status_code == 200:
            print_status("Authentication successful and domain found!")
            try:
                domain_data = response.json().get('domain', {})
                print(f"   Domain Name: {domain_data.get('name')}")
                print(f"   Domain State: {domain_data.get('state')}")
                print(f"   Domain Type: {domain_data.get('type')}")
            except Exception as json_e:
                print_status(f"   Successfully authenticated, but failed to parse JSON response: {json_e}", success=False)
        elif response.status_code == 401:
            print_status("Authentication failed (Unauthorized).", success=False)
            print("   Check your MAILGUN_API_KEY. Ensure it's correct and active.")
            print(f"   Response body: {response.text[:200]}...") # Show beginning of error
        elif response.status_code == 404:
             print_status("Domain not found or incorrect API endpoint.", success=False)
             print(f"   Check if MAILGUN_DOMAIN ('{MAILGUN_DOMAIN}') is correct and registered in your Mailgun account.")
             print(f"   Also verify the MAILGUN_API_BASE_URL ('{MAILGUN_API_BASE_URL}'). Is it correct for your region (US/EU)?")
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