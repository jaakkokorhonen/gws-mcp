import os
import sys
from googleapiclient.errors import HttpError
from googleapiclient.discovery import build

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from mcp_server import get_credentials, SCOPES

def verify_and_test_auth():
    print("Checking local Google Workspace credentials...")
    try:
        creds = get_credentials()
    except Exception as e:
        print(f"Error loading credentials: {e}")
        trigger_reauth()
        return

    # Verify if the loaded credentials actually work against the Google API
    try:
        print("Testing connection to Google Workspace API...")
        service = build("admin", "directory_v1", credentials=creds)
        # Make a tiny read-only call to check authorization
        service.users().list(customer="my_customer", maxResults=1).execute()
        print("🎉 Authentication successful! Credentials are valid.")
    except HttpError as e:
        # Check if the error is due to bad credentials (unauthorized/invalid credentials)
        if e.resp.status in (401, 403):
            print("\n❌ Authentication failed: Token is invalid, expired, or revoked by Google.")
            trigger_reauth()
        else:
            print(f"\n⚠️ Connection test returned API Error {e.resp.status}: {e._get_reason()}")
    except Exception as e:
        print(f"\n⚠️ Unexpected connection error: {e}")
        print("This might be a network issue. Please check your connection.")

def trigger_reauth():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    token_path = os.path.join(script_dir, "token.json")
    
    print("\nAttempting to repair credentials...")
    if os.path.exists(token_path):
        try:
            os.remove(token_path)
            print("Removed invalid token.json.")
        except Exception as e:
            print(f"Failed to remove token.json: {e}")
            
    print("Launching browser for interactive log in...")
    try:
        # Running get_credentials now will not find token.json and will trigger InstalledAppFlow
        get_credentials()
        print("🎉 Log in successful! New credentials saved.")
    except Exception as e:
        print(f"❌ Failed to log in: {e}")

if __name__ == "__main__":
    verify_and_test_auth()
