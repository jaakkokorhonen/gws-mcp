import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from mcp_server import get_credentials, admin_list_users, admin_list_groups, identity_list_devices

try:
    print("Käynnistetään todennus...")
    creds = get_credentials()
    print("Todennus onnistui! Haetaan tietoja...\n")
    
    print("=== Käyttäjät ===")
    try:
        users = admin_list_users()
        print(users)
    except Exception as e:
        print(f"Käyttäjien haku epäonnistui: {e}")
        
    print("\n=== Ryhmät ===")
    try:
        groups = admin_list_groups()
        print(groups)
    except Exception as e:
        print(f"Ryhmien haku epäonnistui: {e}")
        
    print("\n=== Laitteet ===")
    try:
        devices = identity_list_devices()
        print(devices)
    except Exception as e:
        print(f"Laitteiden haku epäonnistui: {e}")
        
except Exception as e:
    print(f"Kriittinen virhe todennuksessa: {e}")
