import os
import sys
import json
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from mcp_server import get_credentials, KNOWN_GWS_PRODUCTS

creds = get_credentials()
output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gws_json")
os.makedirs(output_dir, exist_ok=True)

def save_raw(filename, data):
    path = os.path.join(output_dir, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Saved: {filename}")

def save_error(filename, e):
    path = os.path.join(output_dir, filename)
    if hasattr(e, "content"):
        err_msg = e.content.decode("utf-8")
    else:
        err_msg = json.dumps({"error": str(e)}, indent=2)
    with open(path, "w") as f:
        f.write(err_msg)
    print(f"Failed (saved error): {filename}")

# Build Services
directory_service = build("admin", "directory_v1", credentials=creds)
licensing_service = build("licensing", "v1", credentials=creds)
vault_service = build("vault", "v1", credentials=creds)
identity_service = build("cloudidentity", "v1", credentials=creds)

# 1. Customer
try:
    res = directory_service.customers().get(customerKey="my_customer").execute()
    save_raw("customer.json", res)
except Exception as e:
    save_error("customer_error.json", e)

# 2. Domains
try:
    res = directory_service.domains().list(customer="my_customer").execute()
    save_raw("domains.json", res)
except Exception as e:
    save_error("domains_error.json", e)

# 3. OrgUnits
try:
    res = directory_service.orgunits().list(customerId="my_customer", type="all").execute()
    save_raw("orgunits.json", res)
except Exception as e:
    save_error("orgunits_error.json", e)

# 4. Users
users_list = []
try:
    res = directory_service.users().list(customer="my_customer", orderBy="email").execute()
    save_raw("users.json", res)
    users_list = res.get("users", [])
except Exception as e:
    save_error("users_error.json", e)

# 5. Groups
try:
    res = directory_service.groups().list(customer="my_customer").execute()
    save_raw("groups.json", res)
except Exception as e:
    save_error("groups_error.json", e)

# 6. Licenses (per user)
for user in users_list:
    email = user.get("primaryEmail")
    if email:
        user_licenses = []
        for prod_id, prod_info in KNOWN_GWS_PRODUCTS.items():
            for sku_id in prod_info["skus"].keys():
                try:
                    res = licensing_service.licenseAssignments().get(
                        productId=prod_id, skuId=sku_id, userId=email
                    ).execute()
                    user_licenses.append(res)
                except HttpError as e:
                    # 404 means the user does not have this specific license, which is normal.
                    if e.resp.status != 404:
                        save_error(f"licenses_{email}_{prod_id}_{sku_id}_error.json", e)
                except Exception as e:
                    save_error(f"licenses_{email}_{prod_id}_{sku_id}_error.json", e)
        
        save_raw(f"licenses_{email}.json", user_licenses)

# 7. Vault Matters
try:
    res = vault_service.matters().list().execute()
    save_raw("vault_matters.json", res)
except Exception as e:
    save_error("vault_matters_error.json", e)

# 8. Devices
try:
    # Google Cloud Identity Devices API expects 'customer' query parameter.
    # Note: This will result in a 403 error (saved in devices_error.json) unless the scope
    # 'https://www.googleapis.com/auth/cloud-identity.devices.readonly' has been configured
    # on the OAuth Consent Screen in Google Cloud Console.
    res = identity_service.devices().list(customer="my_customer").execute()
    save_raw("devices.json", res)
except Exception as e:
    save_error("devices_error.json", e)

# 9. Cloud Identity Policies
try:
    res = identity_service.policies().list().execute()
    save_raw("policies.json", res)
except Exception as e:
    save_error("policies_error.json", e)
