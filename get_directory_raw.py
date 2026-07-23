import os
import sys
import json
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from mcp_server import get_credentials
from googleapiclient.discovery import build

creds = get_credentials()
service = build("admin", "directory_v1", credentials=creds)

results = {}

print("=== Haetaan hakemiston kaikki asetukset (Raw Data) ===")

# 1. Asiakasasetukset (Customer Settings)
try:
    results["customer"] = service.customers().get(customerKey="my_customer").execute()
except Exception as e:
    results["customer_error"] = str(e)

# 2. Verkkotunnukset (Domains)
try:
    results["domains"] = service.domains().list(customer="my_customer").execute()
except Exception as e:
    results["domains_error"] = str(e)

# 3. Organisaatioyksiköt (Organizational Units)
try:
    results["orgunits"] = service.orgunits().list(customerId="my_customer", type="all").execute()
except Exception as e:
    results["orgunits_error"] = str(e)

# Tulostetaan raakadata JSON-muodossa
print(json.dumps(results, indent=2))
