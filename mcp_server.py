"""falko_mcp/mcp_server.py

Google Workspace MCP server built on FastMCP.

Organisation
------------
  Sections 1-9 mirror the Google Admin / Cloud Identity API surface:
  1  Users          (Directory API)
  2  Groups         (Directory API + Groups Settings API)
  3  Licenses       (Enterprise License Manager API)
  4  Vault          (Google Vault API)
  5  Org Units      (Directory API)
  6  Devices        (Cloud Identity Devices API)
  7  Chrome Policy  (Chrome Policy API)
  8  Access Context (Access Context Manager API)
  9  Cloud Identity Policies

Credentials
-----------
  OAuth2 credentials are loaded once from token.json (created by the
  initial authorisation flow) and cached in _credentials_cache.
  The cache is protected by a threading.Lock so concurrent MCP tool
  calls do not race on read/refresh/write.

  token.json is written atomically (tempfile + os.replace) so a
  process interruption can never leave a partially-written, unreadable
  token on disk.

Service cache
-------------
  Google API client objects (built by googleapiclient.discovery.build)
  are cached in _service_cache keyed by "<api>_<version>".  This avoids
  re-loading the Discovery JSON document on every tool call.

Security notes
--------------
  * Passwords are sent as plaintext over TLS.  SHA-1 hashing is
    intentionally omitted — it adds no meaningful security when the
    password is short, because SHA-1 digests of common passwords are
    trivially rainbow-table-reversible.  TLS protects the value in
    transit; changePasswordAtNextLogin: True minimises exposure.
  * ID values used in Cloud Identity API calls are validated against
    _ID_PATTERN before use to prevent unexpected characters from
    reaching the API.
  * OAuth scopes follow least-privilege: each scope covers only the
    API surface actually used by this server.
"""

import os
import re
import sys
import json
import tempfile
import threading
from typing import Any

from mcp.server.fastmcp import FastMCP
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# ---------------------------------------------------------------------------
# OAuth 2.0 scopes — one entry per API, narrowed to minimum required access.
# Changing this list requires deleting token.json so a new grant is obtained.
# ---------------------------------------------------------------------------
SCOPES = [
    # Directory API — users, groups, OUs, domains, customer info
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/admin.directory.group",
    "https://www.googleapis.com/auth/admin.directory.customer",
    "https://www.googleapis.com/auth/admin.directory.orgunit",
    "https://www.googleapis.com/auth/admin.directory.domain",
    # Groups Settings API — per-group settings (who can post, join, etc.)
    "https://www.googleapis.com/auth/apps.groups.settings",
    # Enterprise License Manager API
    "https://www.googleapis.com/auth/apps.licensing",
    # Google Vault (eDiscovery)
    "https://www.googleapis.com/auth/ediscovery",
    # Chrome Policy API — manage Chrome browser / device policies
    "https://www.googleapis.com/auth/chrome.management.policy",
    # Cloud Identity Policies — DLP and org policy rules
    "https://www.googleapis.com/auth/cloud-identity.policies",
    # Cloud Identity Devices — read/write devices management
    "https://www.googleapis.com/auth/cloud-identity.devices",
]

mcp = FastMCP("gws-mcp")

# ---------------------------------------------------------------------------
# Thread-safe credentials cache
# ---------------------------------------------------------------------------
# FastMCP may dispatch concurrent tool calls on separate threads.  We protect
# both the cache lookup and the token-refresh path with a single lock so that
# only one thread ever writes to _credentials_cache or token.json at a time.
_credentials_lock = threading.Lock()
_credentials_cache: Credentials | None = None


def get_credentials() -> Credentials:
    """Return valid OAuth2 credentials, refreshing or re-authorising as needed.

    Flow
    ----
    1. Return cached credentials if they are still valid.
    2. Attempt a silent refresh if the access token has expired but a
       refresh token is available.
    3. Fall back to an interactive InstalledAppFlow (opens a browser) using
       the client-secrets file located via GOOGLE_APPLICATION_CREDENTIALS or
       by scanning the script directory and its parent for a file whose name
       matches ``client_secret_*.json``.
    4. Write the new credentials to token.json **atomically** using a
       temporary file and os.replace() so a crash mid-write cannot corrupt
       the stored token.

    Thread safety
    -------------
    The entire body is executed inside ``_credentials_lock``.  Concurrent
    callers block until the first caller has finished refreshing so the
    interactive OAuth flow is never launched twice simultaneously.
    """
    global _credentials_cache
    with _credentials_lock:
        # Fast path: valid token already in memory.
        if _credentials_cache and _credentials_cache.valid:
            return _credentials_cache

        creds: Credentials | None = None
        script_dir = os.path.dirname(os.path.abspath(__file__))
        token_path = os.path.join(script_dir, "token.json")

        # --- Load existing token from disk -----------------------------------
        if os.path.exists(token_path):
            try:
                creds = Credentials.from_authorized_user_file(token_path, SCOPES)
            except Exception:
                # Malformed token.json — treat as absent and re-authorise.
                creds = None

        # --- Refresh or re-authorise -----------------------------------------
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except Exception:
                    # Refresh failed (revoked token, network error, etc.).
                    # Fall through to interactive flow.
                    creds = None

            if not creds:
                # Locate client-secrets file.
                client_secrets_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
                if not client_secrets_path:
                    # Search script dir and its parent for client_secret_*.json
                    # that contains the "installed" OAuth application type.
                    search_dirs = [script_dir, os.path.dirname(script_dir)]
                    for d in search_dirs:
                        if not os.path.exists(d):
                            continue
                        for f in os.listdir(d):
                            if f.startswith("client_secret_") and f.endswith(".json"):
                                path = os.path.join(d, f)
                                try:
                                    with open(path) as fh:
                                        data = json.load(fh)
                                    if "installed" in data:
                                        client_secrets_path = path
                                        break
                                except Exception:
                                    pass
                        if client_secrets_path:
                            break

                    # Second pass: accept any client_secret_*.json if none
                    # matched the "installed" key (e.g. web-app credentials).
                    if not client_secrets_path:
                        for d in search_dirs:
                            if not os.path.exists(d):
                                continue
                            for f in os.listdir(d):
                                if f.startswith("client_secret_") and f.endswith(".json"):
                                    client_secrets_path = os.path.join(d, f)
                                    break
                            if client_secrets_path:
                                break

                if not client_secrets_path or not os.path.exists(client_secrets_path):
                    raise ValueError(
                        "GOOGLE_APPLICATION_CREDENTIALS env var not set and "
                        "no client_secret_*.json file found in the script directory."
                    )

                # Interactive browser-based OAuth consent flow.
                flow = InstalledAppFlow.from_client_secrets_file(
                    client_secrets_path, SCOPES
                )
                creds = flow.run_local_server(port=0)

            # --- Atomic token write ------------------------------------------
            # Write to a temporary file in the same directory, then rename.
            # os.replace() is atomic on POSIX: readers always see either the
            # old complete token or the new one, never a partial write.
            with tempfile.NamedTemporaryFile(
                mode="w", dir=script_dir, suffix=".tmp", delete=False
            ) as tmp:
                tmp.write(creds.to_json())
                tmp_path = tmp.name
            os.replace(tmp_path, token_path)

        _credentials_cache = creds
        return creds


# ---------------------------------------------------------------------------
# Service cache
# ---------------------------------------------------------------------------
# Building a Google API client involves parsing a Discovery JSON document
# (~50-200 KB).  We cache the resulting service object so subsequent calls to
# the same API within the same process are essentially free.
#
# Key format: "<api>_<version>"  e.g. "admin_directory_v1", "vault_v1".
# Note: if credentials are refreshed the service objects remain valid because
# googleapiclient passes credentials by reference, not by value.
_service_cache: dict[str, Any] = {}


def get_service(api: str, version: str) -> Any:
    """Return a cached Google API service client, building it on first use.

    Parameters
    ----------
    api:     Google API name as used by the Discovery service (e.g. 'admin',
             'vault', 'chromepolicy').
    version: API version string (e.g. 'directory_v1', 'v1').

    Returns
    -------
    A ``googleapiclient.discovery.Resource`` object ready for API calls.
    """
    key = f"{api}_{version}"
    if key not in _service_cache:
        creds = get_credentials()
        _service_cache[key] = build(api, version, credentials=creds)
    return _service_cache[key]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_json(raw: str, field_name: str) -> tuple[dict | list | None, str | None]:
    """Parse *raw* as JSON.

    Returns ``(parsed_value, None)`` on success or ``(None, error_message)``
    on failure.  The caller should propagate the error string directly to the
    MCP tool's return value so the LLM receives a human-readable message.
    """
    try:
        return json.loads(raw), None
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON in {field_name}: {e}"


# Allowlist for ID values that are passed to Cloud Identity structured fields.
# Permits alphanumerics, underscores, colons, slashes, @, dots, and hyphens.
# Rejects anything that could be used for injection even in a non-CEL context.
_ID_PATTERN = re.compile(r"^[\w:/@.-]+$")


def _validate_id(value: str, field_name: str) -> str | None:
    """Return an error string if *value* contains characters outside the
    safe allowlist, otherwise return None.

    Used to validate org_unit_id / group_id before they are placed into
    structured API request fields.
    """
    if not _ID_PATTERN.match(value):
        return f"Invalid {field_name} format (unsafe characters): {value!r}"
    return None


# ---------------------------------------------------------------------------
# Known GWS license products
# ---------------------------------------------------------------------------
# The Enterprise License Manager API does **not** expose a products.list
# endpoint — the product catalogue is a static list maintained by Google.
# Authoritative source:
#   https://developers.google.com/admin-sdk/licensing/v1/how-tos/products
#
# Structure: { productId: { name, skus: { skuId: skuName } } }
KNOWN_GWS_PRODUCTS: dict[str, dict] = {
    "Google-Apps": {
        "name": "Google Workspace",
        "skus": {
            "1010020020": "Business Starter",
            "1010020025": "Business Standard",
            "1010020026": "Business Plus",
            "1010060001": "Enterprise Essentials",
            "1010060003": "Enterprise Standard",
            "1010060004": "Enterprise Plus",
            "1010020028": "Essentials Starter",
        },
    },
    "Google-Drive-storage": {
        "name": "Google Drive Storage",
        "skus": {
            "Google-Drive-storage-20gb": "20 GB",
            "Google-Drive-storage-50gb": "50 GB",
            "Google-Drive-storage-200gb": "200 GB",
            "Google-Drive-storage-400gb": "400 GB",
            "Google-Drive-storage-1tb": "1 TB",
            "Google-Drive-storage-2tb": "2 TB",
            "Google-Drive-storage-4tb": "4 TB",
            "Google-Drive-storage-8tb": "8 TB",
            "Google-Drive-storage-16tb": "16 TB",
        },
    },
    "Google-Vault": {
        "name": "Google Vault",
        "skus": {
            "Google-Vault": "Vault",
            "Google-Vault-Former-Employee": "Vault Former Employee",
        },
    },
    "Google-Chrome-Device-Management": {
        "name": "Chrome Device Management",
        "skus": {"Google-Chrome-Device-Management": "Chrome Device Management"},
    },
}


# ===========================================================================
# 1. USERS  (Directory API)
# ===========================================================================

@mcp.tool()
def admin_list_users(max_results: int = 0, page_token: str = None) -> str:
    """List users in the Google Workspace domain."""
    service = get_service("admin", "directory_v1")
    try:
        kwargs = {
            "customer": "my_customer",
            "orderBy": "email"
        }
        if max_results > 0:
            kwargs["maxResults"] = max_results
        if page_token:
            kwargs["pageToken"] = page_token
            
        results = service.users().list(**kwargs).execute()
        return json.dumps(results, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


@mcp.tool()
def admin_create_user(
    primary_email: str, given_name: str, family_name: str, password: str
) -> str:
    """Create a new user account in Google Workspace.

    Security note — password handling
    ----------------------------------
    The password is transmitted as plaintext over an HTTPS connection.
    SHA-1 hashing is intentionally **not** used: the SHA-1 digest of a
    short or common password is trivially reversible via rainbow tables,
    so hashing provides no real security benefit here.  TLS protects the
    value in transit, and ``changePasswordAtNextLogin: True`` ensures the
    temporary password has minimal exposure.

    Parameters
    ----------
    primary_email: Full email address of the new account.
    given_name:    First name.
    family_name:   Last name.
    password:      Temporary password (min 8 characters, Google requirement).
    """
    if len(password) < 8:
        # Google enforces this minimum; fail early with a clear message.
        return "Password must be at least 8 characters (Google requirement)."

    service = get_service("admin", "directory_v1")
    body = {
        "primaryEmail": primary_email,
        "name": {"givenName": given_name, "familyName": family_name},
        # Plaintext over TLS — see docstring for rationale.
        "password": password,
        # Force password change so the operator-set value is never kept.
        "changePasswordAtNextLogin": True,
    }
    try:
        user = service.users().insert(body=body).execute()
        return json.dumps(user, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


@mcp.tool()
def admin_update_user(
    user_email: str,
    suspended: bool = None,
    org_unit_path: str = None,
    given_name: str = None,
    family_name: str = None,
    recovery_email: str = None,
    change_password_at_next_login: bool = None,
) -> str:
    """Update user account settings.

    Only the fields that are explicitly provided (not None) are changed.
    All other fields retain their current values.

    Name-field safety
    -----------------
    ``users.patch()`` with a partial ``name`` object can silently clear the
    sub-field that is omitted.  To prevent this, when either ``given_name``
    or ``family_name`` is supplied the function first fetches the current
    ``name`` from the API and merges the new values into it.

    Parameters
    ----------
    user_email:                    Primary email address (used as the user key).
    suspended:                     True to suspend, False to restore.
    org_unit_path:                 Move the user to this OU path.
    given_name:                    New first name.
    family_name:                   New last name.
    recovery_email:                New recovery email address.
    change_password_at_next_login: Force / clear the password-change flag.
    """
    service = get_service("admin", "directory_v1")
    body: dict = {}

    if suspended is not None:
        body["suspended"] = suspended
    if org_unit_path is not None:
        body["orgUnitPath"] = org_unit_path

    # Handle the nested "name" object carefully: fetch current values first
    # so a partial update does not accidentally clear the untouched sub-field.
    if given_name is not None or family_name is not None:
        try:
            current = service.users().get(
                userKey=user_email, fields="name"
            ).execute()
            body["name"] = dict(current.get("name", {}))
        except HttpError as e:
            return e.content.decode("utf-8")
        if given_name is not None:
            body["name"]["givenName"] = given_name
        if family_name is not None:
            body["name"]["familyName"] = family_name

    if recovery_email is not None:
        body["recoveryEmail"] = recovery_email
    if change_password_at_next_login is not None:
        body["changePasswordAtNextLogin"] = change_password_at_next_login

    if not body:
        return "No update values specified."

    try:
        service.users().patch(userKey=user_email, body=body).execute()
        return json.dumps(body, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


# ===========================================================================
# 2. GROUPS  (Directory API + Groups Settings API)
# ===========================================================================

@mcp.tool()
def admin_list_groups(max_results: int = 0, page_token: str = None) -> str:
    """List groups in the Google Workspace domain."""
    service = get_service("admin", "directory_v1")
    try:
        kwargs = {"customer": "my_customer"}
        if max_results > 0:
            kwargs["maxResults"] = max_results
        if page_token:
            kwargs["pageToken"] = page_token
            
        results = service.groups().list(**kwargs).execute()
        return json.dumps(results, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


@mcp.tool()
def admin_create_group(
    group_email: str, group_name: str, description: str = ""
) -> str:
    """Create a new Google Workspace group."""
    service = get_service("admin", "directory_v1")
    body = {"email": group_email, "name": group_name, "description": description}
    try:
        group = service.groups().insert(body=body).execute()
        return json.dumps(group, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


# Valid role values accepted by the Directory API members.insert endpoint.
VALID_GROUP_ROLES = {"MEMBER", "MANAGER", "OWNER"}


@mcp.tool()
def admin_add_group_member(
    group_email: str, member_email: str, role: str = "MEMBER"
) -> str:
    """Add a new member to a Google Workspace group.

    Parameters
    ----------
    group_email:  Email address of the target group.
    member_email: Email address of the user or group to add.
    role:         ``MEMBER`` (default), ``MANAGER``, or ``OWNER``.
    """
    if role not in VALID_GROUP_ROLES:
        return (
            f"Invalid role '{role}'. "
            f"Must be one of: {', '.join(sorted(VALID_GROUP_ROLES))}"
        )
    service = get_service("admin", "directory_v1")
    body = {"email": member_email, "role": role}
    try:
        member = service.members().insert(groupKey=group_email, body=body).execute()
        return json.dumps(member, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


@mcp.tool()
def admin_get_group_settings(group_email: str) -> str:
    """Get the settings of a Google Workspace group (Groups Settings API)."""
    service = get_service("groupssettings", "v1")
    try:
        results = service.groups().get(groupUniqueId=group_email).execute()
        return json.dumps(results, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


@mcp.tool()
def admin_update_group_settings(group_email: str, settings_json: str) -> str:
    """Update settings of a Google Workspace group (Groups Settings API).

    Parameters
    ----------
    group_email:   Email address of the target group.
    settings_json: JSON object containing only the fields to change.
                   Use ``admin_get_group_settings`` to discover field names.
    """
    body, err = _parse_json(settings_json, "settings_json")
    if err:
        return err
    service = get_service("groupssettings", "v1")
    try:
        results = service.groups().patch(
            groupUniqueId=group_email, body=body
        ).execute()
        return json.dumps(results, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


# ===========================================================================
# 3. LICENSES  (Enterprise License Manager API)
# ===========================================================================

@mcp.tool()
def admin_list_skus() -> str:
    """List available Google Workspace license products and SKUs.

    Returns the static KNOWN_GWS_PRODUCTS catalogue.  The Enterprise
    License Manager API does not expose a ``products.list`` endpoint;
    the authoritative product list is maintained by Google at:
    https://developers.google.com/admin-sdk/licensing/v1/how-tos/products

    Use the returned ``productId`` and ``skuId`` values with
    ``licensing_assign_license`` and ``licensing_remove_license``.
    """
    # No API call needed — the product catalogue is static.
    return json.dumps(KNOWN_GWS_PRODUCTS, indent=2)


@mcp.tool()
def licensing_list_user_licenses(user_email: str) -> str:
    """List the active license assignments for a specific user."""
    service = get_service("licensing", "v1")
    user_licenses = []
    for prod_id, prod_info in KNOWN_GWS_PRODUCTS.items():
        for sku_id in prod_info["skus"].keys():
            try:
                res = service.licenseAssignments().get(
                    productId=prod_id, skuId=sku_id, userId=user_email
                ).execute()
                user_licenses.append(res)
            except HttpError as e:
                # 404 is normal and indicates the user lacks this specific license.
                if e.resp.status != 404:
                    return e.content.decode("utf-8")
            except Exception as e:
                return json.dumps({"error": str(e)}, indent=2)
    return json.dumps(user_licenses, indent=2)


@mcp.tool()
def licensing_assign_license(
    user_email: str, product_id: str, sku_id: str
) -> str:
    """Assign a license to a user.

    Use ``admin_list_skus()`` to discover valid ``product_id`` / ``sku_id``.
    """
    service = get_service("licensing", "v1")
    body = {"userId": user_email}
    try:
        assignment = service.licenseAssignments().insert(
            productId=product_id, skuId=sku_id, body=body
        ).execute()
        return json.dumps(assignment, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


@mcp.tool()
def licensing_remove_license(
    user_email: str, product_id: str, sku_id: str
) -> str:
    """Remove a license assignment from a user."""
    service = get_service("licensing", "v1")
    try:
        service.licenseAssignments().delete(
            productId=product_id, skuId=sku_id, userId=user_email
        ).execute()
        return json.dumps({"status": "success"}, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


# ===========================================================================
# 4. VAULT  (Google Vault API)
# ===========================================================================

@mcp.tool()
def vault_list_matters(page_size: int = 0, page_token: str = None) -> str:
    """List eDiscovery matters in Google Vault."""
    service = get_service("vault", "v1")
    try:
        kwargs = {}
        if page_size > 0:
            kwargs["pageSize"] = page_size
        if page_token:
            kwargs["pageToken"] = page_token
        results = service.matters().list(**kwargs).execute()
        return json.dumps(results, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


@mcp.tool()
def vault_create_matter(name: str, description: str = "") -> str:
    """Create a new eDiscovery matter in Google Vault."""
    service = get_service("vault", "v1")
    body = {"name": name, "description": description}
    try:
        matter = service.matters().create(body=body).execute()
        return json.dumps(matter, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


# ===========================================================================
# 5. ORGANIZATIONAL UNITS  (Directory API)
# ===========================================================================

@mcp.tool()
def admin_list_orgunits(type: str = "all") -> str:
    """List organizational units (OUs) in the Workspace domain.

    Parameters
    ----------
    type: ``'all'`` (default), ``'children'``, or ``'allIncludingParent'``.
    """
    service = get_service("admin", "directory_v1")
    try:
        results = service.orgunits().list(
            customerId="my_customer", type=type
        ).execute()
        return json.dumps(results, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


@mcp.tool()
def admin_create_orgunit(
    name: str, parent_org_unit_path: str = "/"
) -> str:
    """Create a new organizational unit (OU).

    Parameters
    ----------
    name:                 Short display name of the new OU.
    parent_org_unit_path: Full path of the parent OU (default: root ``/``).
    """
    service = get_service("admin", "directory_v1")
    body = {"name": name, "parentOrgUnitPath": parent_org_unit_path}
    try:
        ou = service.orgunits().insert(
            customerId="my_customer", body=body
        ).execute()
        return json.dumps(ou, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


# ===========================================================================
# 6. DEVICE MANAGEMENT  (Cloud Identity Devices API)
# ===========================================================================

@mcp.tool()
def identity_list_devices(customer: str = "my_customer", page_size: int = 0, page_token: str = None) -> str:
    """List devices registered in Cloud Identity."""
    service = get_service("cloudidentity", "v1")
    try:
        kwargs = {"customer": customer}
        if page_size > 0:
            kwargs["pageSize"] = page_size
        if page_token:
            kwargs["pageToken"] = page_token
        results = service.devices().list(**kwargs).execute()
        return json.dumps(results, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


@mcp.tool()
def identity_update_device_status(
    device_name: str, action: str, device_user_name: str = ""
) -> str:
    """Execute an action on a managed device.

    Parameters
    ----------
    device_name:
        Full resource name, e.g.
        ``customers/my_customer/devices/12345``.
    action:
        One of ``approve``, ``block``, ``wipe``, ``cancel_wipe``.
        * ``approve`` / ``block`` operate on a **device user** (the
          association between a device and a specific account).  If
          *device_user_name* is omitted, the first device user is
          resolved automatically via a subsidiary API call.
        * ``wipe`` / ``cancel_wipe`` operate on the **device** itself.
    device_user_name:
        Full resource name of the device user (optional for approve/block).
        Example: ``customers/my_customer/devices/12345/deviceUsers/67890``.
    """
    service = get_service("cloudidentity", "v1")

    try:
        if action in ("approve", "block"):
            # Resolve the device-user resource name if not supplied.
            if not device_user_name:
                users_resp = (
                    service.devices()
                    .deviceUsers()
                    .list(parent=device_name)
                    .execute()
                )
                device_users = users_resp.get("deviceUsers", [])
                if not device_users:
                    return f"No device users found for device {device_name}."
                device_user_name = device_users[0]["name"]

            du = service.devices().deviceUsers()
            if action == "approve":
                result = du.approve(name=device_user_name, body={}).execute()
            else:
                result = du.block(name=device_user_name, body={}).execute()

        elif action == "wipe":
            result = service.devices().wipe(
                name=device_name, body={}
            ).execute()
        elif action == "cancel_wipe":
            result = service.devices().cancelWipe(
                name=device_name, body={}
            ).execute()
        else:
            return (
                f"Unknown device action: '{action}'. "
                "Valid actions: approve, block, wipe, cancel_wipe"
            )

        return json.dumps(result, indent=2) if result else json.dumps({"status": "success"}, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


# ===========================================================================
# 7. CHROME POLICIES  (Chrome Policy API)
# ===========================================================================

@mcp.tool()
def chrome_list_policy_schemas(
    filter: str = "", page_size: int = 100, page_token: str = None
) -> str:
    """List available Chrome Policy schemas."""
    service = get_service("chromepolicy", "v1")
    try:
        kwargs = {
            "parent": "customers/my_customer",
            "filter": filter,
            "pageSize": page_size
        }
        if page_token:
            kwargs["pageToken"] = page_token
            
        results = service.customers().policySchemas().list(**kwargs).execute()
        return json.dumps(results, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


@mcp.tool()
def chrome_update_policy(
    policy_schema: str, org_unit_id: str, value_json: str
) -> str:
    """Update a Chrome policy for an Organizational Unit.

    Parameters
    ----------
    policy_schema:
        Schema name, e.g. ``'chrome.users.BrowserSignin'``.
        Use ``chrome_list_policy_schemas()`` to discover valid names.
    org_unit_id:
        ID or full path of the target OU,
        e.g. ``'orgunits/03ph8a2z36qachz'`` or ``'03ph8a2z36qachz'``.
    value_json:
        JSON object whose keys are the policy field(s) to set.
        Only the fields present in this object are overwritten
        (derived from a per-key ``updateMask``).

    Notes
    -----
    * ``updateMask`` (a comma-separated list of field names) is derived
      from the top-level keys of *value_json*.  This matches the Chrome
      Policy API ``batchModify`` contract; see:
      https://developers.google.com/chrome/policy/reference/rest/v1/customers.policies.orgunits/batchModify
    """
    value, err = _parse_json(value_json, "value_json")
    if err:
        return err
    if not isinstance(value, dict):
        return "value_json must be a JSON object (dict), not an array or scalar."

    # Derive the FieldMask from the keys present in the value object.
    # This ensures only the fields the caller specified are modified.
    update_mask = ",".join(value.keys()) if value else "value"

    service = get_service("chromepolicy", "v1")
    body = {
        "requests": [
            {
                "policyTargetKey": {
                    # Strip any "orgunits/" prefix so we always pass the bare ID.
                    "targetResource": f"orgunits/{org_unit_id.split('/')[-1]}"
                },
                "policyValue": {
                    "policySchema": policy_schema,
                    "value": value,
                },
                # updateMask must be a FieldMask string, not an object.
                "updateMask": update_mask,
            }
        ]
    }
    try:
        result = (
            service.customers()
            .policies()
            .orgunits()
            .batchModify(customer="customers/my_customer", body=body)
            .execute()
        )
        return json.dumps(result, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


# ===========================================================================
# 8. ACCESS CONTEXT MANAGER
# ===========================================================================

@mcp.tool()
def accesscontext_list_policies(page_token: str = None) -> str:
    """List Access Context Manager access policies for the organisation."""
    service = get_service("accesscontextmanager", "v1")
    try:
        kwargs = {}
        if page_token:
            kwargs["pageToken"] = page_token
        results = service.accessPolicies().list(**kwargs).execute()
        return json.dumps(results, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


@mcp.tool()
def accesscontext_update_access_level(
    policy_id: str,
    access_level_name: str,
    title: str,
    conditions_json: str,
) -> str:
    """Create or update a Context-Aware Access (CAA) access level.

    Parameters
    ----------
    policy_id:
        Parent Access Policy resource name or bare numeric ID,
        e.g. ``'accessPolicies/123456789'`` or ``'123456789'``.
    access_level_name:
        Full resource name of an existing access level to update.
        Pass an empty string to create a new access level instead.
    title:
        Short human-readable title shown in the Admin console.
    conditions_json:
        JSON array of ``BasicLevel.Condition`` objects.
        All conditions are combined with ``AND`` (``combiningFunction``).
    """
    conditions, err = _parse_json(conditions_json, "conditions_json")
    if err:
        return err
    service = get_service("accesscontextmanager", "v1")
    body = {
        "title": title,
        "basic": {
            # AND: the principal must satisfy every condition.
            "combiningFunction": "AND",
            "conditions": conditions,
        },
    }
    try:
        if access_level_name:
            # Update existing access level (PATCH with field mask).
            result = (
                service.accessPolicies()
                .accessLevels()
                .patch(
                    name=access_level_name,
                    body=body,
                    updateMask="title,basic",
                )
                .execute()
            )
            return json.dumps(result, indent=2)
        else:
            # Create a new access level under the specified policy.
            parent = f"accessPolicies/{policy_id.split('/')[-1]}"
            result = (
                service.accessPolicies()
                .accessLevels()
                .create(parent=parent, body=body)
                .execute()
            )
            return json.dumps(result, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


# ===========================================================================
# 9. CLOUD IDENTITY POLICIES
# ===========================================================================

@mcp.tool()
def identity_list_policies(filter: str = "", page_token: str = None) -> str:
    """List Cloud Identity policies (DLP rules, Workspace policies, etc.)."""
    service = get_service("cloudidentity", "v1")
    try:
        kwargs = {}
        if filter:
            kwargs["filter"] = filter
        if page_token:
            kwargs["pageToken"] = page_token
        results = service.policies().list(**kwargs).execute()
        return json.dumps(results, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


@mcp.tool()
def identity_create_policy(
    setting_type: str,
    value_json: str,
    org_unit_id: str = None,
    group_id: str = None,
) -> str:
    """Create a Cloud Identity policy under ``customers/my_customer``.

    Security note — ID validation
    ------------------------------
    *org_unit_id* and *group_id* are validated against ``_ID_PATTERN``
    before use.  This prevents unexpected characters from reaching the API
    even though the values are placed into structured fields (not interpolated
    into a CEL expression).

    The ``policyQuery.query`` field is always set to the literal string
    ``"true"``; scope is expressed exclusively via the structured
    ``policyQuery.orgUnit`` / ``policyQuery.group`` fields so there is no
    risk of CEL injection.

    Parameters
    ----------
    setting_type: Fully-qualified policy setting type, e.g.
                  ``'settings/workspace.drivedatasharing'``.
    value_json:   JSON object with the policy value fields.
    org_unit_id:  Optional OU ID to scope the policy.
    group_id:     Optional group ID to scope the policy.
    """
    value, err = _parse_json(value_json, "value_json")
    if err:
        return err

    # Validate IDs before use.
    if org_unit_id:
        if err := _validate_id(org_unit_id, "org_unit_id"):
            return err
    if group_id:
        if err := _validate_id(group_id, "group_id"):
            return err

    service = get_service("cloudidentity", "v1")

    # Structured request — no CEL string interpolation.
    body: dict = {
        "customer": "customers/my_customer",
        # "true" matches all principals; scoping is done via the
        # orgUnit / group fields below, not via a CEL expression.
        "policyQuery": {"query": "true"},
        "setting": {"type": setting_type, "value": value},
    }
    if org_unit_id:
        body["policyQuery"]["orgUnit"] = f"orgunits/{org_unit_id}"
    if group_id:
        body["policyQuery"]["group"] = f"groups/{group_id}"

    try:
        result = service.policies().create(body=body).execute()
        return json.dumps(result, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


@mcp.tool()
def identity_patch_policy(
    policy_name: str,
    value_json: str,
    update_mask: str = "setting.value",
) -> str:
    """Patch an existing Cloud Identity policy.

    Parameters
    ----------
    policy_name:  Full resource name of the policy to update.
    value_json:   JSON object with the new setting value fields.
    update_mask:  FieldMask for the patch (default: ``'setting.value'``).
    """
    value, err = _parse_json(value_json, "value_json")
    if err:
        return err
    service = get_service("cloudidentity", "v1")
    body = {"setting": {"value": value}}
    try:
        result = service.policies().patch(
            name=policy_name, body=body, updateMask=update_mask
        ).execute()
        return json.dumps(result, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


@mcp.tool()
def identity_delete_policy(policy_name: str) -> str:
    """Delete an existing Cloud Identity policy.

    Parameters
    ----------
    policy_name: Full resource name of the policy to delete.
    """
    service = get_service("cloudidentity", "v1")
    try:
        service.policies().delete(name=policy_name).execute()
        return json.dumps({"status": "success"}, indent=2)
    except HttpError as e:
        return e.content.decode("utf-8")


if __name__ == "__main__":
    mcp.run()
