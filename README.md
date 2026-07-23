# GWS MCP Server

A FastMCP-based server designed to integrate Google Workspace Administration with LLM-powered interfaces. This server allows LLMs to query and mutate Google Workspace configurations, including Users, Groups, Licenses, Devices, Chrome Policies, and more.

## Architecture

* **Framework:** [FastMCP](https://github.com/jlowin/fastmcp)
* **Auth:** Uses a local `client_secret.json` and interactive OAuth 2.0 flow (`InstalledAppFlow`) to generate a `token.json`. This is intentional for a locally-run MCP server: the token is stored on the same machine that runs the server and is only accessible to the authenticated admin. See [Future Plans](#future-plans-server-side-mcp) for the multi-tenant path.
* **Error Handling:** All tools return the **raw JSON string** from the Google API for both success and error responses — including HTTP errors. We deliberately rely on the **native `HttpError` content** (`e.content.decode("utf-8")`) rather than wrapping errors in custom exception classes or log statements. The rationale: the raw Google error payload contains the exact HTTP status code, error reason, and message that the LLM needs to self-correct (e.g. `insufficientPermissions`, `notFound`, `quotaExceeded`). Custom wrappers would lose this signal. See [Error Handling Design](#error-handling-design) for details.
* **API Responses:** All tools are designed to be "pass-through". We return the **raw JSON** string directly from the Google API for both success responses and errors.
* **Pagination:** Endpoints requiring pagination (such as `admin_list_users`) accept an optional `page_token`. They do *not* automatically iterate through pages to prevent out-of-memory errors on large Google Workspace domains. The LLM or client is responsible for calling the endpoint again with the `nextPageToken` if more results are needed.

## Error Handling Design

Every tool in this server follows the same error handling pattern:

```python
try:
    result = service.resource().method(**kwargs).execute()
    return json.dumps(result, indent=2)
except HttpError as e:
    return e.content.decode("utf-8")
```

**Why we return raw `HttpError` content instead of raising or wrapping:**

1. **LLM self-correction**: The raw Google error JSON contains structured fields (`status`, `error.code`, `error.errors[].reason`, `error.message`) that the LLM can parse and act on — for example, recognising `insufficientPermissions` and asking the user to add a scope, or retrying with different parameters on `invalid` input errors.
2. **No information loss**: Custom exception wrappers typically stringify errors into a single message, discarding the `reason` and `domain` fields. The native payload preserves everything.
3. **Consistency**: Every tool behaves identically — success and failure both return a JSON string. The LLM does not need to distinguish between exception types.
4. **Scope for evolution**: When the server transitions to a containerised backend, logging can be added as a side effect (e.g. `logger.error(e.content)`) without changing the return contract.

The one case where this pattern needs care: **do not log `e.content` to stdout in the local server**, as it may contain sensitive user data visible in terminal output.

## Google Vault

The server includes [Google Vault API](https://developers.google.com/vault) tools (`vault_*`). Vault is Google Workspace's eDiscovery and legal hold product.

**Important scope and edition constraints:**

* Vault is only available on **Business Plus, Enterprise, Education Standard/Plus, and Frontline** editions. It is **not available** on Business Starter, Business Standard, or Essentials.
* The OAuth scope required is `https://www.googleapis.com/auth/ediscovery` (read/write) or `https://www.googleapis.com/auth/ediscovery.readonly`.
* If your domain does not have Vault enabled, all `vault_*` tools will return a `403 SERVICE_DISABLED` error. To verify: Admin Console → Apps → Google Workspace → Vault → check that the service is ON.
* DWD is **not required** for Vault — the authenticating admin's own OAuth credentials are sufficient, provided the account has the **Vault Admin** or **Vault User** role in Admin Console.
* Vault matters data is **legally sensitive**. Treat all `vault_*` tool outputs as confidential. Do not log responses or expose them outside of a secure audit context.

## Future Plans: Server-Side MCP

We plan to transition this MCP Server to a containerized, multi-tenant backend architecture:
* **GCP Secret Manager:** Instead of a local `token.json`, the server will securely fetch distinct OIDC tokens from GCP Secret Manager based on the current admin user (e.g. `projects/<project>/secrets/gws-admin-<email>/versions/latest`). This ensures proper attribution of API changes in Google Workspace Audit Logs.
* **Container Orchestration Logging:** We will replace simple string error returns with standard Python `logging` designed to hook into orchestration aggregators (e.g., GCP Cloud Logging or Datadog) for centralized auditing and debugging.

## Setup

### 1. Create Google OAuth Desktop Credentials
To authenticate locally, the server requires OAuth 2.0 Desktop Application credentials:
1. Open the [Google Cloud Console](https://console.cloud.google.com/).
2. Select your Google Workspace project.
3. Go to **APIs & Services** > **Credentials**.
4. Click **Create Credentials** > **OAuth client ID**.
5. Set the **Application type** to **Desktop app**.
6. Provide a descriptive name and click **Create**.
7. Download the credentials JSON file.
8. Save this file in the `gws-mcp` directory (the filename must start with `client_secret_` and end with `.json`).

### 2. Installation
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Execute the verification script to trigger the interactive browser authentication:
   ```bash
   .venv/bin/python test_auth.py
   ```
   This will open a browser window requesting authorization for the specified scopes and automatically generate a local `token.json` file.

### Adding New Scopes

When a new API is added, its OAuth scopes must be added to the `SCOPES` list in `mcp_server.py`. After editing `SCOPES`:

```bash
rm token.json
.venv/bin/python test_auth.py
```

The old `token.json` is tied to the previously authorised scope set and will cause `invalid_grant` or `insufficientPermissions` errors if reused after a scope change.

## Supported APIs

* Google Admin Directory API (Users, Groups, Org Units)
* Google Groups Settings API
* Google Enterprise License Manager API
* Google Vault API *(Business Plus or higher — see [Google Vault](#google-vault))*
* Cloud Identity Devices API
* Chrome Policy API
* Access Context Manager API
* Cloud Identity Policies API

## GWS Configuration Extraction

A helper script `gws_json.py` is included to dump raw Google Workspace configuration data directly to local files inside the `gws_json/` directory.

Run the extraction script:
```bash
.venv/bin/python gws_json.py
```

## Troubleshooting

### Cloud Identity Devices Scope (invalid_scope / 403 Permission Denied)
The `cloud-identity.devices` scope is excluded from the default local credentials list. Attempting to list devices via `identity_list_devices` will result in `403 Request had insufficient authentication scopes`.

To enable device management sustainably:
1. Go to the **Google Cloud Console**.
2. Enable the **Cloud Identity API** (`cloudidentity.googleapis.com`) on your project.
3. Navigate to **APIs & Services** > **Google Auth Platform** > **Data Access** (or **OAuth consent screen**).
4. Click **Add Scopes** and manually enter the scope:
   `https://www.googleapis.com/auth/cloud-identity.devices.readonly`
5. Save the configuration and refresh the console page.
6. Re-add the scope to the `SCOPES` array in `mcp_server.py`, delete the local `token.json`, and run `.venv/bin/python test_auth.py` again to complete authorization.

### Vault returns 403 SERVICE_DISABLED
Your domain does not have Google Vault enabled. Vault requires **Business Plus or higher**. Check Admin Console → Apps → Google Workspace → Vault.

### token.json errors after adding new APIs
Any scope change invalidates the existing `token.json`. Delete it and re-run `test_auth.py` to reauthorise. See [Adding New Scopes](#adding-new-scopes).
