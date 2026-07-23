# GWS MCP Server

A FastMCP-based server designed to integrate Google Workspace Administration with LLM-powered interfaces. This server allows LLMs to query and mutate Google Workspace configurations, including Users, Groups, Licenses, Devices, Chrome Policies, and more.

## Architecture

* **Framework:** [FastMCP](https://github.com/jlowin/fastmcp)
* **Auth:** Currently uses a local `client_secret.json` and interactive OAuth 2.0 flow (`InstalledAppFlow`) to generate a `token.json`.
* **API Responses:** All tools are designed to be "pass-through". We return the **raw JSON** string directly from the Google API for both success responses and errors.
* **Pagination:** Endpoints requiring pagination (such as `admin_list_users`) accept an optional `page_token`. They do *not* automatically iterate through pages to prevent out-of-memory errors on large Google Workspace domains. The LLM or client is responsible for calling the endpoint again with the `nextPageToken` if more results are needed.

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

## Supported APIs

* Google Admin Directory API (Users, Groups, Org Units)
* Google Groups Settings API
* Google Enterprise License Manager API
* Google Vault API
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


## Feature Roadmap & Implementation Plans

Below is the structured roadmap for planned Workspace integrations:

### 1. Gmail API Integration
* **Feasibility:** High
* **Scope:** `https://www.googleapis.com/auth/gmail.modify`
* **Tools:** `gmail_list_messages`, `gmail_get_message`, `gmail_send_message`
* **Plan:** Add MIME serialization helpers in `mcp_server.py` and query with pagination.

### 2. Calendar API Integration
* **Feasibility:** High
* **Scope:** `https://www.googleapis.com/auth/calendar`
* **Tools:** `calendar_list_events`, `calendar_insert_event`, `calendar_delete_event`
* **Plan:** Standardize date-time checks to handle ISO 8601 strings from LLM prompts.

### 3. Drive API + Drive Activity API Integration
* **Feasibility:** High
* **Scopes:** `https://www.googleapis.com/auth/drive`, `https://www.googleapis.com/auth/drive.activity.readonly`
* **Tools:** `drive_list_files`, `drive_get_file_metadata`, `drive_list_activity`
* **Plan:** Return resource references/links to keep LLM context footprint small.

### 4. Docs, Sheets, Slides and Forms API Integration
* **Feasibility:** High
* **Scopes:** Docs, Spreadsheets, Presentations, and Forms readonly scopes.
* **Tools:** `docs_get_document`, `sheets_read_range`, `sheets_write_range`, `slides_get_presentation`, `forms_list_responses`
* **Plan:** Abstract complex batch update payloads into simpler MCP interfaces.

### 5. Chat API and Meet API Integration
* **Feasibility:** Medium
* **Scopes:** Chat spaces read/write and Meet space metadata.
* **Tools:** `chat_list_spaces`, `chat_create_message`, `meet_create_space`
* **Plan:** Support space creation and messaging; document Chatbot Console activation.

### 6. Cloud Search API Integration
* **Feasibility:** High (requires Enterprise Workspace)
* **Scope:** `https://www.googleapis.com/auth/cloud_search.query`
* **Tools:** `cloudsearch_search`
* **Plan:** Build query client; return descriptive error when Search Application is missing.

### 7. Keep, Tasks, Classroom and Apps Script API Integration
* **Feasibility:** High
* **Scopes:** Keep, Tasks, Classroom readonly, and Apps Script run permissions.
* **Tools:** `keep_list_notes`, `tasks_list_tasks`, `classroom_list_courses`, `script_run`
* **Plan:** Add direct tasks/notes listing; apply strict input filters to Apps Script execution.

### 8. Google Workspace Marketplace SDK / Licensing API Integration
* **Feasibility:** High
* **Scopes:** `licensing` (active) and `appsmarket` SDK scopes.
* **Tools:** `licensing_get_license_assignment`, `marketplace_get_app_installation`
* **Plan:** Expand current license checkouts and audit application installations.


