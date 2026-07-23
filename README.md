# Falko MCP Server

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

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Place your Google API `client_secret_*.json` in the root of the project.
3. Run the MCP server. FastMCP will automatically trigger an interactive OAuth flow on the first run, creating `token.json`.

## Supported APIs

* Google Admin Directory API (Users, Groups, Org Units)
* Google Groups Settings API
* Google Enterprise License Manager API
* Google Vault API
* Cloud Identity Devices API
* Chrome Policy API
* Access Context Manager API
* Cloud Identity Policies API
