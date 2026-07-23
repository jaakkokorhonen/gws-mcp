# Contributing to Falko MCP Server

Thank you for contributing! When adding new features or modifying existing code, please adhere to the following principles.

## Core Principles

1. **Raw JSON Passthrough**
   This MCP Server is strictly a conduit for Google Workspace APIs. When you add a new endpoint or update an existing one, **do not** parse, summarize, or mutate the Google API responses. Return them exactly as they are provided by the Google API client library, using `json.dumps(result, indent=2)`.

2. **Error Handling**
   Do not catch and summarize `HttpError` objects into custom human-readable strings. The client application needs the structured Google API error details to behave intelligently. Always extract and return the raw JSON error string from the `HttpError`:
   ```python
   except HttpError as e:
       return e.content.decode("utf-8")
   ```

3. **No Pagination Automation**
   Do not implement `while True` loops to exhaustively fetch all pages of a Google API list endpoint. In large enterprise environments, this will result in out-of-memory errors or extremely large context windows. Provide a `page_token` (or similar) optional parameter to your MCP Tool, let the Google API return a `nextPageToken` in the payload, and allow the LLM or client to decide if it wants to request the next page.

## Testing Your Changes

1. Run a syntax check before committing:
   ```bash
   python -m py_compile mcp_server.py
   ```
2. Manually test your endpoint locally using an MCP inspector or the provided `test_auth.py` script. Make sure that the payload output is exactly matching the Google Workspace REST API documentation payload examples.

## Adding a New MCP Tool

* Always document the endpoint using a Python docstring. FastMCP utilizes the docstring to present the tool's capabilities to the LLM.
* Keep parameter names clear and use Python type hinting.
* If your endpoint requires a new OAuth scope, add it to the `SCOPES` list in `mcp_server.py`. Remember that modifying the `SCOPES` list requires deleting your local `token.json` file so that a new OAuth consent grant can be obtained.
