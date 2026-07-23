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

4. **Destructive Operations Require a Confirmation Guard**
   Any tool that performs an **irreversible** action (deleting a file, deleting a calendar event, permanently removing a resource) **must** include a `confirm: bool = False` parameter. The tool must return an explanatory string without performing any action when `confirm` is `False`.

   ```python
   def drive_delete_file(file_id: str, confirm: bool = False) -> str:
       """Permanently delete a file from Google Drive.

       Parameters
       ----------
       file_id : str
           ID of the file to delete.
           Example: ``"1BxSjkD7T4pMa3c8EXAMPLEiRwY9Z"``
       confirm : bool
           Must be ``True`` to execute the deletion. When ``False`` (default)
           the function returns a description of what *would* be deleted
           without making any changes.
       """
       if not confirm:
           return (
               f"Dry-run: would permanently delete file '{file_id}'. "
               "Pass confirm=True to execute."
           )
       # ... actual deletion logic
   ```

   This convention applies to — but is not limited to — `drive_delete_file`, `calendar_delete_event`, and any future tool that calls a Google API `delete` or `remove` method.

5. **Document Resource Name Formats with a Concrete Example**
   Many Google APIs use structured resource names (`spaces/XXXXX`, `searchapplications/default`, `projects/{id}`) rather than plain identifiers. An LLM cannot infer the correct format from a parameter name alone.

   **Every parameter whose value is a resource name or opaque ID must include an `Example:` line in the docstring:**

   ```python
   def chat_send_message(space_name: str, text: str) -> str:
       """Send a message to a Google Chat space.

       Parameters
       ----------
       space_name : str
           Resource name of the target space.
           Example: ``"spaces/AAAABBBBCCCC"``
           Retrieve with ``chat_list_spaces``.
       """
   ```

   **How to discover the correct format during development:**
   Before implementing a new tool that consumes a resource ID, run the corresponding list/enumerate call directly in a Python shell:

   ```python
   from mcp_server import get_service
   import json

   svc = get_service("<api>", "<version>")
   result = svc.<resource>().list().execute()
   print(json.dumps(result, indent=2))
   # Inspect the "name" or "id" field of the first item and copy its
   # exact format into the docstring Example: line.
   ```

   This one-time check also surfaces edition restrictions (e.g. Cloud Search returns 403 on Business Starter) before any implementation work begins.

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
