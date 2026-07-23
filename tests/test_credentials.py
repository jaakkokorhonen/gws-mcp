import os
import json
import pytest
from unittest.mock import patch, MagicMock, mock_open

import mcp_server

@pytest.fixture(autouse=True)
def reset_credentials_cache():
    """Reset the global credentials cache before each test."""
    mcp_server._credentials_cache = None
    yield
    mcp_server._credentials_cache = None

@patch("mcp_server.os.path.exists")
@patch("mcp_server.Credentials.from_authorized_user_file")
def test_get_credentials_valid_token_exists(mock_from_file, mock_exists):
    """Test that a valid token on disk is loaded and returned directly."""
    # Setup mocks
    mock_exists.return_value = True
    mock_creds = MagicMock()
    mock_creds.valid = True
    mock_from_file.return_value = mock_creds

    # Execute
    creds = mcp_server.get_credentials()

    # Verify
    assert creds == mock_creds
    mock_from_file.assert_called_once()
    assert mcp_server._credentials_cache == mock_creds

@patch("mcp_server.os.path.exists")
@patch("mcp_server.Credentials.from_authorized_user_file")
@patch("mcp_server.Request")
@patch("mcp_server.os.replace")
@patch("mcp_server.tempfile.NamedTemporaryFile")
def test_get_credentials_expired_token_refreshes(mock_tempfile, mock_replace, mock_request, mock_from_file, mock_exists):
    """Test that an expired token with a refresh_token is refreshed automatically."""
    # Setup mocks: token.json exists, but is expired
    mock_exists.return_value = True
    
    mock_creds = MagicMock()
    mock_creds.valid = False
    mock_creds.expired = True
    mock_creds.refresh_token = "some-refresh-token"
    mock_creds.to_json.return_value = '{"token": "new"}'
    
    mock_from_file.return_value = mock_creds

    # Execute
    creds = mcp_server.get_credentials()

    # Verify
    assert creds == mock_creds
    mock_creds.refresh.assert_called_once()
    mock_tempfile.assert_called_once()
    mock_replace.assert_called_once()

@patch("mcp_server.os.path.exists")
@patch("mcp_server.InstalledAppFlow.from_client_secrets_file")
@patch("mcp_server.os.replace")
@patch("mcp_server.tempfile.NamedTemporaryFile")
def test_get_credentials_interactive_flow(mock_tempfile, mock_replace, mock_flow, mock_exists, monkeypatch):
    """Test that missing token.json triggers the InstalledAppFlow interactive login."""
    # Setup mocks: nothing exists on disk initially, so it falls through to auth flow
    # os.path.exists is called for token.json, and then to find client_secret.json
    # We will mock os.path.exists to return False for token.json, but True for our fake client_secret
    def fake_exists(path):
        if "token.json" in path:
            return False
        if "client_secret" in path:
            return True
        return False
    
    mock_exists.side_effect = fake_exists

    # Mock the environment variable to point directly to a client secret to bypass the search logic
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/fake/client_secret.json")

    mock_flow_instance = MagicMock()
    mock_creds = MagicMock()
    mock_creds.valid = True
    mock_flow_instance.run_local_server.return_value = mock_creds
    mock_flow.return_value = mock_flow_instance

    # Execute
    creds = mcp_server.get_credentials()

    # Verify
    assert creds == mock_creds
    mock_flow.assert_called_once_with("/fake/client_secret.json", mcp_server.SCOPES)
    mock_flow_instance.run_local_server.assert_called_once_with(port=0)
    mock_tempfile.assert_called_once()
    mock_replace.assert_called_once()
