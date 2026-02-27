"""Unit tests for the HIBP API client.

Validates the interactions with HaveIBeenPwned API and parsing logic.
"""

from unittest.mock import MagicMock, patch

from backend.ingestion.hibp_client import HIBPClient


@patch("httpx.Client.get")
def test_get_all_breaches_success(mock_get) -> None:
    """Verify that fetching all breaches processes and normalizes the payload correctly."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "Name": "TestBreach",
            "Domain": "test.com",
            "BreachDate": "2023-01-01",
            "DataClasses": ["Email addresses", "Passwords"],
            "PwnCount": 1000,
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": False,
        }
    ]
    mock_get.return_value = mock_response

    client = HIBPClient()
    # Bypass the cache if it was set
    client._all_breaches_cache = None
    
    breaches = client.get_all_breaches()

    assert len(breaches) == 1
    assert breaches[0]["Name"] == "TestBreach"
    assert breaches[0]["DataClasses"] == ["Email addresses", "Passwords"]


@patch("httpx.Client.get")
def test_get_breaches_for_email_no_breaches(mock_get) -> None:
    """Verify that a 404 from HIBP translates to an empty breach list (safe footprint)."""
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response

    client = HIBPClient()
    breaches = client.get_breaches_for_email("secure@example.com")

    assert breaches == []
