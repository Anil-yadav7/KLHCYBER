"""Have I Been Pwned API client for data ingestion.

This module provides the HIBPClient class to communicate with the Have I Been Pwned
and Pwned Passwords APIs. It implements rate limiting and k-anonymity for privacy.
"""

import hashlib
import logging
import time
from typing import Any, Optional

import httpx

from ..config.settings import settings

logger = logging.getLogger(__name__)


class HIBPClient:
    """Client for interacting with Have I Been Pwned APIs."""

    def __init__(self) -> None:
        """Initialize the HIBP API client with configuration from settings."""
        self.session = httpx.Client(timeout=30.0)
        self.headers: dict[str, str] = {
            "hibp-api-key": settings.HIBP_API_KEY,
            "user-agent": settings.HIBP_USER_AGENT,
        }
        self.base_url: str = settings.HIBP_BASE_URL
        self.pwned_url: str = settings.HIBP_PWNED_URL
        self.rate_limit: float = settings.HIBP_RATE_LIMIT_SECONDS
        self._last_request_time: float = 0.0
        
        # Cache for all breaches
        self._all_breaches_cache: Optional[list[dict[str, Any]]] = None
        self._all_breaches_cache_time: float = 0.0

    def _wait_for_rate_limit(self) -> None:
        """Ensure API requests strictly adhere to the HIBP rate limit.
        
        Calculates the time since the last request and pauses execution if needed.
        Must be called before executing any HTTP GET request.
        """
        elapsed: float = time.time() - self._last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()

    def get_breaches_for_email(self, email: str) -> list[dict[str, Any]]:
        """Retrieve all data breaches associated with a given email address.
        
        Args:
            email: The email address to search for.
            
        Returns:
            A list of dictionary objects representing breaches. Empty if none found.
            
        Raises:
            ValueError: If the HIBP API key is invalid (401 response).
            RuntimeError: If an unexpected error is returned from the API.
        """
        url: str = f"{self.base_url}/breachedaccount/{email}?truncateResponse=false"
        
        try:
            self._wait_for_rate_limit()
            response = self.session.get(url, headers=self.headers)
            
            if response.status_code == 429:
                logger.warning(f"Rate limited by HIBP for email {email}, waiting 5 seconds and retrying...")
                time.sleep(5.0)
                self._wait_for_rate_limit()
                response = self.session.get(url, headers=self.headers)
                
            if response.status_code == 404:
                return []
            if response.status_code == 401:
                raise ValueError("Invalid HIBP API key")
            if response.status_code == 200:
                logger.info(f"Successfully retrieved breaches for {email}")
                return response.json()
                
            raise RuntimeError(f"HIBP API error: {response.status_code}")
            
        except httpx.RequestError as e:
            logger.error(f"HTTP request error while fetching breaches for {email}: {e}")
            raise RuntimeError(f"Failed to communicate with HIBP API: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error in get_breaches_for_email: {e}")
            raise

    def check_password_pwned(self, password: str) -> int:
        """Check if a password has been compromised using the Pwned Passwords API.
        
        Implements k-anonymity by only sending the first 5 characters of the SHA-1 hash
        to the API, preserving the privacy of the original password.
        
        Args:
            password: The plaintext password to check.
            
        Returns:
            The number of times the password was found in the breach database.
            
        Raises:
            RuntimeError: If the Pwned Passwords API request fails.
        """
        sha1_hash: str = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix: str = sha1_hash[:5]
        suffix: str = sha1_hash[5:]
        url: str = f"{self.pwned_url}/range/{prefix}"
        
        try:
            self._wait_for_rate_limit()
            # Do NOT send standard headers (API key is not required and should not be leaked)
            response = self.session.get(url)
            response.raise_for_status()
            
            for line in response.text.splitlines():
                if ":" in line:
                    hash_suffix, count_str = line.split(":", 1)
                    if hash_suffix == suffix:
                        return int(count_str)
            return 0
            
        except httpx.RequestError as e:
            logger.error(f"HTTP request error while checking password: {e}")
            raise RuntimeError(f"Failed to communicate with Pwned Passwords API: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error in check_password_pwned: {e}")
            raise

    def get_all_breaches(self) -> list[dict[str, Any]]:
        """Retrieve the exhaustive list of all breaches tracked by HIBP.
        
        Caches the request in memory for 24 hours to avoid redundant API calls.
        
        Returns:
            A complete list of dictionary objects representing all documented breaches.
            
        Raises:
            RuntimeError: If the API request fails to fetch all breaches.
        """
        current_time: float = time.time()
        # 86400 seconds = 24 hours TTL for the internal cache
        if self._all_breaches_cache is not None and (current_time - self._all_breaches_cache_time) < 86400:
            logger.info("Returning all breaches from internal 24h cache.")
            return self._all_breaches_cache

        url: str = f"{self.base_url}/breaches"
        try:
            self._wait_for_rate_limit()
            response = self.session.get(url, headers=self.headers)
            response.raise_for_status()
            
            breaches: list[dict[str, Any]] = response.json()
            # Update cache successfully
            self._all_breaches_cache = breaches
            self._all_breaches_cache_time = current_time
            logger.info(f"Successfully fetched and cached {len(breaches)} breaches from HIBP.")
            return breaches
            
        except httpx.RequestError as e:
            logger.error(f"HTTP request error while fetching all breaches: {e}")
            raise RuntimeError(f"Failed to fetch all breaches from HIBP API: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error in get_all_breaches: {e}")
            raise

    def normalize_breach(self, raw_breach: dict[str, Any]) -> dict[str, Any]:
        """Convert a raw HIBP breach dictionary into a cleansed, standard format.
        
        Strips away unused or excessive metadata to maintain a clean internal model.
        
        Args:
            raw_breach: The raw dictionary directly from the HIBP API.
            
        Returns:
            A normalized dictionary with verified safe mappings.
        """
        return {
            "name": str(raw_breach.get("Name", "")),
            "domain": str(raw_breach.get("Domain", "")),
            "breach_date": str(raw_breach.get("BreachDate", "")),
            "pwn_count": int(raw_breach.get("PwnCount", 0)),
            "data_classes": list(raw_breach.get("DataClasses", [])),
            "is_verified": bool(raw_breach.get("IsVerified", True)),
            "is_fabricated": bool(raw_breach.get("IsFabricated", False)),
            "is_sensitive": bool(raw_breach.get("IsSensitive", False)),
        }

    def close(self) -> None:
        """Close the underlying HTTP session connection.
        
        Ensures resources handle tear-down gracefully.
        """
        self.session.close()
        logger.info("HIBP client session closed")

    def __enter__(self) -> "HIBPClient":
        """Enter the context manager, returning the established client."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the context manager, safely closing the session."""
        self.close()
