"""Remediation advisor using the Anthropic Claude API.

This module generates specific, actionable remediation steps for users
whose credentials were found in a data breach. Results are cached in the
database to minimize API calls and latency for common breaches.
"""

import hashlib
import json
import logging
from typing import Any

import anthropic

from ..config.settings import settings
from ..database.models import RemediationCache

logger = logging.getLogger(__name__)


class LLMAdvisor:
    """Uses Anthropic Claude to generate personalized breach remediation advice."""

    def __init__(self) -> None:
        """Initialize the Claude API client and model parameters."""
        self.client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        self.model: str = settings.CLAUDE_MODEL
        self.max_tokens: int = settings.CLAUDE_MAX_TOKENS

    def _build_cache_key(self, breach_name: str, data_classes: list[str]) -> str:
        """Construct a deterministic cache key for a specific breach scenario.
        
        Args:
            breach_name: The name of the breach.
            data_classes: A list of exposed data classes.
            
        Returns:
            A SHA-256 hex digest string.
        """
        sorted_classes: list[str] = sorted(data_classes)
        joined_classes: str = ",".join(sorted_classes)
        raw_key: str = f"{breach_name}|{joined_classes}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def _build_prompt(self, breach_name: str, data_classes: list[str]) -> str:
        """Construct the precise prompt required to instruct Claude.
        
        Args:
            breach_name: The name of the breach.
            data_classes: A list of exposed data classes.
            
        Returns:
            The fully formatted prompt string.
        """
        classes_str: str = ", ".join(data_classes)
        prompt: str = f"""
You are a cybersecurity expert helping a regular person understand
what to do after their data was exposed in a breach.

The user's email was found in the '{breach_name}' data breach.
The following types of data were exposed: {classes_str}

Write a clear, friendly, step-by-step remediation checklist.
Format your response EXACTLY as follows:

IMMEDIATE ACTIONS (Do these within 1 hour):
1. [specific action]
2. [specific action]

SHORT-TERM ACTIONS (Do these within 24 hours):
3. [specific action]
4. [specific action]

LONG-TERM PROTECTION (Do these this week):
5. [specific action]

RULES FOR YOUR RESPONSE:
- Be specific to the {breach_name} platform and what was exposed
- Use plain English, no jargon
- Each step must start with an action verb (e.g., Change, Enable, Check)
- Keep each step to 1-2 sentences maximum
- Total response must be under 400 words
- Do not include any preamble or explanation before the checklist
"""
        return prompt.strip()

    def generate_remediation(
        self,
        breach_name: str,
        data_classes: list[str],
        db_session: Any
    ) -> str:
        """Generate remediation steps for a given breach, utilizing the DB cache.
        
        Args:
            breach_name: The name of the breach.
            data_classes: A list of exposed data classes.
            db_session: A SQLAlchemy session to access the cache.
            
        Returns:
            A string containing the formatted remediation checklist.
        """
        cache_key: str = self._build_cache_key(breach_name, data_classes)
        
        try:
            # Query the database to check if this exact scenario has been seen before
            existing = db_session.query(RemediationCache).filter_by(cache_key=cache_key).first()
            if existing:
                existing.hit_count += 1
                db_session.commit()
                logger.info(f"Cache hit for breach {breach_name}, hit_count={existing.hit_count}")
                return existing.remediation_text
                
        except Exception as e:
            # We don't want a DB error to completely break the flow if we can just call the API
            logger.warning(f"Failed to query remediation cache for {breach_name}: {e}")

        # Cache miss or DB error, call the Claude API
        try:
            logger.info(f"Generating new remediation advice via Claude for {breach_name}")
            prompt_content: str = self._build_prompt(breach_name, data_classes)
            
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[{"role": "user", "content": prompt_content}],
            )
            
            remediation_text: str = response.content[0].text
            
            # Attempt to save the newly generated advice back to the cache
            try:
                new_cache_entry = RemediationCache(
                    cache_key=cache_key,
                    breach_name=breach_name,
                    data_classes_json=data_classes,
                    remediation_text=remediation_text,
                    hit_count=1,
                )
                db_session.add(new_cache_entry)
                db_session.commit()
                logger.info(f"Successfully cached new remediation advice for {breach_name}")
            except Exception as db_e:
                logger.warning(f"Failed to save generated advice to cache: {db_e}")
                db_session.rollback()
                
            return remediation_text
            
        except Exception as api_e:
            logger.error(f"Failed to generate remediation via Claude: {api_e}")
            # Safe fallback string exactly as specified if API or network fails
            return "Please change your password for this service immediately and enable two-factor authentication."

    def generate_risk_summary(
        self,
        total_breaches: int,
        severity_counts: dict[str, int],
        most_exposed_data: list[str]
    ) -> str:
        """Generate a concise risk summary spanning all of a user's breaches.
        
        Args:
            total_breaches: Total number of breaches across all emails.
            severity_counts: Dictionary mapping severity labels to their occurrences.
            most_exposed_data: A list of the most frequent types of data exposed.
            
        Returns:
            A brief 2-3 sentence risk summary string.
        """
        try:
            severity_str: str = json.dumps(severity_counts)
            most_exposed_str: str = ", ".join(most_exposed_data)
            
            prompt: str = (
                f"A user has {total_breaches} total data breaches. Breakdown by severity: "
                f"{severity_str}. The most exposed data types are: {most_exposed_str}. "
                "Write a brief 2-3 sentence risk summary assessing their overall cybersecurity "
                "posture and the most critical threat vector they face right now. Do not include "
                "remediation steps."
            )
            
            logger.info("Generating overall risk summary via Claude")
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            
            return response.content[0].text
            
        except Exception as e:
            logger.error(f"Failed to generate risk summary via Claude: {e}")
            # Fallback text if the API fails
            return (
                f"You have {total_breaches} total breaches affecting your accounts. "
                "Please review the high-severity alerts immediately and monitor your "
                "accounts for suspicious activity."
            )
