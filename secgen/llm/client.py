"""Gemini LLM client wrapper with retry logic and response parsing."""

import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

# Check if google-genai is available
try:
    from google import genai
    from google.genai import types

    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    genai = None  # type: ignore
    types = None  # type: ignore

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class GeminiClient:
    """
    Wrapper around Google Gemini API for generating security data artifacts.

    Provides:
    - Configurable model selection
    - Response parsing (JSON/YAML)
    - Token counting for cost awareness
    - Rate limiting and retry logic
    """

    DEFAULT_MAX_RETRIES = 3
    DEFAULT_RETRY_DELAY = 1.0
    DEFAULT_TEMPERATURE = 0.7

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-3-pro-preview",
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_delay: float = DEFAULT_RETRY_DELAY,
    ) -> None:
        """
        Initialize Gemini client.

        Args:
            api_key: Google Gemini API key
            model: Model name to use (gemini-3-pro-preview, gemini-2.0-flash, etc.)
            max_retries: Maximum retry attempts for failed requests
            retry_delay: Base delay between retries (exponential backoff)

        Raises:
            ImportError: If google-genai is not installed
            ValueError: If API key is empty
        """
        if not GEMINI_AVAILABLE:
            raise ImportError(
                "google-genai is not installed. Install with: pip install google-genai"
            )

        if not api_key:
            raise ValueError(
                "Gemini API key is required. "
                "Set GEMINI_API_KEY environment variable or pass api_key parameter."
            )

        self.api_key = api_key
        self.model_name = model
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        # Create the client
        self.client = genai.Client(api_key=api_key)

        # Track token usage
        self._total_prompt_tokens = 0
        self._total_completion_tokens = 0

        logger.info(f"Initialized Gemini client with model: {model}")

    def generate(
        self,
        prompt: str,
        temperature: float = DEFAULT_TEMPERATURE,
        max_output_tokens: int | None = None,
    ) -> str:
        """
        Generate text from a prompt with retry logic.

        Args:
            prompt: The prompt to send to the model
            temperature: Sampling temperature (0.0-1.0)
            max_output_tokens: Maximum tokens in response

        Returns:
            Generated text response

        Raises:
            RuntimeError: If all retries are exhausted
        """
        config = types.GenerateContentConfig(
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )

        last_error: Exception | None = None

        for attempt in range(self.max_retries):
            try:
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=config,
                )

                # Track token usage if available
                if hasattr(response, "usage_metadata") and response.usage_metadata:
                    usage = response.usage_metadata
                    if hasattr(usage, "prompt_token_count") and usage.prompt_token_count:
                        self._total_prompt_tokens += usage.prompt_token_count
                    if hasattr(usage, "candidates_token_count") and usage.candidates_token_count:
                        self._total_completion_tokens += usage.candidates_token_count

                return response.text

            except Exception as e:
                last_error = e
                delay = self.retry_delay * (2**attempt)
                logger.warning(
                    f"Gemini API error (attempt {attempt + 1}/{self.max_retries}): {e}. "
                    f"Retrying in {delay:.1f}s..."
                )
                time.sleep(delay)

        raise RuntimeError(
            f"Failed to generate after {self.max_retries} attempts. Last error: {last_error}"
        )

    def generate_json(
        self,
        prompt: str,
        temperature: float = DEFAULT_TEMPERATURE,
        max_output_tokens: int | None = None,
    ) -> dict[str, Any]:
        """
        Generate and parse JSON response.

        Args:
            prompt: The prompt (should request JSON output)
            temperature: Sampling temperature
            max_output_tokens: Maximum tokens in response

        Returns:
            Parsed JSON as dictionary

        Raises:
            json.JSONDecodeError: If response is not valid JSON
        """
        # Add JSON instruction to prompt
        full_prompt = f"{prompt}\n\nRespond ONLY with valid JSON, no markdown or explanation."

        response = self.generate(
            full_prompt,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )

        # Clean up response (remove markdown code blocks if present)
        cleaned = self._clean_code_block(response, "json")

        return json.loads(cleaned)

    def generate_yaml(
        self,
        prompt: str,
        temperature: float = DEFAULT_TEMPERATURE,
        max_output_tokens: int | None = None,
    ) -> dict[str, Any]:
        """
        Generate and parse YAML response.

        Args:
            prompt: The prompt (should request YAML output)
            temperature: Sampling temperature
            max_output_tokens: Maximum tokens in response

        Returns:
            Parsed YAML as dictionary

        Raises:
            yaml.YAMLError: If response is not valid YAML
            ImportError: If PyYAML is not installed
        """
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML is not installed. Install with: pip install pyyaml")

        # Add YAML instruction to prompt
        full_prompt = f"{prompt}\n\nRespond ONLY with valid YAML, no markdown or explanation."

        response = self.generate(
            full_prompt,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )

        # Clean up response (remove markdown code blocks if present)
        cleaned = self._clean_code_block(response, "yaml")

        return yaml.safe_load(cleaned)

    def _clean_code_block(self, text: str, language: str) -> str:
        """
        Remove markdown code block markers from response.

        Args:
            text: Raw response text
            language: Expected language (json, yaml)

        Returns:
            Cleaned text without code block markers
        """
        text = text.strip()

        # Remove ```json or ```yaml markers
        for prefix in [f"```{language}", "```"]:
            if text.startswith(prefix):
                text = text[len(prefix) :]
                break

        # Remove trailing ```
        if text.endswith("```"):
            text = text[:-3]

        return text.strip()

    @property
    def total_tokens_used(self) -> dict[str, int]:
        """Get total token usage statistics."""
        return {
            "prompt_tokens": self._total_prompt_tokens,
            "completion_tokens": self._total_completion_tokens,
            "total_tokens": self._total_prompt_tokens + self._total_completion_tokens,
        }

    def reset_token_count(self) -> None:
        """Reset token usage counters."""
        self._total_prompt_tokens = 0
        self._total_completion_tokens = 0


def get_gemini_client(settings: Any) -> GeminiClient:
    """
    Create a Gemini client from settings.

    Args:
        settings: Settings object with gemini_api_key and gemini_model

    Returns:
        Configured GeminiClient instance
    """
    return GeminiClient(
        api_key=settings.gemini_api_key,
        model=settings.gemini_model,
    )
