"""Tests for Gemini client."""

import pytest
from unittest.mock import MagicMock, patch


class TestGeminiClient:
    """Tests for GeminiClient."""

    @pytest.fixture
    def mock_genai(self):
        """Mock the google.genai module."""
        mock_types = MagicMock()

        with patch("secgen.llm.client.GEMINI_AVAILABLE", True):
            with patch("secgen.llm.client.genai") as mock_gen:
                with patch("secgen.llm.client.types", mock_types):
                    mock_gen.Client = MagicMock()
                    yield mock_gen, mock_types

    def test_init_requires_api_key(self, mock_genai):
        """Test that initialization requires an API key."""
        mock_gen, _ = mock_genai
        from secgen.llm.client import GeminiClient

        with pytest.raises(ValueError, match="API key is required"):
            GeminiClient(api_key="")

    def test_init_configures_api(self, mock_genai):
        """Test that initialization configures the Gemini API."""
        mock_gen, _ = mock_genai
        from secgen.llm.client import GeminiClient

        client = GeminiClient(api_key="test_key", model="gemini-2.0-flash")

        mock_gen.Client.assert_called_once_with(api_key="test_key")

    def test_generate_returns_text(self, mock_genai):
        """Test that generate returns response text."""
        mock_gen, mock_types = mock_genai

        # Setup mock
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "Generated response"
        mock_client.models.generate_content.return_value = mock_response
        mock_gen.Client.return_value = mock_client

        from secgen.llm.client import GeminiClient

        client = GeminiClient(api_key="test_key")
        result = client.generate("Test prompt")

        assert result == "Generated response"

    def test_generate_retries_on_failure(self, mock_genai):
        """Test that generate retries on failure."""
        mock_gen, mock_types = mock_genai

        with patch("secgen.llm.client.time.sleep"):  # Don't actually sleep
            # Setup mock to fail twice then succeed
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.text = "Success"

            call_count = 0

            def side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count < 3:
                    raise Exception("API Error")
                return mock_response

            mock_client.models.generate_content.side_effect = side_effect
            mock_gen.Client.return_value = mock_client

            from secgen.llm.client import GeminiClient

            client = GeminiClient(api_key="test_key", max_retries=3, retry_delay=0.1)
            result = client.generate("Test prompt")

            assert result == "Success"
            assert call_count == 3

    def test_generate_raises_after_max_retries(self, mock_genai):
        """Test that generate raises after exhausting retries."""
        mock_gen, mock_types = mock_genai

        with patch("secgen.llm.client.time.sleep"):
            mock_client = MagicMock()
            mock_client.models.generate_content.side_effect = Exception("Always fails")
            mock_gen.Client.return_value = mock_client

            from secgen.llm.client import GeminiClient

            client = GeminiClient(api_key="test_key", max_retries=2, retry_delay=0.1)

            with pytest.raises(RuntimeError, match="Failed to generate"):
                client.generate("Test prompt")

    def test_generate_json_parses_response(self, mock_genai):
        """Test that generate_json parses JSON response."""
        mock_gen, mock_types = mock_genai

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = '{"key": "value"}'
        mock_client.models.generate_content.return_value = mock_response
        mock_gen.Client.return_value = mock_client

        from secgen.llm.client import GeminiClient

        client = GeminiClient(api_key="test_key")
        result = client.generate_json("Test prompt")

        assert result == {"key": "value"}

    def test_generate_json_strips_code_blocks(self, mock_genai):
        """Test that generate_json strips markdown code blocks."""
        mock_gen, mock_types = mock_genai

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = '```json\n{"key": "value"}\n```'
        mock_client.models.generate_content.return_value = mock_response
        mock_gen.Client.return_value = mock_client

        from secgen.llm.client import GeminiClient

        client = GeminiClient(api_key="test_key")
        result = client.generate_json("Test prompt")

        assert result == {"key": "value"}

    def test_clean_code_block_json(self, mock_genai):
        """Test _clean_code_block for JSON."""
        mock_gen, mock_types = mock_genai

        from secgen.llm.client import GeminiClient

        client = GeminiClient(api_key="test_key")

        # Test with ```json prefix
        result = client._clean_code_block('```json\n{"data": 1}\n```', "json")
        assert result == '{"data": 1}'

        # Test with just ``` prefix
        result = client._clean_code_block('```\n{"data": 1}\n```', "json")
        assert result == '{"data": 1}'

        # Test without code block
        result = client._clean_code_block('{"data": 1}', "json")
        assert result == '{"data": 1}'

    def test_token_tracking(self, mock_genai):
        """Test token usage tracking."""
        mock_gen, mock_types = mock_genai

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "Response"
        mock_response.usage_metadata = MagicMock()
        mock_response.usage_metadata.prompt_token_count = 100
        mock_response.usage_metadata.candidates_token_count = 50
        mock_client.models.generate_content.return_value = mock_response
        mock_gen.Client.return_value = mock_client

        from secgen.llm.client import GeminiClient

        client = GeminiClient(api_key="test_key")
        client.generate("Test")

        usage = client.total_tokens_used
        assert usage["prompt_tokens"] == 100
        assert usage["completion_tokens"] == 50
        assert usage["total_tokens"] == 150

    def test_reset_token_count(self, mock_genai):
        """Test resetting token counters."""
        mock_gen, mock_types = mock_genai

        from secgen.llm.client import GeminiClient

        client = GeminiClient(api_key="test_key")
        client._total_prompt_tokens = 100
        client._total_completion_tokens = 50

        client.reset_token_count()

        usage = client.total_tokens_used
        assert usage["total_tokens"] == 0


class TestGeminiClientImportError:
    """Tests for when google-genai is not installed."""

    def test_raises_import_error_when_not_available(self):
        """Test that ImportError is raised when SDK not installed."""
        with patch("secgen.llm.client.GEMINI_AVAILABLE", False):
            # Need to reimport to get the patched value
            import secgen.llm.client as client_module

            # Temporarily store original
            original_available = client_module.GEMINI_AVAILABLE
            client_module.GEMINI_AVAILABLE = False

            try:
                with pytest.raises(ImportError, match="google-genai"):
                    client_module.GeminiClient(api_key="test")
            finally:
                client_module.GEMINI_AVAILABLE = original_available

