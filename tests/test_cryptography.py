import pytest
from cryptography.fernet import InvalidToken
from ddcCryptography import Cryptography


class TestCryptography:
    @classmethod
    def setup_class(cls):
        cls.private_key = "sMZo38VwRdigN78FBnHj8mETNlofL4Qhj_x5cvyxJsc="
        cls.wrong_private_key = "wN3dIm9VeT_dtDi1rQoJVehdmUtG_lIFyGRGv9p4cAs="
        cls.test_string = "test"
        cls.crypto_instance = Cryptography(cls.private_key)

    def test_generate_private_key(self):
        result = self.crypto_instance.generate_private_key()
        assert result is not None
        assert len(result) > 0
        assert isinstance(result, str)

    def test_encode_str(self):
        result = self.crypto_instance.encode(self.test_string)
        assert result is not None
        assert isinstance(result, str)

    def test_encode_int(self):
        with pytest.raises(TypeError) as exc_info:
            self.crypto_instance.encode(1)
        assert "data must be bytes" in str(exc_info.value)

    def test_decode(self):
        # Use a pre-encoded string for consistent testing
        passw = "gAAAAABls-0f8Krl0SGvMrcJWv3fpa8cUfkcqb-yivz6KZS4jb0-N6K2AGkwq8GkVa5Btfpht9hiVVLcF8v0Vwj0_U2o799QbQ=="
        result = self.crypto_instance.decode(passw)
        assert result == self.test_string

    def test_decode_wrong_private_key(self):
        with pytest.raises(ValueError) as exc_info:
            Cryptography("not a private key")
        assert "Fernet key must be 32 url-safe base64-encoded bytes." in str(exc_info.value)

    def test_decode_not_encrypted(self):
        with pytest.raises(InvalidToken) as exc_info:
            self.crypto_instance.decode("not encrypted password")
        assert exc_info.value.args[0] == "Not encrypted"

    def test_decode_mismatch_private_key(self):
        wrong_crypto = Cryptography(self.wrong_private_key)
        passw = "gAAAAABls-0f8Krl0SGvMrcJWv3fpa8cUfkcqb-yivz6KZS4jb0-N6K2AGkwq8GkVa5Btfpht9hiVVLcF8v0Vwj0_U2o799QbQ=="
        with pytest.raises(InvalidToken) as exc_info:
            wrong_crypto.decode(passw)
        assert exc_info.value.args[0] == "Encrypted with another private key"

    def test_decode_empty_string(self):
        with pytest.raises(ValueError) as exc_info:
            self.crypto_instance.decode("")
        assert exc_info.value.args[0] == "String to decode cannot be empty"

    def test_encode_batch(self):
        test_strings = ["test1", "test2", "test3"]
        results = self.crypto_instance.encode_batch(test_strings)
        assert len(results) == 3
        assert all(isinstance(result, str) and result for result in results)

        # Verify we can decode them back
        decoded_results = self.crypto_instance.decode_batch(results)
        assert decoded_results == test_strings

    def test_decode_batch(self):
        test_strings = ["test1", "test2", "test3"]
        encoded_strings = self.crypto_instance.encode_batch(test_strings)
        results = self.crypto_instance.decode_batch(encoded_strings)
        assert results == test_strings

    def test_encode_batch_empty_list(self):
        results = self.crypto_instance.encode_batch([])
        assert results == []

    def test_decode_batch_empty_list(self):
        results = self.crypto_instance.decode_batch([])
        assert results == []

    def test_private_key_property(self):
        assert self.crypto_instance.private_key == self.private_key

    def test_encode_bytes_input(self):
        test_bytes = b"test_bytes"
        result = self.crypto_instance.encode(test_bytes)
        assert result is not None
        decoded = self.crypto_instance.decode(result)
        assert decoded == "test_bytes"

    def test_decode_batch_empty_string_error(self):
        """Test decode_batch with empty string - covers line 110"""
        with pytest.raises(ValueError) as exc_info:
            self.crypto_instance.decode_batch([""])
        assert exc_info.value.args[0] == "String to decode cannot be empty"

    def test_decode_batch_invalid_token_not_encrypted(self):
        """Test decode_batch with invalid token - covers lines 116-121"""
        crypto = Cryptography(self.private_key)
        with pytest.raises(InvalidToken) as exc_info:
            crypto.decode_batch(["not_encrypted_string"])
        assert exc_info.value.args[0] == "Not encrypted"
        assert exc_info.typename == "InvalidToken"

    def test_decode_batch_invalid_token_wrong_key(self):
        """Test decode_batch with wrong private key - covers lines 116-121"""
        crypto = Cryptography(self.private_key)
        wrong_crypto = Cryptography(self.wrong_private_key)

        # Encode with original key
        encoded_string = crypto.encode("test_message")

        # Try to decode the wrong key
        with pytest.raises(InvalidToken) as exc_info:
            wrong_crypto.decode_batch([encoded_string])
        assert exc_info.value.args[0] == "Encrypted with another private key"
        assert exc_info.typename == "InvalidToken"

    def test_init_with_default_key(self):
        """Test initialization without providing a key"""
        crypto = Cryptography()
        assert crypto.private_key == Cryptography._DEFAULT_KEY

        # Test it works for encoding/decoding
        test_text = "default_key_test"
        encoded = crypto.encode(test_text)
        decoded = crypto.decode(encoded)
        assert decoded == test_text

    def test_init_with_custom_key(self):
        """Test initialization with custom key"""
        # Use a valid Fernet key
        custom_key = self.crypto_instance.generate_private_key()
        crypto = Cryptography(custom_key)
        assert crypto.private_key == custom_key

    def test_generate_private_key_uniqueness(self):
        """Test that generate_private_key produces unique keys"""
        crypto = Cryptography()
        keys = set()
        for _ in range(10):
            key = crypto.generate_private_key()
            assert len(key) > 0
            keys.add(key)
        # All keys should be unique
        assert len(keys) == 10

    def test_generate_private_key_validity(self):
        """Test that generated keys are valid and can be used"""
        crypto = Cryptography()
        generated_key = crypto.generate_private_key()

        # Use the generated key to create a new crypto instance
        new_crypto = Cryptography(generated_key)
        test_message = "test_with_generated_key"

        encoded = new_crypto.encode(test_message)
        decoded = new_crypto.decode(encoded)
        assert decoded == test_message

    def test_encode_batch_with_mixed_content(self):
        """Test encode_batch with various string types"""
        crypto = Cryptography(self.private_key)
        test_strings = [
            "short",
            "medium length string with spaces",
            "very_long_string_" * 10,
            "special!@#$%^&*()characters",
            "unicode_тест_測試",
            "",  # empty string should work in encode
            "123456789",
        ]

        results = crypto.encode_batch(test_strings)
        assert len(results) == len(test_strings)

        # Verify all can be decoded back
        decoded_results = crypto.decode_batch(results)
        assert decoded_results == test_strings

    def test_batch_operations_performance(self):
        """Test that batch operations work with larger datasets"""
        crypto = Cryptography(self.private_key)
        large_dataset = [f"test_string_{i}" for i in range(100)]

        # Test batch encoding
        encoded_batch = crypto.encode_batch(large_dataset)
        assert len(encoded_batch) == 100

        # Test batch decoding
        decoded_batch = crypto.decode_batch(encoded_batch)
        assert decoded_batch == large_dataset

    def test_encode_decode_consistency(self):
        """Test that encoding and decoding are consistent across different instances"""
        crypto1 = Cryptography(self.private_key)
        crypto2 = Cryptography(self.private_key)

        test_message = "consistency_test_message"

        # Encode with first instance
        encoded = crypto1.encode(test_message)

        # Decode with second instance
        decoded = crypto2.decode(encoded)

        assert decoded == test_message

    def test_edge_case_very_long_string(self):
        """Test encoding/decoding very long strings"""
        crypto = Cryptography(self.private_key)
        very_long_string = "A" * 10000  # 10KB string

        encoded = crypto.encode(very_long_string)
        decoded = crypto.decode(encoded)

        assert decoded == very_long_string
        assert len(decoded) == 10000

    def test_edge_case_special_characters(self):
        """Test encoding/decoding strings with special characters"""
        crypto = Cryptography(self.private_key)
        special_strings = [
            "newline\ntest",
            "tab\ttest",
            "unicode: àáâãäåæçèé",
            "emoji: 🔐🔑💻",
            "json: {\"key\": \"value\"}",
            "xml: <root><child>text</child></root>",
        ]

        for special_string in special_strings:
            encoded = crypto.encode(special_string)
            decoded = crypto.decode(encoded)
            assert decoded == special_string

    def test_private_key_immutability(self):
        """Test that private_key property is read-only via property"""
        crypto = Cryptography(self.private_key)
        original_key = crypto.private_key

        # Should not be able to modify the key directly
        assert crypto.private_key == original_key

    def test_class_constants(self):
        """Test class-level constants"""
        assert Cryptography._DEFAULT_KEY == "sMZo38VwRdigN78FBnHj8mETNlofL4Qhj_x5cvyxJsc="
        assert Cryptography._ENCRYPTED_LENGTH == 100

    def test_slots_memory_optimization(self):
        """Test that __slots__ is working properly"""
        crypto = Cryptography()

        # Should have the expected slots
        expected_slots = ('_private_key', '_cipher_suite', '_utf8_encoding')
        assert crypto.__slots__ == expected_slots

        # Should not be able to add arbitrary attributes
        with pytest.raises(AttributeError):
            crypto.arbitrary_attribute = "should_fail"
