import base64
import os
from typing import Optional, Union
from cryptography.fernet import Fernet, InvalidToken


class Cryptography:
    __slots__ = ('_private_key', '_cipher_suite', '_utf8_encoding')

    _DEFAULT_KEY = "sMZo38VwRdigN78FBnHj8mETNlofL4Qhj_x5cvyxJsc="
    _ENCRYPTED_LENGTH = 100

    def __init__(self, private_key: Optional[str] = None) -> None:
        try:
            self._private_key = private_key or self._DEFAULT_KEY
            self._utf8_encoding = "utf-8"
            key_bytes = self._private_key.encode(self._utf8_encoding)
            self._cipher_suite = Fernet(key_bytes)
        except ValueError as e:
            raise ValueError(str(e)) from e

    @property
    def private_key(self) -> str:
        """Access to private key for backward compatibility"""
        return self._private_key

    def generate_private_key(self) -> str:
        """
        Generates a private key to be used instead of default one
        But keep in mind that this private key will be needed to decode further strings
        :return: str
        """
        random_bytes = os.urandom(32)
        encoded_key = base64.urlsafe_b64encode(random_bytes)
        return encoded_key.decode(self._utf8_encoding)

    def encode(self, str_to_encode: Union[str, bytes]) -> str:
        """
        Encodes a given string or bytes
        :param str_to_encode: str or bytes
        :return: str
        """
        # Handle both str and bytes inputs
        if isinstance(str_to_encode, str):
            data_bytes = str_to_encode.encode(self._utf8_encoding)
        else:
            data_bytes = str_to_encode

        encrypted_bytes = self._cipher_suite.encrypt(data_bytes)
        return encrypted_bytes.decode(self._utf8_encoding)

    def decode(self, str_to_decode: str) -> str:
        """
        Decodes a given string
        :param str_to_decode: str
        :return: str
        """

        if not str_to_decode:
            raise ValueError("String to decode cannot be empty")

        try:
            encrypted_bytes = str_to_decode.encode(self._utf8_encoding)
            decrypted_bytes = self._cipher_suite.decrypt(encrypted_bytes)
            return decrypted_bytes.decode(self._utf8_encoding)
        except InvalidToken:
            if len(str_to_decode) == self._ENCRYPTED_LENGTH:
                error_msg = "Encrypted with another private key"
            else:
                error_msg = "Not encrypted"
            raise InvalidToken(error_msg) from None

    def encode_batch(self, strings_to_encode: list[str]) -> list[str]:
        """
        Encode multiple strings at once
        :param strings_to_encode: list of strings
        :return: list of encoded strings
        """
        if not strings_to_encode:
            return []

        results = []
        cipher = self._cipher_suite
        encoding = self._utf8_encoding

        # Avoid attribute lookups in loop
        for text in strings_to_encode:
            data_bytes = text.encode(encoding)
            encrypted_bytes = cipher.encrypt(data_bytes)
            results.append(encrypted_bytes.decode(encoding))

        return results

    def decode_batch(self, strings_to_decode: list[str]) -> list[str]:
        """
        Decode multiple strings at once
        :param strings_to_decode: list of encoded strings
        :return: list of decoded strings
        """
        if not strings_to_decode:
            return []

        results = []
        cipher = self._cipher_suite
        encoding = self._utf8_encoding
        encrypted_length = self._ENCRYPTED_LENGTH

        for encrypted_text in strings_to_decode:
            if not encrypted_text:
                raise ValueError("String to decode cannot be empty")

            try:
                encrypted_bytes = encrypted_text.encode(encoding)
                decrypted_bytes = cipher.decrypt(encrypted_bytes)
                results.append(decrypted_bytes.decode(encoding))
            except InvalidToken:
                if len(encrypted_text) == encrypted_length:
                    error_msg = "Encrypted with another private key"
                else:
                    error_msg = "Not encrypted"
                raise InvalidToken(error_msg) from None

        return results
