import base64
import os
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken


class Cryptography:
    __slots__ = ('private_key', 'cipher_suite')
    
    def __init__(self, private_key: Optional[str] = None) -> None:
        try:
            self.private_key = private_key or "sMZo38VwRdigN78FBnHj8mETNlofL4Qhj_x5cvyxJsc="
            self.cipher_suite = Fernet(self.private_key.encode("utf-8"))
        except ValueError as e:
            raise ValueError(str(e)) from e

    @staticmethod
    def generate_private_key() -> str:
        """
        Generates a private key to be used instead of default one
        But keep in mind that this private key will be needed to decode further strings
        :return: str
        """
        private_key = base64.urlsafe_b64encode(os.urandom(32))
        return private_key.decode("utf-8")

    def encode(self, str_to_encode: str) -> str:
        """
        Encodes a given string
        :param str_to_encode: str
        :return: str
        """
        str_bytes = str_to_encode.encode("utf-8")
        encoded_text = self.cipher_suite.encrypt(str_bytes)
        return encoded_text.decode("utf-8")

    def decode(self, str_to_decode: str) -> str:
        """
        Decodes a given string
        :param str_to_decode: str
        :return: str
        """
        if not str_to_decode:
            raise ValueError("String to decode cannot be empty")
            
        try:
            encrypted_bytes = str_to_decode.encode("utf-8")
            decoded_text = self.cipher_suite.decrypt(encrypted_bytes).decode("utf-8")
            return decoded_text
        except InvalidToken:
            error_msg = "Not encrypted"
            if len(str_to_decode) == 100:
                error_msg = "Encrypted with another private key"
            raise InvalidToken(error_msg) from None
