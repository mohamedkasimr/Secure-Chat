import json
import base64
import struct
from .crypto_utils import CryptoUtils

class ProtocolHandler:
    """
    Handles the Presentation Layer security requirements:
    - Serialization/Deserialization of JSON payloads.
    - End-to-End Encryption (E2E) of message contents.
    - Message framing (length-prefixed) to handle complete socket messages.
    """

    @staticmethod
    def create_message(msg_type: str, payload: dict) -> bytes:
        """
        Creates a structured JSON message.
        """
        msg = {
            "type": msg_type,
            "payload": payload
        }
        json_data = json.dumps(msg).encode('utf-8')
        return json_data

    @staticmethod
    def parse_message(data: bytes) -> dict:
        """
        Parses a structured JSON message.
        """
        try:
            return json.loads(data.decode('utf-8'))
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON message format: {e}")

    @staticmethod
    def frame_message(message: bytes) -> bytes:
        """
        Adds a 4-byte length prefix to a message for reliable socket transmission.
        """
        return struct.pack("!I", len(message)) + message

    @staticmethod
    def unframe_message(data: bytes) -> tuple:
        """
        Attempts to read a length-prefixed message from a buffer.
        Returns (message_bytes, remaining_buffer) if a complete message is available.
        Returns (None, data) if incomplete.
        """
        if len(data) < 4:
            return None, data
        
        msg_len = struct.unpack("!I", data[:4])[0]
        if len(data) < 4 + msg_len:
            return None, data

        return data[4:4 + msg_len], data[4 + msg_len:]

    @staticmethod
    def encrypt_payload(aes_key: bytes, plaintext_payload: dict) -> dict:
        """
        Encrypts the payload dictionary using AES-GCM for End-to-End Encryption.
        """
        plaintext_bytes = json.dumps(plaintext_payload).encode('utf-8')
        ciphertext, nonce, tag = CryptoUtils.encrypt_aes_gcm(aes_key, plaintext_bytes)

        return {
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8')
        }

    @staticmethod
    def decrypt_payload(aes_key: bytes, encrypted_payload: dict) -> dict:
        """
        Decrypts an E2E AES-GCM encrypted payload.
        """
        try:
            ciphertext = base64.b64decode(encrypted_payload["ciphertext"])
            nonce = base64.b64decode(encrypted_payload["nonce"])
            tag = base64.b64decode(encrypted_payload["tag"])

            plaintext_bytes = CryptoUtils.decrypt_aes_gcm(aes_key, nonce, tag, ciphertext)
            return json.loads(plaintext_bytes.decode('utf-8'))
        except KeyError as e:
            raise ValueError(f"Missing encryption field: {e}")
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
