import json

class Protocol:
    TYPE_HANDSHAKE = "HANDSHAKE"
    TYPE_SESSION = "SESSION"
    TYPE_DATA = "DATA"
    TYPE_RESPONSE = "RESPONSE"

    STATUS_OK = "OK"
    STATUS_ERROR = "ERROR"
    STATUS_PENALTY = "PENALTY"

    @staticmethod
    def create_message(msg_type, payload=None, signature=None):
        """
        Creates a JSON message string.
        payload: dict or string
        signature: hex string (optional)
        """
        message = {
            "type": msg_type,
            "payload": payload,
        }
        if signature:
            message["signature"] = signature
        return json.dumps(message)

    @staticmethod
    def parse_message(json_data):
        return json.loads(json_data)
