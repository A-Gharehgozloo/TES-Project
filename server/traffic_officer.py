import socket
import threading
import json
import time
import os
import uuid

from server.auth import AuthManager
from server.storage import StorageManager
from core.crypto_utils import RSAManager, DESManager
from core.protocol import Protocol
from core.logger import TESLogger

class TrafficOfficerServer:
    HOST = '127.0.0.1'
    PORT = 9999
    PENDING_FILE = "data/pending.json"

    def __init__(self):
        self.auth = AuthManager()
        self.storage = StorageManager()
        self.private_key, self.public_key = RSAManager.generate_keys()
        self.rsa_manager = RSAManager(private_key_data=self.private_key, public_key_data=self.public_key)
        TESLogger.setup()
        TESLogger.log("Server Initialized (Socket: 9999). RSA Keys Generated.")

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.HOST, self.PORT))
        self.server_socket.listen(5)
        TESLogger.log(f"Listening on {self.HOST}:{self.PORT}")

        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                TESLogger.log(f"Connection from {addr}")
                client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_handler.start()
        except Exception as e:
            TESLogger.log(f"Server Error: {e}", "ERROR")
        finally:
            self.server_socket.close()

    def _queue_message(self, plate, speed, signature_verified):
        # Add to pending.json
        # Format: {id, timestamp, plate, speed, signature_verified, status='PENDING'}
        
        record = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "plate": plate,
            "speed": speed,
            "signature_verified": signature_verified,
            "status": "PENDING"
        }
        
        PENDING_FILE = "data/pending.json"
        data = []
        if os.path.exists(PENDING_FILE):
            with open(PENDING_FILE, 'r') as f:
                try:
                    data = json.load(f)
                except:
                    data = []
        
        data.append(record)
        with open(PENDING_FILE, 'w') as f:
            json.dump(data, f, indent=4)
        
        TESLogger.log(f"Queued message for {plate} (Verified: {signature_verified})")

    def handle_client(self, conn):
        des_manager = None
        authenticated_user = None
        client_rsa = None

        try:
            # 1. Send Public Key
            handshake_msg = Protocol.create_message(Protocol.TYPE_HANDSHAKE, payload=self.public_key.decode('utf-8'))
            conn.sendall(handshake_msg.encode('utf-8'))

            while True:
                data = conn.recv(4096)
                if not data:
                    break

                try:
                    message_str = data.decode('utf-8')
                    message = Protocol.parse_message(message_str)
                except json.JSONDecodeError:
                    TESLogger.log("Invalid JSON received", "WARNING")
                    break

                msg_type = message.get("type")
                payload = message.get("payload")
                signature = message.get("signature")

                if msg_type == Protocol.TYPE_SESSION:
                    try:
                        session_data = json.loads(payload)
                        encrypted_key = bytes.fromhex(session_data["encrypted_key"])
                        client_pem = session_data["client_public_key"]
                        
                        client_rsa = RSAManager(public_key_data=client_pem)
                        des_key = self.rsa_manager.decrypt(encrypted_key)
                        des_manager = DESManager(des_key)
                        
                        TESLogger.log("Secure Session Established")
                        conn.sendall(Protocol.create_message(Protocol.STATUS_OK, "Session Ready").encode('utf-8'))
                    except Exception as e:
                        TESLogger.log(f"Handshake Error: {e}", "ERROR")
                        break

                elif msg_type == "LOGIN":
                    if not des_manager:
                        continue
                    try:
                        encrypted_payload = bytes.fromhex(payload)
                        decrypted_json_bytes = des_manager.decrypt(encrypted_payload)
                        creds = json.loads(decrypted_json_bytes.decode('utf-8'))
                        
                        if self.auth.validate_login(creds['username'], creds['password']):
                            authenticated_user = creds['username']
                            TESLogger.log(f"User {authenticated_user} logged in.")
                            conn.sendall(Protocol.create_message(Protocol.STATUS_OK, "Login Successful").encode('utf-8'))
                        else:
                            TESLogger.log(f"Failed login attempt for {creds.get('username')}", "WARNING")
                            conn.sendall(Protocol.create_message(Protocol.STATUS_ERROR, "Invalid Credentials").encode('utf-8'))
                    except Exception as e:
                        TESLogger.log(f"Login Error: {e}", "ERROR")
                        continue

                elif msg_type == Protocol.TYPE_DATA:
                    if not des_manager or not authenticated_user:
                        conn.sendall(Protocol.create_message(Protocol.STATUS_ERROR, "Unauthorized").encode('utf-8'))
                        continue

                    try:
                        encrypted_data = bytes.fromhex(payload)
                        
                        # Verify Signature
                        sig_verified = False
                        if signature and client_rsa:
                            sig_bytes = bytes.fromhex(signature)
                            if client_rsa.verify(encrypted_data, sig_bytes):
                                sig_verified = True
                            else:
                                TESLogger.log("Signature Verification FAILED", "WARNING")
                        
                        # Decrypt
                        decrypted_bytes = des_manager.decrypt(encrypted_data)
                        data_obj = json.loads(decrypted_bytes.decode('utf-8'))
                        
                        plate = data_obj['plate']
                        speed = int(data_obj['speed'])
                        
                        # QUEUE THE MESSAGE
                        self._queue_message(plate, speed, sig_verified)
                        
                        conn.sendall(Protocol.create_message(Protocol.STATUS_OK, "Message Queued for Processing").encode('utf-8'))
                        
                    except Exception as e:
                         TESLogger.log(f"Data Processing Error: {e}", "ERROR")
                         conn.sendall(Protocol.create_message(Protocol.STATUS_ERROR, "Processing Error").encode('utf-8'))

        except Exception as e:
            TESLogger.log(f"Connection Error: {e}", "ERROR")
        finally:
            conn.close()

if __name__ == "__main__":
    server = TrafficOfficerServer()
    server.start()
