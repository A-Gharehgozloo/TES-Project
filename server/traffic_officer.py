import socket
import threading
import json
import time

from server.auth import AuthManager
from server.storage import StorageManager
from core.crypto_utils import RSAManager, DESManager
from core.protocol import Protocol

class TrafficOfficerServer:
    HOST = '127.0.0.1'
    PORT = 9999

    def __init__(self):
        self.auth = AuthManager()
        self.storage = StorageManager()
        # Generate Server RSA Keys (or load if persistent)
        self.private_key, self.public_key = RSAManager.generate_keys()
        self.rsa_manager = RSAManager(private_key_data=self.private_key, public_key_data=self.public_key)
        print(f"[SERVER] RSA Keys generated.")

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.HOST, self.PORT))
        server_socket.listen(5)
        print(f"[SERVER] Listening on {self.HOST}:{self.PORT}")

        try:
            while True:
                client_socket, addr = server_socket.accept()
                print(f"[SERVER] Connection from {addr}")
                client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_handler.start()
        except KeyboardInterrupt:
            print("[SERVER] Shutting down.")
            server_socket.close()

    def handle_client(self, conn):
        des_manager = None
        authenticated_user = None

        try:
            # 1. Send Public Key to Client
            handshake_msg = Protocol.create_message(Protocol.TYPE_HANDSHAKE, payload=self.public_key.decode('utf-8'))
            conn.sendall(handshake_msg.encode('utf-8'))

            while True:
                data = conn.recv(4096)
                if not data:
                    break

                # Attempt to parse as raw JSON first (for handshake/session)
                # If encrypted, we might need to handle differently, but here we assume all messages are JSON wrappers
                try:
                    message_str = data.decode('utf-8')
                    message = Protocol.parse_message(message_str)
                except json.JSONDecodeError:
                    print("[SERVER] Invalid JSON received")
                    break

                msg_type = message.get("type")
                payload = message.get("payload")
                signature = message.get("signature")

                print(f"[SERVER] Received {msg_type}")

                if msg_type == Protocol.TYPE_SESSION:
                    # Payload is JSON string: {"encrypted_key": "hex...", "client_public_key": "pem..."}
                    try:
                        session_data = json.loads(payload)
                        encrypted_key = bytes.fromhex(session_data["encrypted_key"])
                        client_pem = session_data["client_public_key"]
                        
                        # Set Client RSA for verification
                        # We need a new RSAManager for the client public key
                        # But RSAManager init imports keys. Let's create a helper or just use the class
                        # Note: We need to store this for the signature verification later
                        # For now, let's just store the keys?
                        # Wait, RSAManager constructor takes keys.
                        client_rsa = RSAManager(public_key_data=client_pem)
                        
                        des_key = self.rsa_manager.decrypt(encrypted_key)
                        des_manager = DESManager(des_key)
                        print(f"[SERVER] Secure Session Established. Key: {des_key.hex()}")
                        
                        conn.sendall(Protocol.create_message(Protocol.STATUS_OK, "Session Ready").encode('utf-8'))
                        
                    except Exception as e:
                        print(f"[SERVER] Handshake Error: {e}")
                        break

                elif msg_type == "LOGIN":
                    # Decrypt payload using DES
                    if not des_manager:
                        print("[SERVER] Login attempted without session key")
                        continue
                    
                    try:
                        # Payload is encrypted JSON: {"username": "...", "password": "..."}
                        encrypted_payload = bytes.fromhex(payload)
                        decrypted_json_bytes = des_manager.decrypt(encrypted_payload)
                        creds = json.loads(decrypted_json_bytes.decode('utf-8'))
                        
                        if self.auth.validate_login(creds['username'], creds['password']):
                            authenticated_user = creds['username']
                            print(f"[SERVER] User {authenticated_user} logged in.")
                            conn.sendall(Protocol.create_message(Protocol.STATUS_OK, "Login Successful").encode('utf-8'))
                        else:
                            print(f"[SERVER] Failed login for {creds.get('username')}")
                            conn.sendall(Protocol.create_message(Protocol.STATUS_ERROR, "Invalid Credentials").encode('utf-8'))
                    except Exception as e:
                        print(f"[SERVER] Login Decryption Error: {e}")
                        continue

                elif msg_type == Protocol.TYPE_DATA:
                    if not des_manager or not authenticated_user:
                        print("[SERVER] Unauthorized data attempt")
                        conn.sendall(Protocol.create_message(Protocol.STATUS_ERROR, "Unauthorized").encode('utf-8'))
                        continue

                    # Payload: Encrypted {plate, speed}
                    # Signature: Signed (Encrypted Payload)
                    
                    try:
                        encrypted_data = bytes.fromhex(payload)
                        
                        # 1. Verify Signature
                        if signature and client_rsa:
                            sig_bytes = bytes.fromhex(signature)
                            if not client_rsa.verify(encrypted_data, sig_bytes):
                                print("[SERVER] Signature Verification FAILED")
                                conn.sendall(Protocol.create_message(Protocol.STATUS_ERROR, "Invalid Signature").encode('utf-8'))
                                continue
                            print("[SERVER] Signature Verified.")
                        else:
                            print("[SERVER] Missing signature or client key")
                            conn.sendall(Protocol.create_message(Protocol.STATUS_ERROR, "Missing Signature").encode('utf-8'))
                            continue
                        
                        # 2. Decrypt
                        decrypted_bytes = des_manager.decrypt(encrypted_data)
                        data_obj = json.loads(decrypted_bytes.decode('utf-8'))
                        
                        plate = data_obj['plate']
                        speed = int(data_obj['speed'])
                        
                        print(f"[SERVER] Processing: Plate={plate}, Speed={speed}")
                        
                        # Calculate Penalty
                        points = 0
                        if 50 <= speed < 70:
                            points = 10
                        elif 70 <= speed < 100:
                            points = 20
                        elif speed >= 100:
                            points = 50
                        
                        if points > 0:
                            total_points = self.storage.add_record(plate, points)
                            print(f"[SERVER] Penalty: {points} points. Total for {plate}: {total_points}")
                            conn.sendall(Protocol.create_message(Protocol.STATUS_PENALTY, {"points": points, "total": total_points}).encode('utf-8'))
                        else:
                             print(f"[SERVER] No penalty.")
                             conn.sendall(Protocol.create_message(Protocol.STATUS_OK, "No Penalty").encode('utf-8'))
                    except Exception as e:
                         print(f"[SERVER] Data Processing Error: {e}")
                         conn.sendall(Protocol.create_message(Protocol.STATUS_ERROR, "Processing Error").encode('utf-8'))

        except Exception as e:
            print(f"[SERVER] Error: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    server = TrafficOfficerServer()
    server.start()
