import socket
import json
import time
from core.crypto_utils import RSAManager, DESManager
from core.protocol import Protocol

class TrafficPoliceClient:
    HOST = '127.0.0.1'
    PORT = 9999

    def __init__(self):
        # Generate Client RSA Keys
        self.private_key, self.public_key = RSAManager.generate_keys()
        self.rsa_manager = RSAManager(private_key_data=self.private_key, public_key_data=self.public_key)
        self.server_rsa = None
        self.des_manager = None
        self.socket = None
        self.session_active = False

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.HOST, self.PORT))
        print(f"[CLIENT] Connected to {self.HOST}:{self.PORT}")

        # 1. Receive Handshake (Server Public Key)
        data = self.socket.recv(4096)
        msg = Protocol.parse_message(data.decode('utf-8'))
        if msg['type'] == Protocol.TYPE_HANDSHAKE:
            server_pub_key_pem = msg['payload']
            self.server_rsa = RSAManager(public_key_data=server_pub_key_pem)
            print("[CLIENT] Received Server Public Key")
            
            # 2. Establish Session
            # Generate DES Key
            des_key = DESManager.generate_key()
            self.des_manager = DESManager(des_key)
            
            # Encrypt DES key with Server Public Key
            encrypted_key = self.server_rsa.encrypt(des_key)
            
            # Send Session Key AND Client Public Key (so server can verify signatures)
            # Payload: JSON { encrypted_key: hex, client_public_key: pem }
            session_payload = {
                "encrypted_key": encrypted_key.hex(),
                "client_public_key": self.public_key.decode('utf-8')
            }
            
            # Note: Server expects just hex string of key currently? 
            # I need to update the server to handle this dict payload.
            # But wait, sending complex JSON in payload might be tricky if Server expects raw hex.
            # I will simple send the payload as a JSON string.
            
            self.send_message(Protocol.TYPE_SESSION, json.dumps(session_payload))
            
            # Wait for Session OK
            response = self.receive_response()
            if response['type'] == Protocol.STATUS_OK:
                print("[CLIENT] Session Established")
                self.session_active = True
                return True
        return False

    def login(self, username, password):
        if not self.session_active:
            print("[CLIENT] No active session.")
            return False

        creds = {"username": username, "password": password}
        creds_json = json.dumps(creds)
        
        # Encrypt with DES
        encrypted_creds = self.des_manager.encrypt(creds_json.encode('utf-8'))
        
        self.send_message("LOGIN", encrypted_creds.hex())
        
        response = self.receive_response()
        if response['type'] == Protocol.STATUS_OK:
            print("[CLIENT] Login Successful")
            return True
        else:
            print(f"[CLIENT] Login Failed: {response.get('payload')}")
            return False

    def send_traffic_data(self, plate, speed):
        if not self.session_active:
            print("[CLIENT] No active session.")
            return

        data = {"plate": plate, "speed": speed}
        data_json = json.dumps(data)
        
        # 1. Encrypt with DES
        encrypted_data = self.des_manager.encrypt(data_json.encode('utf-8'))
        
        # 2. Sign the ENCRYPTED data (Encryt-then-Sign is better? or Sign-then-Encrypt? PRD says Digitally signed. Usually Sign hash of plaintext or ciphertext. 
        # PRD: "Traffic Police sends messages containing... Messages must be: DES-encrypted, Digitally signed"
        # Let's sign the ciphertext to prevent tampering without decryption.
        signature = self.rsa_manager.sign(encrypted_data)
        
        self.send_message(Protocol.TYPE_DATA, encrypted_data.hex(), signature=signature.hex())
        
        response = self.receive_response()
        print(f"[CLIENT] Server Response: {response}")

    def send_message(self, msg_type, payload, signature=None):
        msg = Protocol.create_message(msg_type, payload, signature)
        self.socket.sendall(msg.encode('utf-8'))

    def receive_response(self):
        data = self.socket.recv(4096)
        return Protocol.parse_message(data.decode('utf-8'))

    def run_interactive(self):
        if not self.connect():
            return
        
        username = input("Username: ")
        password = input("Password: ")
        
        if not self.login(username, password):
            return
            
        while True:
            print("\n--- Enter Traffic Data ---")
            plate = input("Plate Number (or 'q' to quit): ")
            if plate.lower() == 'q':
                break
            try:
                speed = int(input("Speed: "))
                self.send_traffic_data(plate, speed)
            except ValueError:
                print("Invalid speed.")

if __name__ == "__main__":
    client = TrafficPoliceClient()
    client.run_interactive()
