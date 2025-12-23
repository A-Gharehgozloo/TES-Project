import threading
import time
import unittest
import os
import sys
import json
import requests

# Add project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server.traffic_officer import TrafficOfficerServer
from client.police_client import TrafficPoliceClient
from server.web_app import app as officer_app
from client.web_app import app as police_app

class TestWebIntegration(unittest.TestCase):
    def setUp(self):
        try:
            # Override Port to avoid conflict with running background process
            TrafficOfficerServer.PORT = 9998
            TrafficPoliceClient.PORT = 9998
            
            # 1. Start Socket Server
            self.server = TrafficOfficerServer()
            self.server_thread = threading.Thread(target=self.server.start)
            self.server_thread.daemon = True
            self.server_thread.start()
            time.sleep(2) # Increased wait time

            # 2. Setup Flask Test Clients
            self.officer_client = officer_app.test_client()
            self.police_client = police_app.test_client()

            # Clear data
            if os.path.exists("data/pending.json"):
                os.remove("data/pending.json")
            if os.path.exists("data/drivers.enc"):
                os.remove("data/drivers.enc")
        except Exception as e:
            print(f"SETUP FAILED: {e}")
            raise e

    def test_full_workflow(self):
        # A. POLICE CLIENT: Login & Send Data
        # 1. Login
        print(">>> 1. Police Login")
        response = self.police_client.post('/login', data={'username': 'admin', 'password': 'password'}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Traffic Data Entry', response.data)

        # 2. Send Data
        print(">>> 2. Send Traffic Data")
        response = self.police_client.post('/observation', data={'plate': 'WEB-TEST-01', 'speed': '120'}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Sent Violation', response.data)

        # Wait for Socket Server to process and write to pending.json
        time.sleep(2)

        # B. OFFICER SERVER: View & Process
        # 3. Check Dashboard (Pending Messages)
        print(">>> 3. Officer Check Dashboard")
        response = self.officer_client.get('/dashboard')
        self.assertIn(b'WEB-TEST-01', response.data)
        
        # Get ID from pending.json directly to simulate knowing which button to click
        with open("data/pending.json", 'r') as f:
            pending = json.load(f)
        msg_id = pending[0]['id']

        # 4. View Processing Page
        print(f">>> 4. View Details for {msg_id}")
        response = self.officer_client.get(f'/process/{msg_id}')
        self.assertIn(b'50 Points', response.data) # 120km/h = 50 pts
        self.assertIn(b'Verified', response.data)

        # 5. Apply Penalty
        print(">>> 5. Apply Penalty")
        response = self.officer_client.post('/api/action', data={'id': msg_id, 'action': 'approve', 'points': '50'}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)

        # 6. Check Records
        print(">>> 6. Check Encrypted Database")
        response = self.officer_client.get('/records')
        self.assertIn(b'WEB-TEST-01', response.data)
        self.assertIn(b'50', response.data)
        self.assertIn(b'DES-Encrypted', response.data)

if __name__ == '__main__':
    unittest.main()
