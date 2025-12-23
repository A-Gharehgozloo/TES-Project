import threading
import time
import unittest
import os
import sys

# Add project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server.traffic_officer import TrafficOfficerServer
from client.police_client import TrafficPoliceClient
from core.protocol import Protocol

class TestIntegration(unittest.TestCase):
    def setUp(self):
        # Start Server in Thread
        self.server = TrafficOfficerServer()
        self.server_thread = threading.Thread(target=self.server.start)
        self.server_thread.daemon = True
        self.server_thread.start()
        time.sleep(1) # Wait for server to bind

    def test_flow(self):
        client = TrafficPoliceClient()
        
        # 1. Connect & Handshake
        connected = client.connect()
        self.assertTrue(connected, "Client failed to connect and establish session")
        
        # 2. Login (Invalid)
        success = client.login("admin", "wrongpassword")
        self.assertFalse(success, "Login should fail with wrong password")
        
        # 3. Login (Valid)
        success = client.login("admin", "password")
        self.assertTrue(success, "Login should succeed")
        
        # 4. Send Data (Speeding)
        # Mocking print to capture output if needed, but checking via return/state is hard as methods print.
        # We can trust the client methods return types or mock socket, but let's just run it.
        # We want to verify Server received it. We can check server storage.
        
        client.send_traffic_data("TEST-001", 120) # 50 points
        time.sleep(0.5)
        
        # Check Server Storage
        record = self.server.storage.get_record("TEST-001")
        self.assertEqual(record, 50, "Penalty points should be 50")
        
        client.send_traffic_data("TEST-001", 80) # +20 points
        time.sleep(0.5)
        
        record = self.server.storage.get_record("TEST-001")
        self.assertEqual(record, 70, "Penalty points should be 70")
        
        client.send_traffic_data("TEST-002", 40) # 0 points
        time.sleep(0.5)
        
        record = self.server.storage.get_record("TEST-002")
        self.assertEqual(record, 0, "Penalty points should be 0")

    def tearDown(self):
        # Server thread is daemon, will die on exit.
        # Clean up data files?
        pass

if __name__ == '__main__':
    unittest.main()
