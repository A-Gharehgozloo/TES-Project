import json
import os
from core.crypto_utils import DESManager

class StorageManager:
    DB_FILE = "data/drivers.enc"
    # Static key for storage encryption (PRD requirement: DES encrypted file)
    # in a real system, this should be protected or derived from a master key.
    # For this project, we'll use a hardcoded key.
    STORAGE_KEY = b'STOREKEY' 

    def __init__(self):
        os.makedirs(os.path.dirname(self.DB_FILE), exist_ok=True)
        self.des = DESManager(self.STORAGE_KEY)

    def load_records(self):
        if not os.path.exists(self.DB_FILE):
            return {}
        
        try:
            with open(self.DB_FILE, 'rb') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                return {}

            json_bytes = self.des.decrypt(encrypted_data)
            return json.loads(json_bytes.decode('utf-8'))
        except Exception as e:
            print(f"Error loading records: {e}")
            return {}

    def save_records(self, records):
        json_bytes = json.dumps(records).encode('utf-8')
        encrypted_data = self.des.encrypt(json_bytes)
        
        with open(self.DB_FILE, 'wb') as f:
            f.write(encrypted_data)

    def add_record(self, plate, points):
        records = self.load_records()
        if plate in records:
            records[plate] += points
        else:
            records[plate] = points
        self.save_records(records)
        return records[plate]

    def get_record(self, plate):
        records = self.load_records()
        return records.get(plate, 0)
