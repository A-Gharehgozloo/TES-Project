import hashlib
import json
import os

class AuthManager:
    USERS_FILE = "data/users.json"

    def __init__(self):
        # Ensure data directory exists
        os.makedirs(os.path.dirname(self.USERS_FILE), exist_ok=True)
        if not os.path.exists(self.USERS_FILE):
             # Default user: admin/password
             self._save_users({"admin": self._hash_password("password")})

        self.users = self._load_users()

    def _hash_password(self, password):
        # PRD requires generic hash/salt. Using SHA256 for simplicity.
        return hashlib.sha256(password.encode()).hexdigest()

    def _load_users(self):
        with open(self.USERS_FILE, 'r') as f:
            return json.load(f)

    def _save_users(self, users):
        with open(self.USERS_FILE, 'w') as f:
            json.dump(users, f)

    def validate_login(self, username, password):
        if username not in self.users:
            return False
        return self.users[username] == self._hash_password(password)

    def add_user(self, username, password):
        self.users[username] = self._hash_password(password)
        self._save_users(self.users)
