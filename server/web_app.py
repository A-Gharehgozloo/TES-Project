from flask import Flask, render_template, request, redirect, url_for, jsonify
import json
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server.auth import AuthManager
from server.storage import StorageManager
from core.logger import TESLogger

app = Flask(__name__)
app.secret_key = 'supersecretkey' # For session management in a real app

# Initialize Managers
auth = AuthManager()
storage = StorageManager()
TESLogger.setup()

PENDING_FILE = "data/pending.json"

def get_pending_messages():
    if not os.path.exists(PENDING_FILE):
        return []
    try:
        with open(PENDING_FILE, 'r') as f:
            return json.load(f)
    except:
        return []

def save_pending_messages(messages):
    with open(PENDING_FILE, 'w') as f:
        json.dump(messages, f, indent=4)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if auth.validate_login(username, password):
            # In a real app, set session here
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid Credentials")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    messages = get_pending_messages()
    # Filter only PENDING status
    pending = [m for m in messages if m.get('status') == 'PENDING']
    return render_template('dashboard.html', messages=pending)

@app.route('/process/<msg_id>', methods=['GET'])
def process_message(msg_id):
    messages = get_pending_messages()
    msg = next((m for m in messages if m['id'] == msg_id), None)
    if not msg:
        return "Message not found", 404
    
    # Calculate penalty preview
    speed = int(msg['speed'])
    points = 0
    if 50 <= speed < 70:
        points = 10
    elif 70 <= speed < 100:
        points = 20
    elif speed >= 100:
        points = 50
        
    return render_template('processing.html', msg=msg, points=points)

@app.route('/api/action', methods=['POST'])
def action():
    msg_id = request.form['id']
    action_type = request.form['action'] # 'approve' or 'reject'
    points = int(request.form.get('points', 0))
    
    messages = get_pending_messages()
    msg = next((m for m in messages if m['id'] == msg_id), None)
    
    if msg:
        if action_type == 'approve':
            storage.add_record(msg['plate'], points)
            msg['status'] = 'PROCESSED'
            TESLogger.log(f"Processed violation {msg_id}: Added {points} pts to {msg['plate']}")
        else:
            msg['status'] = 'REJECTED'
            TESLogger.log(f"Rejected violation {msg_id}")
            
        save_pending_messages(messages)
        
    return redirect(url_for('dashboard'))

@app.route('/records')
def records():
    all_records = storage.load_records() # Returns dict {plate: points}
    return render_template('records.html', records=all_records)

@app.route('/status')
def status():
    logs = TESLogger.get_recent_logs()
    # Mocking key status for UI
    key_status = {"active": True, "rotated": "2h ago"}
    return render_template('status.html', logs=logs, key_status=key_status)

if __name__ == '__main__':
    print("Starting Web Dashboard on port 5001...")
    app.run(host='0.0.0.0', port=5001, debug=True)
