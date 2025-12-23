from flask import Flask, render_template, request, redirect, url_for, flash
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from client.police_client import TrafficPoliceClient
from core.protocol import Protocol

app = Flask(__name__)
app.secret_key = 'police_secret'

# Single Global Client Instance (for simplicity in demo, normally per-session)
# Note: In a real web app, we'd handle connection persistence or reconnection per request.
# For this project, we'll try to keep one persistent connection or reconnect on demand.
client_instance = TrafficPoliceClient()
is_connected = False

def ensure_connection():
    global is_connected
    if not is_connected:
        print("Connecting to Socket Server...")
        if client_instance.connect():
            is_connected = True
            return True
        return False
    return True

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not ensure_connection():
            flash("Could not connect to Server.")
            return render_template('login.html', error="Server Unavailable")

        # Perform Secure Login via Socket
        if client_instance.login(username, password):
            return redirect(url_for('observation'))
        else:
            return render_template('login.html', error="Invalid Credentials")
            
    return render_template('login.html')

@app.route('/observation', methods=['GET', 'POST'])
def observation():
    global is_connected
    status = {
        "session": "Active",
        "encryption": "DES",
        "signature": "RSA",
        "last_msg": "None"
    }
    
    if request.method == 'POST':
        plate = request.form['plate']
        try:
            speed = int(request.form['speed'])
            
            if not ensure_connection():
                flash("Connection lost.")
                return redirect(url_for('login'))
                
            # Send Data
            client_instance.send_traffic_data(plate, speed)
            flash(f"Sent Violation: {plate} at {speed} km/h")
            status['last_msg'] = f"Sent: {plate}"
            
        except ValueError:
            flash("Invalid Speed")

    return render_template('observation.html', status=status)

if __name__ == '__main__':
    print("Starting Police Client Web App on port 5000...")
    app.run(port=5000, debug=True)
