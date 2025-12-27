# Traffic Enforcement System (TES) 🚓💨

A distributed, secure system for reporting and processing traffic violations. This project simulates a secure communication channel between Traffic Police units (Client) and a Traffic Officer (Server) using **RSA** and **DES** cryptography.

## 📌 Features

*   **Distributed Architecture**: Runs on separate machines (Client & Server) via TCP/IP.
*   **Encrypted Communication**: All traffic data is encrypted using **DES** (CBC Mode).
*   **Digital Signatures**: All reports are signed using **RSA-2048** to ensure integrity and non-repudiation.
*   **Secure Handshake**: Session keys are exchanged securely using RSA encryption.
*   **Web Interfaces**:
    *   **Police Client**: For submitting license plate and speed data.
    *   **Officer Dashboard**: For reviewing, approving, or rejecting violations.
*   **Encrypted Storage**: Driver records are stored in a DES-encrypted file (`drivers.enc`).

## 🛠️ Tech Stack

*   **Language**: Python 3.12+
*   **Framework**: Flask (Web UI)
*   **Cryptography**: PyCryptodome (RSA, DES, SHA-256)
*   **Networking**: Python `socket` (TCP)

## ⚙️ Installation

1.  **Clone the repository**:
    ```bash
    git clone <repository_url>
    cd Security-project
    ```

2.  **Create a Virtual Environment** (Recommended):
    ```bash
    python -m venv venv
    # Windows:
    .\venv\Scripts\activate
    # Mac/Linux:
    source venv/bin/activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## 🚀 Usage

The system consists of three parts that must be run simultaneously.

### 1. Start the Socket Server & Officer Dashboard (Machine A)
This handles the secure backend and the Officer's UI.

**Terminal 1 (Socket Server):**
```bash
python -m server.traffic_officer
```
*Listens on port 9999.*

**Terminal 2 (Officer Web App):**
```bash
python -m server.web_app
```
*Hosted at `http://localhost:5001`. Login: `admin` / `password`.*

### 2. Start the Police Client (Machine B)
This is the interface for the Traffic Police.

**Terminal 3 (Client Web App):**
```bash
python -m client.web_app
```
*Hosted at `http://localhost:5000`.*

### 3. Connect & Report
1.  Open **[http://localhost:5000](http://localhost:5000)** (Client).
2.  Enter the **Server IP** (use `127.0.0.1` if running locally, or the server's actual IP).
3.  Login with **`admin`** / **`password`**.
4.  Enter a License Plate (e.g., `34ABC123`) and Speed (e.g., `120`).
5.  Check the **Officer Dashboard** ([http://localhost:5001](http://localhost:5001)) to process the violation.

## 📂 Project Structure

```
Security-project/
├── client/                 # Police (Client) code
│   ├── police_client.py    # Socket client logic
│   └── web_app.py          # Flask app for Police
├── server/                 # Officer (Server) code
│   ├── traffic_officer.py  # Socket server logic
│   ├── web_app.py          # Flask app for Officer
│   └── storage.py          # Encrypted DB handler
├── core/                   # Shared utilities
│   ├── crypto_utils.py     # RSA/DES wrappers
│   └── protocol.py         # JSON message definitions
└── data/                   # Generated data (records, logs)
```

## 🔐 Security Details

*   **Handshake**: Server sends Public Key -> Client encrypts generated DES key with it -> Session established.
*   **Data Transmission**: `DES_Encrypt(JSON_Payload)` + `RSA_Sign(Encrypted_Payload)`.
*   **Storage**: Database `drivers.enc` is encrypted at rest using DES.
*   **Passwords**: SHA-256 hashed (simple implementation).

## ⚠️ Limitations
*   DES is used as per project requirements but is considered insecure for modern production systems (AES is preferred).
*   Keys are ephemeral and regenerated on server restart.

---
**Course Project**: Secure Systems Design (Fall 2025)
