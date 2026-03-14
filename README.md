# Secure Chat Application

A highly secure, enterprise-grade Python chat application utilizing `tkinter` for UI and implementing strict security controls modeled on the 7-Layer OSI methodology.

## Security Architecture (7-Layers)

This application was designed from the ground up to prevent data leaks, SQL injections, network eavesdropping, and credential theft.

1. **Physical Layer**: `config.py` uses AES-GCM (PyCryptodome) with PBKDF2 key derivation (from a master unlock password) to encrypt the system configuration and credential salts at rest. This protects against physical data breaches.
2. **Data Link Layer**: `server/mac_filter.py` provides MAC address validation. The server maintains a strict whitelist of allowed physical device addresses. 
3. **Network Layer**: IP Addresses are completely abstracted. `server/sessions.py` acts as an internal DNS mapping human-readable `usernames` strictly to socket connections. IPs are completely stripped out to prevent tracking and network topological mapping, even obfuscated in audit logs.
4. **Transport Layer**: Python's `ssl` module wraps all TCP sockets in mutually enforced TLS (v1.2+) with strict cipher requirements. This secures data in transit and verifies server identity utilizing x509 certificates.
5. **Session Layer**: `server/auth.py` generates short-lived, cryptographically secure hex tokens used to authenticate stateful transactions after the initial handshake, preventing token replay and timing out idle sessions.
6. **Presentation Layer**: `common/protocol.py` handles the serialization, framing, and strict length-prefixing of JSON payloads. Additionally, **End-to-End Encryption (E2E)** utilizing asymmetric RSA key exchange to share symmetric AES-GCM keys ensures the server itself cannot read the chat message bodies.
7. **Application Layer**: Authentication operates entirely on securely salted bcrypt hashing. `server/db.py` uses strict parameterized SQLite queries to render SQL injection impossible. An Admin Interface allows for auditing of security events and real-time monitoring.

## Features

- **E2E Encrypted Messaging**: Only the sender and receiver can decrypt the chat messages. 
- **User Allowlisting**: Built-in MAC address filtering constraints.
- **Admin Dashboard**: Real-time log monitoring and active user counts via `run_admin.py`.
- **Graphical Client**: Lightweight tkinter chat UI preventing protocol tampering.
- **Brute-force Mitigations**: Configurable account lockouts upon multiple failed login attempts.

## Setup Instructions

### 1. Requirements
Ensure Python 3.8+ is installed.
```bash
pip install -r requirements.txt
```

### 2. Prepare the Server
Run the server generation script. You will be prompted to create a Master Password which will encrypt your `server_config.enc` local storage.

```bash
python run_server.py
```
> Note: If no certificates are found, the script will automatically generate self-signed testing certificates in the `certs/` directory using the `cryptography` library.

### 3. Launching Clients

To launch the regular user Chat UI:
```bash
python run_client.py
```
*Click 'Register' first to create an identity, then login and chat securely!*

To launch the system monitoring Admin Dashboard:
```bash
python run_admin.py
```
*A default user `admin / admin` is created automatically on the first server boot.* 

## Development Standards
- Developed entirely following PEP 8 guidelines.
- Deep separation of concerns separating UI, Crypto, Database, and Protocol components.
- Complete type hinting and documentation strings provided on all classes and functions.
