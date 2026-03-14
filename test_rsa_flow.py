import json
from common.crypto_utils import CryptoUtils

def test_flow():
    # 1. Generate on Client A
    priv_a_bytes, pub_a_bytes = CryptoUtils.generate_rsa_keypair()
    print(f"Original Pub A Bytes: {type(pub_a_bytes)}")
    
    # 2. Client A stringifies it to send in REGISTER
    pub_a_str = pub_a_bytes.decode('utf-8')
    payload_to_send = {"public_key": pub_a_str}
    json_str_sent = json.dumps(payload_to_send)
    
    # 3. Server receives JSON and puts in DB exactly as string
    received_json = json.loads(json_str_sent)
    db_stored_str = received_json["public_key"]
    
    # 4. Server sends to Client B in PUBLIC_KEY
    server_payload = {"public_key": db_stored_str}
    server_json_sent = json.dumps(server_payload)
    
    # 5. Client B receives JSON
    client_b_received = json.loads(server_json_sent)
    
    # 6. Client B encodes to bytes to use in encryption
    # Let's use the explicit string replace fix we added
    raw_key = client_b_received.get("public_key", "")
    clean_key = raw_key.replace('\\n', '\n') # Our fix
    pub_a_received_bytes = clean_key.encode('utf-8')
    
    print(f"Match: {pub_a_bytes == pub_a_received_bytes}")
    print(f"Can Import? ", end="")
    try:
        from Cryptodome.PublicKey import RSA
        RSA.import_key(pub_a_received_bytes)
        print("YES")
    except Exception as e:
        print(f"NO: {e}")
        print("Raw Key repr:", repr(raw_key))
        print("Clean Key repr:", repr(clean_key))

test_flow()
