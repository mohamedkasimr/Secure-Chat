import tkinter as tk
from client.client import SecureClient
from client.ui import SecureChatUI

if __name__ == "__main__":
    root = tk.Tk()
    # Connect to localhost by default
    client = SecureClient("localhost", 8443, "certs/server_cert.pem")
    try:
        client.connect()
    except Exception as e:
        print(f"Failed to connect to server: {e}")
        print("Please ensure the server is running and certs are generated.")
        
    app = SecureChatUI(root, client)
    root.protocol("WM_DELETE_WINDOW", lambda: (client.disconnect(), root.destroy()))
    root.mainloop()
