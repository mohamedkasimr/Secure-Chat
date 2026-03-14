import tkinter as tk
from admin.admin_client import AdminClient
from admin.ui import AdminUI

if __name__ == "__main__":
    root = tk.Tk()
    # Admin client connecting to localhost
    client = AdminClient("localhost", 8443, "certs/server_cert.pem")
    try:
        client.connect()
    except Exception as e:
        print(f"Failed to connect to server: {e}")
        
    app = AdminUI(root, client)
    root.protocol("WM_DELETE_WINDOW", lambda: (client.disconnect(), root.destroy()))
    root.mainloop()
