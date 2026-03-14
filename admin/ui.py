import tkinter as tk
from tkinter import ttk, messagebox
from admin.admin_client import AdminClient

class AdminUI:
    """
    Admin Dashboard UI using tkinter.
    """
    def __init__(self, root: tk.Tk, client: AdminClient):
        self.root = root
        self.root.title("Secure Chat Admin Dashboard")
        self.root.geometry("800x600")
        
        self.client = client
        self.client.register_callback("LOGIN_ACK", self.on_login_ack)
        self.client.register_callback("SYSTEM_LOGS", self.on_logs)
        self.client.register_callback("ALL_USERS", self.on_users)
        self.client.register_callback("ERROR", self.on_error)
        
        self.create_login_ui()

    def create_login_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
            
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True)
        
        ttk.Label(frame, text="Admin Login", font=("Helvetica", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=10)
        
        ttk.Label(frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.username_var).grid(row=1, column=1, pady=5)
        
        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.password_var, show="*").grid(row=2, column=1, pady=5)
        
        ttk.Button(frame, text="Login", command=self.do_login).grid(row=3, column=0, columnspan=2, pady=15)

    def create_dashboard_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
            
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.logs_tab = ttk.Frame(notebook)
        self.users_tab = ttk.Frame(notebook)
        
        notebook.add(self.logs_tab, text="Security Logs")
        notebook.add(self.users_tab, text="Registered Users")
        
        # Logs Tab
        self.logs_tree = ttk.Treeview(self.logs_tab, columns=("Time", "Event", "User", "Details"), show="headings")
        self.logs_tree.heading("Time", text="Timestamp")
        self.logs_tree.heading("Event", text="Event Type")
        self.logs_tree.heading("User", text="Username")
        self.logs_tree.heading("Details", text="Details")
        self.logs_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Button(self.logs_tab, text="Refresh Logs", command=self.client.get_logs).pack(pady=5)
        
        # Users Tab
        self.users_listbox = tk.Listbox(self.users_tab)
        self.users_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Button(self.users_tab, text="Refresh Users", command=self.client.get_all_users).pack(pady=5)
        
        # Initial Fetch
        self.client.get_logs()
        self.client.get_all_users()

    def do_login(self):
        u, p = self.username_var.get(), self.password_var.get()
        if not u or not p:
            messagebox.showwarning("Error", "Enter username and password.")
            return
        self.client.login(u, p)

    def on_login_ack(self, payload):
        if payload.get("success"):
            self.client.session_token = payload.get("token")
            self.root.after(0, self.create_dashboard_ui)
        else:
            messagebox.showerror("Error", "Admin login failed.", parent=self.root)

    def on_logs(self, payload):
        logs = payload.get("logs", [])
        self.logs_tree.delete(*self.logs_tree.get_children())
        for log in logs:
            self.logs_tree.insert("", "end", values=log)

    def on_users(self, payload):
        users = payload.get("users", [])
        self.users_listbox.delete(0, tk.END)
        for u in users:
            self.users_listbox.insert(tk.END, u)

    def on_error(self, payload):
        messagebox.showerror("Error", payload.get("message"), parent=self.root)
