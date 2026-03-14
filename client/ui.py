import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from client.client import SecureClient
import threading

class SecureChatUI:
    """
    Client UI using tkinter for regular users.
    Handles Login, Registration, and Chat interface.
    """
    def __init__(self, root: tk.Tk, client: SecureClient):
        self.root = root
        self.root.title("Secure Chat Client")
        self.root.geometry("600x500")
        
        self.client = client
        self.client.register_callback("REGISTER_ACK", self.on_register_ack)
        self.client.register_callback("LOGIN_ACK", self.on_login_ack)
        self.client.register_callback("ONLINE_USERS", self.on_online_users)
        self.client.register_callback("PUBLIC_KEY", self.on_public_key_received)
        self.client.register_callback("RECEIVE_MESSAGE", self.on_message_received)
        self.client.register_callback("ERROR", self.on_error)
        self.client.register_callback("DISCONNECT", self.on_disconnect)
        
        self.public_keys_cache = {}
        self.pending_messages = {} # username -> list of msgs waiting for public key
        
        self.create_login_ui()

    # --- UI Layouts ---

    def create_login_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
            
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True)
        
        ttk.Label(frame, text="Secure Chat Login", font=("Helvetica", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=10)
        
        ttk.Label(frame, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.username_var).grid(row=1, column=1, pady=5)
        
        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.password_var, show="*").grid(row=2, column=1, pady=5)
        
        ttk.Button(frame, text="Login", command=self.do_login).grid(row=3, column=0, pady=15)
        ttk.Button(frame, text="Register", command=self.do_register).grid(row=3, column=1, pady=15)

    def create_chat_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
            
        self.root.geometry("900x650")
        
        # Style improvements
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#f0f2f5')
        style.configure('TLabel', background='#f0f2f5', font=('Segoe UI', 10))
        style.configure('Header.TLabel', font=('Segoe UI', 12, 'bold'), foreground='#1c1e21')
        style.configure('TButton', font=('Segoe UI', 10), padding=5)
        
        self.root.configure(bg='#f0f2f5')
        
        # Main layout
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left Panel (Users)
        left_frame = ttk.Frame(paned, width=220)
        paned.add(left_frame, weight=1)
        
        header_frame = ttk.Frame(left_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(header_frame, text=f"Logged in as: {self.client.username}", style='Header.TLabel').pack(side=tk.LEFT)
        
        ttk.Label(left_frame, text="Online Users").pack(anchor=tk.W, pady=(10, 5))
        
        self.users_listbox = tk.Listbox(left_frame, font=('Segoe UI', 10), selectbackground='#0084ff', selectforeground='white', relief=tk.FLAT, borderwidth=1)
        self.users_listbox.pack(fill=tk.BOTH, expand=True)
        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_select)
        
        ttk.Button(left_frame, text="Refresh Users", command=self.client.get_online_users).pack(fill=tk.X, pady=10)
        
        # Right Panel (Chat Tabs)
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=3)
        
        self.chat_notebook = ttk.Notebook(right_frame)
        self.chat_notebook.pack(fill=tk.BOTH, expand=True)
        
        self.chat_tabs = {} # username -> dict of widgets {frame, text_widget, msg_var}
        
        # Create Global Chat Tab
        self.create_chat_tab("Global")
        
        # Initial fetch
        self.client.get_online_users()

    # --- Actions ---

    def do_login(self):
        u, p = self.username_var.get(), self.password_var.get()
        if not u or not p:
            messagebox.showwarning("Error", "Enter username and password.", parent=self.root)
            return
        self.client.login(u, p)

    def do_register(self):
        u, p = self.username_var.get(), self.password_var.get()
        if not u or not p:
            messagebox.showwarning("Error", "Enter username and password.", parent=self.root)
            return
        self.client.register(u, p)

    def create_chat_tab(self, name: str):
        if name in self.chat_tabs:
            self.chat_notebook.select(self.chat_tabs[name]['frame'])
            return
            
        tab_frame = ttk.Frame(self.chat_notebook, padding=10)
        self.chat_notebook.add(tab_frame, text=name)
        
        # Message Display
        chat_display = tk.Text(tab_frame, state=tk.DISABLED, wrap=tk.WORD, font=('Segoe UI', 10), 
                             bg='white', relief=tk.FLAT, padx=10, pady=10)
        chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Input Area
        input_frame = ttk.Frame(tab_frame)
        input_frame.pack(fill=tk.X)
        
        msg_var = tk.StringVar()
        msg_entry = ttk.Entry(input_frame, textvariable=msg_var, font=('Segoe UI', 11))
        msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        msg_entry.bind("<Return>", lambda e, target=name: self.send_message(target))
        
        send_btn = ttk.Button(input_frame, text="Send", command=lambda target=name: self.send_message(target))
        send_btn.pack(side=tk.RIGHT)
        
        self.chat_tabs[name] = {
            'frame': tab_frame,
            'display': chat_display,
            'msg_var': msg_var
        }
        self.chat_notebook.select(tab_frame)

    def on_user_select(self, event):
        selection = event.widget.curselection()
        if selection:
            target = event.widget.get(selection[0])
            self.create_chat_tab(target)

    def send_message(self, target: str):
        msg_var = self.chat_tabs[target]['msg_var']
        msg = msg_var.get()
        if not msg.strip():
            return
            
        msg_var.set("")
        
        if target == "Global":
            self.append_chat(target, "You", msg, is_self=True)
            # Actually send it to the server unencrypted
            # We utilize the encrypted_box as just a plain dict for the server to forward
            fake_box = {"text": msg, "is_global": True}
            self.client._send("SEND_MESSAGE", {
                "token": self.client.session_token,
                "recipient": "Global",
                "encrypted_box": fake_box
            })
            return
            
        self.append_chat(target, "You", msg, is_self=True)
        
        # If we have the public key, encrypt and send
        if target in self.public_keys_cache:
            try:
                self.client.send_encrypted_message(target, self.public_keys_cache[target], msg)
            except Exception as e:
                self.append_chat(target, "System", f"Failed to encrypt message: {e}")
        else:
            # Request key and queue message
            if target not in self.pending_messages:
                self.pending_messages[target] = []
            self.pending_messages[target].append(msg)
            self.client.request_public_key(target)

    def append_chat(self, tab_name: str, prefix: str, message: str, is_self: bool = False):
        if tab_name not in self.chat_tabs:
            self.create_chat_tab(tab_name)
            
        display = self.chat_tabs[tab_name]['display']
        display.config(state=tk.NORMAL)
        
        # Basic aesthetic differentiation
        tag = "self" if is_self else ("system" if prefix == "System" else "other")
        display.tag_config("self", foreground="#0084ff", font=('Segoe UI', 10, 'bold'))
        display.tag_config("other", foreground="#4b4f56", font=('Segoe UI', 10, 'bold'))
        display.tag_config("system", foreground="#e0245e", font=('Segoe UI', 9, 'italic'))
        display.tag_config("msg", foreground="#1c1e21")
        
        display.insert(tk.END, f"[{prefix}] ", tag)
        display.insert(tk.END, f"{message}\n", "msg")
        display.see(tk.END)
        display.config(state=tk.DISABLED)

    # --- Callbacks ---

    def on_register_ack(self, payload):
        if payload.get("success"):
            messagebox.showinfo("Success", "Registered! You can now login.")
        else:
            messagebox.showerror("Error", "Registration failed. Username might exist.")

    def on_login_ack(self, payload):
        if payload.get("success"):
            self.client.session_token = payload.get("token")
            self.root.after(0, self.create_chat_ui)
        else:
            messagebox.showerror("Error", payload.get("message", "Login failed."))

    def on_online_users(self, payload):
        users = payload.get("users", [])
        self.users_listbox.delete(0, tk.END)
        for u in users:
            self.users_listbox.insert(tk.END, u)

    def on_public_key_received(self, payload):
        target = payload.get("username")
        
        # When serialized to JSON and stored in SQLite, proper newlines might be escaped
        # We need to make sure the PEM format is strictly honored (i.e., real \n bytes)
        raw_key = payload.get("public_key", "")
        clean_key = raw_key.replace('\\n', '\n')
        key = clean_key.encode('utf-8')
        
        self.public_keys_cache[target] = key
        
        # Send pending messages
        if target in self.pending_messages:
            for msg in self.pending_messages[target]:
                try:
                    self.client.send_encrypted_message(target, key, msg)
                except Exception as e:
                    self.append_chat(target, "System", f"Failed to encrypt pending message: {e}")
            del self.pending_messages[target]

    def on_message_received(self, payload):
        sender = payload.get("sender")
        recipient_tab = payload.get("recipient", sender)
        encrypted_box = payload.get("encrypted_box")
        
        if recipient_tab == "Global":
            plaintext = encrypted_box.get("text", "")
            self.append_chat("Global", sender, plaintext)
            return
            
        try:
            plaintext = self.client.decrypt_message(encrypted_box)
            self.append_chat(sender, sender, plaintext)
        except Exception as e:
            self.append_chat(sender, "System", f"Failed to decrypt message from {sender} (Keys might be mismatched). Error: {e}")

    def on_error(self, payload):
        messagebox.showerror("Server Error", payload.get("message"), parent=self.root)

    def on_disconnect(self):
        messagebox.showwarning("Disconnected", "Lost connection to server.", parent=self.root)
        self.root.after(0, self.root.quit)
