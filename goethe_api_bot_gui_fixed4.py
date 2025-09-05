import asyncio
import csv
import json
import logging
import random
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
import os
from pathlib import Path
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Import the main bot
try:
    from goethe_ultimate_api_bot import GoetheBookingManager, GoetheAPIBot, RateLimitException, PersistentServerException
    BOT_AVAILABLE = True
except ImportError:
    BOT_AVAILABLE = False

# New Class for Real-Time Logging
class TkinterLogHandler(logging.Handler):
    """A custom logging handler that redirects logs to appropriate Tkinter Text widgets based on message prefixes."""
    def __init__(self, main_text_widget, root, log_widgets_dict=None):
        super().__init__()
        self.main_text_widget = main_text_widget
        self.root = root
        self.log_widgets_dict = log_widgets_dict or {}

    def emit(self, record):
        msg = self.format(record)
        
        def append_message():
            # Parse message to determine target widget
            target_widget = self.main_text_widget  # Default to main log
            
            # Check if message has a user prefix like "[1] user@email.com" or "[2] another@email.com"
            if msg.strip().startswith('[') and ']' in msg:
                try:
                    prefix_end = msg.find(']')
                    if prefix_end > 0:
                        prefix = msg[1:prefix_end].strip()
                        # Look for matching tab in log_widgets_dict
                        for tab_key, widget in self.log_widgets_dict.items():
                            if prefix in tab_key or tab_key in prefix:
                                target_widget = widget
                                break
                except:
                    pass  # If parsing fails, use main widget
            
            # Update the appropriate widget
            target_widget.configure(state='normal')
            target_widget.insert(tk.END, msg + '\n')
            target_widget.configure(state='disabled')
            target_widget.see(tk.END)  # Auto-scroll
        
        # Schedule the GUI update to run in the main thread
        self.root.after(0, append_message)

class GoetheAPIBotGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🤖 Goethe API Bot - High-Speed Booking")
        self.root.geometry("1200x900")
        
        # Variables
        self.exam_url_var = tk.StringVar()
        # --- ADD THESE TWO LINES ---
        self.single_exam_url_var = tk.StringVar()
        self.multi_exam_url_var = tk.StringVar()
        # --- END OF ADDITION ---
        self.interval_var = tk.StringVar(value="0.1")
        
        # Configuration variables
        self.proxies_text = tk.StringVar()
        self.saved_config = {
            'exam_url': '',
            'proxies': []
        }
        self.use_proxies_var = tk.BooleanVar(value=True) # ADD THIS LINE
        
        # Single user variables
        self.email_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.recaptcha_action_var = tk.StringVar() # ADD THIS LINE
        self.reading_var = tk.BooleanVar(value=True)
        self.listening_var = tk.BooleanVar(value=True)
        self.writing_var = tk.BooleanVar(value=False)
        self.speaking_var = tk.BooleanVar(value=False)
        
        # Multi-user variables
        self.csv_file_var = tk.StringVar()
        self.csv_users_data = []  # Store loaded CSV data
        
        # Status and logging
        self.is_running = False
        self.auto_scroll = tk.BooleanVar(value=True)
        self.log_widgets = {}
        
        self.create_widgets()
        # Load saved configuration on startup
        self.load_configuration_on_startup()
        
        # --- FIX for REAL-TIME LOGGING ---
        self.log_text.configure(state='disabled')
        
        log_handler = TkinterLogHandler(self.log_text, self.root, self.log_widgets)
        # Use a more detailed format for the GUI logger
        log_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s', datefmt='%H:%M:%S'))
        
        # Add the handler to the root logger to capture everything
        logging.getLogger().addHandler(log_handler)
        logging.getLogger().setLevel(logging.INFO)
        
        # Replace the old log_message method with a direct call to the logger
        self.log_message = logging.info
        
        # Log a startup message
        self.log_message("GUI Initialized. Real-time logging is active.")
        # --- END OF FIX ---
    
    def create_widgets(self):
        # Create notebook for 4-pane structure
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Pane 1: Configuration
        config_frame = ttk.Frame(notebook)
        notebook.add(config_frame, text="⚙️ Config")
        self.create_config_pane(config_frame)
        
        # Pane 2: Single User
        single_frame = ttk.Frame(notebook)
        notebook.add(single_frame, text="👤 Single")
        self.create_single_pane(single_frame)
        
        # Pane 3: Multiple Users
        multi_frame = ttk.Frame(notebook)
        notebook.add(multi_frame, text="👥 Multiple")
        self.create_multiple_pane(multi_frame)
        
        # Pane 4: Logs
        logs_frame = ttk.Frame(notebook)
        notebook.add(logs_frame, text="📊 Logs")
        self.create_logs_pane(logs_frame)
    
    def create_config_pane(self, parent):
        """Create configuration pane for pasting a list of proxies."""
        main_frame = ttk.Frame(parent, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        title_label = ttk.Label(main_frame, text="⚙️ Proxy Configuration", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))

        cred_frame = ttk.LabelFrame(main_frame, text="⭐ Proxy List", padding="15")
        cred_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        info_label = ttk.Label(cred_frame,
                               text="Paste your list of proxies here, one per line.\nFormat: host:port:username:password",
                               justify=tk.LEFT)
        info_label.pack(anchor=tk.W, pady=(0, 10))

        # Use ScrolledText for better handling of long lists
        self.proxy_list_text = scrolledtext.ScrolledText(cred_frame, height=15, width=100, wrap=tk.WORD)
        self.proxy_list_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # ADD THIS ENTIRE BLOCK
        # Checkbox to enable/disable proxies
        proxy_toggle_frame = ttk.Frame(cred_frame)
        proxy_toggle_frame.pack(fill=tk.X, pady=(10, 0))
        
        proxy_checkbox = ttk.Checkbutton(proxy_toggle_frame, 
                                         text="✅ Use Proxies (Recommended)", 
                                         variable=self.use_proxies_var)
        proxy_checkbox.pack(side=tk.LEFT)
        # END OF BLOCK

        
        # Save button (simplified)
        save_button = ttk.Button(main_frame, text="💾 Save Configuration",
                               command=self.save_configuration)
        save_button.pack(pady=20)
        
        self.config_status_var = tk.StringVar(value="⚠️ Configuration not saved")
        status_label = ttk.Label(main_frame, textvariable=self.config_status_var, 
                               foreground="orange")
        status_label.pack(pady=(10, 0))
    
    def create_single_pane(self, parent):
        """Create single user pane with email, password, modules"""
        main_frame = ttk.Frame(parent, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="👤 Single User Booking", font=("Arial", 18, "bold"))
        title_label.pack(pady=(0, 30))
        
        # Info message
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=(0, 20))
        
        info_text = "📋 Configure exam URL and proxies in the Config tab, then enter user credentials below"
        info_label = ttk.Label(info_frame, text=info_text, font=("Arial", 10), foreground="darkblue")
        info_label.pack(anchor=tk.W)
        
        # --- ADD THIS ENTIRE BLOCK ---
        # Exam URL input
        url_frame = ttk.LabelFrame(main_frame, text="🔗 Exam URL", padding="15")
        url_frame.pack(fill=tk.X, pady=(0, 20))
        
        url_grid = ttk.Frame(url_frame)
        url_grid.pack(fill=tk.X)
        
        url_entry = ttk.Entry(url_grid, textvariable=self.single_exam_url_var, width=100)
        url_entry.pack(fill=tk.X, expand=True)
        # --- END OF BLOCK ---
        
        # User credentials
        cred_frame = ttk.LabelFrame(main_frame, text="👤 User Credentials", padding="15")
        cred_frame.pack(fill=tk.X, pady=(0, 20))
        
        cred_grid = ttk.Frame(cred_frame)
        cred_grid.pack(fill=tk.X)
        
        ttk.Label(cred_grid, text="Email:", font=("Arial", 11, "bold")).grid(row=0, column=0, sticky=tk.W, pady=10)
        email_entry = ttk.Entry(cred_grid, textvariable=self.email_var, width=50)
        email_entry.grid(row=0, column=1, sticky=tk.W, padx=(15, 0), pady=10)
        
        ttk.Label(cred_grid, text="Password:", font=("Arial", 11, "bold")).grid(row=1, column=0, sticky=tk.W, pady=10)
        password_entry = ttk.Entry(cred_grid, textvariable=self.password_var, width=50)
        password_entry.grid(row=1, column=1, sticky=tk.W, padx=(15, 0), pady=10)
        
        # ADD THIS ENTIRE BLOCK FOR THE V3 ACTION
        ttk.Label(cred_grid, text="reCAPTCHA v3 Action:", font=("Arial", 11, "bold")).grid(row=2, column=0, sticky=tk.W, pady=10)
        action_entry = ttk.Entry(cred_grid, textvariable=self.recaptcha_action_var, width=50)
        action_entry.grid(row=2, column=1, sticky=tk.W, padx=(15, 0), pady=10)
        ttk.Label(cred_grid, text="(Optional: for v3 Enterprise)").grid(row=2, column=2, sticky=tk.W, padx=5)
        
        # Module selection for single user
        module_frame = ttk.LabelFrame(main_frame, text="📚 Modules to Book", padding="15")
        module_frame.pack(fill=tk.X, pady=(0, 20))
        
        module_grid = ttk.Frame(module_frame)
        module_grid.pack()
        
        ttk.Checkbutton(module_grid, text="📖 READING", variable=self.reading_var).grid(row=0, column=0, padx=15, pady=10)
        ttk.Checkbutton(module_grid, text="🎧 LISTENING", variable=self.listening_var).grid(row=0, column=1, padx=15, pady=10)
        ttk.Checkbutton(module_grid, text="✍️ WRITING", variable=self.writing_var).grid(row=0, column=2, padx=15, pady=10)
        ttk.Checkbutton(module_grid, text="🗣️ SPEAKING", variable=self.speaking_var).grid(row=0, column=3, padx=15, pady=10)
        
        # Control buttons
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(pady=30)
        
        self.single_start_button = ttk.Button(buttons_frame, text="🚀 Start Single User Booking", 
                                            command=self.start_single_booking, style="Accent.TButton")
        self.single_start_button.pack(side=tk.LEFT, padx=10)
        
        self.single_stop_button = ttk.Button(buttons_frame, text="⏹️ Stop Booking", 
                                           command=self.stop_booking, state=tk.DISABLED)
        self.single_stop_button.pack(side=tk.LEFT, padx=10)
        
        # Status display
        self.single_status_var = tk.StringVar(value="⚡ Ready to start booking")
        status_label = ttk.Label(main_frame, textvariable=self.single_status_var, 
                               font=("Arial", 12, "bold"), foreground="green")
        status_label.pack(pady=(20, 0))
    
    def create_multiple_pane(self, parent):
        """Create multiple users pane with CSV loading functionality"""
        main_frame = ttk.Frame(parent, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="👥 Multiple Users Booking", font=("Arial", 18, "bold"))
        title_label.pack(pady=(0, 30))
        
        # Info message
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=(0, 20))
        
        info_text = "📋 Configure exam URL and proxies in the Config tab, then load a CSV file with user credentials"
        info_label = ttk.Label(info_frame, text=info_text, font=("Arial", 10), foreground="darkblue")
        info_label.pack(anchor=tk.W)

        # --- ADD THIS ENTIRE BLOCK ---
        # Exam URL input
        url_frame = ttk.LabelFrame(main_frame, text="🔗 Exam URL", padding="15")
        url_frame.pack(fill=tk.X, pady=(0, 20))
        
        url_grid = ttk.Frame(url_frame)
        url_grid.pack(fill=tk.X)
        
        url_entry = ttk.Entry(url_grid, textvariable=self.multi_exam_url_var, width=100)
        url_entry.pack(fill=tk.X, expand=True)
        # --- END OF BLOCK ---
        
        # CSV file selection
        csv_frame = ttk.LabelFrame(main_frame, text="📄 CSV File with Candidate Details", padding="15")
        csv_frame.pack(fill=tk.X, pady=(0, 20))
        
        csv_select_frame = ttk.Frame(csv_frame)
        csv_select_frame.pack(fill=tk.X)
        
        ttk.Label(csv_select_frame, text="CSV File:", font=("Arial", 11, "bold")).pack(side=tk.LEFT)
        csv_entry = ttk.Entry(csv_select_frame, textvariable=self.csv_file_var, width=60)
        csv_entry.pack(side=tk.LEFT, padx=(15, 10), fill=tk.X, expand=True)
        ttk.Button(csv_select_frame, text="📁 Browse", command=self.browse_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(csv_select_frame, text="👁️ Preview", command=self.preview_csv).pack(side=tk.LEFT, padx=5)
        
        # CSV format info
        format_info = ttk.Label(csv_frame, text="Format: email,password,modules (e.g., user@email.com,pass123,READING|LISTENING)", 
                               font=("Arial", 9), foreground="gray")
        format_info.pack(anchor=tk.W, pady=(5, 0))
        
        # CSV preview area
        preview_frame = ttk.LabelFrame(main_frame, text="👁️ Candidates Preview", padding="15")
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        # Create treeview for CSV preview
        columns = ("Email", "Password", "Modules", "Flexible")
        self.csv_tree = ttk.Treeview(preview_frame, columns=columns, show="headings", height=10)
        
        # Configure columns
        self.csv_tree.heading("Email", text="📧 Email")
        self.csv_tree.heading("Password", text="🔐 Password")
        self.csv_tree.heading("Modules", text="📚 Modules")
        self.csv_tree.heading("Flexible", text="🤸 not-Flexible")
        
        self.csv_tree.column("Email", width=300)
        self.csv_tree.column("Password", width=150)
        self.csv_tree.column("Modules", width=250)
        self.csv_tree.column("Flexible", width=80, anchor=tk.CENTER)
        
        # Add scrollbar
        csv_scrollbar = ttk.Scrollbar(preview_frame, orient=tk.VERTICAL, command=self.csv_tree.yview)
        self.csv_tree.configure(yscrollcommand=csv_scrollbar.set)
        
        self.csv_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        csv_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # --- ADD THIS BLOCK RIGHT AFTER IT ---
        # Bind the double-click event to the toggle function
        self.csv_tree.bind("<Double-1>", self.toggle_flexible_status)
        
        # Add an info label to instruct the user
        info_label = ttk.Label(preview_frame, text="💡 Tip: Double-click a row to toggle its 'Flexible' status.",
                               font=("Arial", 9), foreground="darkblue")
        info_label.pack(side=tk.BOTTOM, fill=tk.X, pady=(5, 0))
        # --- END OF BLOCK ---
        
        # Control buttons
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(pady=30)
        
        self.multi_start_button = ttk.Button(buttons_frame, text="🚀 Start Multi User Booking", 
                                           command=self.start_multi_booking, style="Accent.TButton")
        self.multi_start_button.pack(side=tk.LEFT, padx=10)
        
        self.multi_stop_button = ttk.Button(buttons_frame, text="⏹️ Stop Booking", 
                                          command=self.stop_booking, state=tk.DISABLED)
        self.multi_stop_button.pack(side=tk.LEFT, padx=10)
        
        # Status display
        self.multi_status_var = tk.StringVar(value="⚡ Ready to start booking")
        status_label = ttk.Label(main_frame, textvariable=self.multi_status_var, 
                               font=("Arial", 12, "bold"), foreground="green")
        status_label.pack(pady=(20, 0))
    
    def create_logs_pane(self, parent):
        """Create logs pane with a tab for each user and a main log."""
        main_frame = ttk.Frame(parent, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        self.log_notebook = ttk.Notebook(main_frame)
        self.log_notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create the main log tab
        main_log_frame = ttk.Frame(self.log_notebook)
        self.log_notebook.add(main_log_frame, text="📊 Main Log")
        
        self.log_text = scrolledtext.ScrolledText(main_log_frame, height=25, width=100, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Log control buttons
        log_buttons = ttk.Frame(main_frame)
        log_buttons.pack(pady=(0, 0))
        
        ttk.Button(log_buttons, text="💾 Save Main Log", command=self.save_logs).pack(side=tk.LEFT, padx=5)
    
    def log_message(self, message):
        """Add message to log area"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        if self.auto_scroll.get():
            self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def toggle_auto_scroll(self):
        """Toggle auto-scroll for logs"""
        self.auto_scroll.set(not self.auto_scroll.get())
        status = "enabled" if self.auto_scroll.get() else "disabled"
        self.log_message(f"Auto-scroll {status}")
    
    def clear_logs(self):
        """Clear the log area"""
        self.log_text.delete(1.0, tk.END)
        self.log_message("Logs cleared")
    
    def save_logs(self):
        """Save logs to file"""
        filename = filedialog.asksaveasfilename(
            title="Save Logs",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                self.log_message(f"Logs saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs: {e}")
    
    def browse_csv(self):
        """Browse for CSV file"""
        filename = filedialog.askopenfilename(
            title="Select CSV file with user credentials",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            self.csv_file_var.set(filename)
            self.log_message(f"Selected CSV file: {filename}")
    
    def preview_csv(self):
        """Preview CSV file contents, defaulting 'flexible' to False."""
        csv_file = self.csv_file_var.get().strip()
        if not csv_file or not os.path.exists(csv_file):
            messagebox.showerror("Error", "Please select a valid CSV file first.")
            return

        try:
            for item in self.csv_tree.get_children():
                self.csv_tree.delete(item)
            self.csv_users_data = []

            with open(csv_file, 'r', newline='', encoding='utf-8-sig') as file:
                reader = csv.reader(file)
                rows = list(reader)
                
                # Remove empty rows
                rows = [row for row in rows if row and any(cell.strip() for cell in row)]
                
                if not rows:
                    messagebox.showwarning("Warning", "CSV file is empty.")
                    return
                
                # Check if first row is header
                first_row = rows[0]
                is_header = (len(first_row) >= 2 and 
                           'email' in first_row[0].lower() and 
                           'password' in first_row[1].lower())
                
                start_row = 1 if is_header else 0
                
                # Process data rows
                for row_num, row in enumerate(rows[start_row:], start_row + 1):
                    if len(row) < 2:
                        self.log_message(f"Row {row_num}: Skipped due to insufficient columns.")
                        continue

                    email = row[0].strip() if len(row) > 0 else ""
                    password = row[1].strip() if len(row) > 1 else ""
                    modules_str = row[2].strip() if len(row) > 2 else ""
                    
                    if not email or not password:
                        self.log_message(f"Row {row_num}: Missing email or password - skipped.")
                        continue

                    # Parse modules - handle both ; and | separators
                    if modules_str:
                        # Split by either ; or | and clean up
                        if ';' in modules_str:
                            modules = [m.strip().upper() for m in modules_str.split(';') if m.strip()]
                        else:
                            modules = [m.strip().upper() for m in modules_str.split('|') if m.strip()]
                    else:
                        modules = ['READING', 'LISTENING'] # Default

                    user_data = {
                        'email': email,
                        'password': password,
                        'modules': modules,
                        'flexible': False  # Default to False
                    }
                    self.csv_users_data.append(user_data)
                    
                    # Display with | separator for consistency
                    self.csv_tree.insert('', 'end', values=(email, password, '|'.join(modules), 'No'))

            self.log_message(f"CSV preview loaded: {len(self.csv_users_data)} users found.")
            if not self.csv_users_data:
                messagebox.showwarning("Warning", "No valid user data found in CSV file.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load CSV file: {e}")
            self.log_message(f"Error loading CSV: {e}")

    def toggle_flexible_status(self, event):
        """Handles double-clicking a row in the multi-user treeview to toggle flexible status."""
        selected_item_id = self.csv_tree.focus()
        if not selected_item_id:
            return

        # Get the index of the selected row
        item_index = self.csv_tree.index(selected_item_id)
        
        # Get the corresponding user data dictionary
        user_data = self.csv_users_data[item_index]
        
        # Toggle the 'flexible' boolean value
        user_data['flexible'] = not user_data['flexible']
        
        # Update the display text in the Treeview
        new_status_text = "Yes" if user_data['flexible'] else "No"
        self.csv_tree.item(selected_item_id, values=(
            user_data['email'],
            user_data['password'],
            '|'.join(user_data['modules']),
            new_status_text
        ))
        
        self.log_message(f"Toggled flexible status for {user_data['email']} to: {new_status_text}")
        
    # Configuration management methods
    def save_configuration(self):
        """Saves the proxy list to a file."""
        try:
            # We now only save the raw text from the proxy list box
            self.saved_config = {
                'proxies_text': self.proxy_list_text.get(1.0, tk.END).strip()
            }
            with open('gui_config.json', 'w') as f:
                json.dump(self.saved_config, f, indent=2)
            self.config_status_var.set("✅ Proxy List configuration saved!")
            self.log_message("✅ Proxy list saved successfully.")
        except Exception as e:
            self.config_status_var.set(f"❌ Error saving config: {e}")

    def load_configuration_on_startup(self):
        """Loads proxy list configuration on startup."""
        try:
            if os.path.exists('gui_config.json'):
                with open('gui_config.json', 'r') as f:
                    self.saved_config = json.load(f)

                # Get the saved text and insert it into the text box
                proxies_text = self.saved_config.get('proxies_text', '')
                self.proxy_list_text.delete(1.0, tk.END)
                self.proxy_list_text.insert(tk.END, proxies_text)

                self.config_status_var.set("✅ Proxy List configuration loaded.")
        except Exception as e:
            self.config_status_var.set(f"⚠️ Could not load proxy config: {e}")
            
    def load_configuration(self):
        """Loads configuration and provides user feedback."""
        self.load_configuration_on_startup()
        if self.config_status_var.get() == "✅ Bright Data configuration loaded.":
            self.log_message("✅ Configuration loaded from gui_config.json")
        else:
            self.log_message("ℹ️ No configuration file found.")

    def get_current_config(self):
        """
        Gets the current configuration and parses the proxy list only if enabled.
        """
        # If the "Use Proxies" checkbox is not checked, return an empty proxy list.
        if not self.use_proxies_var.get():
            self.log_message("ℹ️ Proxies are disabled by user.")
            return {'proxies': []}

        # Get the raw text from the text box
        proxies_text = self.proxy_list_text.get(1.0, tk.END).strip()
        proxy_lines = proxies_text.splitlines()

        parsed_proxies = []
        for line in proxy_lines:
            line = line.strip()
            if not line:
                continue
            
            parts = line.split(':')
            if len(parts) != 4:
                self.log_message(f"⚠️ Skipping malformed proxy line: {line}")
                continue
            
            host, port, user, password = parts
            # Format into the URL the bot's HTTP client needs
            proxy_url = f"http://{user}:{password}@{host}:{port}"
            parsed_proxies.append(proxy_url)

        # The function now returns a dictionary with the final list of proxy URLs
        if parsed_proxies:
            self.log_message(f"ℹ️ Proxies are enabled. Loaded {len(parsed_proxies)} proxies.")
        else:
            self.log_message("⚠️ Proxies are enabled, but the list is empty.")
            
        return {'proxies': parsed_proxies}

    def get_selected_modules(self):
        """Get list of selected modules"""
        modules = []
        if self.reading_var.get():
            modules.append("READING")
        if self.listening_var.get():
            modules.append("LISTENING")
        if self.writing_var.get():
            modules.append("WRITING")
        if self.speaking_var.get():
            modules.append("SPEAKING")
        return modules
    
    def validate_single_user_inputs(self):
        """Validate single user inputs"""
        config = self.get_current_config()
        
        if not self.single_exam_url_var.get().strip():
            messagebox.showerror("Error", "Please enter exam URL in the Single User tab")
            return False
        
        if self.use_proxies_var.get() and not config['proxies']:
            messagebox.showerror("Error", "'Use Proxies' is checked, but the proxy list is empty. Please add proxies or uncheck the box.")
            return False
        
        if not self.email_var.get().strip() or not self.password_var.get().strip():
            messagebox.showerror("Error", "Please enter both email and password")
            return False
        
        if not self.get_selected_modules():
            messagebox.showerror("Error", "Please select at least one module")
            return False
        
        return True
    
    def validate_multi_user_inputs(self):
        """Validate multi-user inputs"""
        config = self.get_current_config()
        
        if not self.multi_exam_url_var.get().strip():
            messagebox.showerror("Error", "Please enter exam URL in the Multiple Users tab")
            return False
        
        if self.use_proxies_var.get() and not config['proxies']:
            messagebox.showerror("Error", "'Use Proxies' is checked, but the proxy list is empty. Please add proxies or uncheck the box.")
            return False
        
        if not self.csv_file_var.get().strip() or not os.path.exists(self.csv_file_var.get()):
            messagebox.showerror("Error", "Please select a valid CSV file")
            return False
        
        if not self.csv_users_data:
            messagebox.showerror("Error", "Please preview CSV file first to load candidate data")
            return False
        
        return True
    
    def start_single_booking(self):
        """Start single user booking process"""
        if not BOT_AVAILABLE:
            messagebox.showerror("Error", "Bot module not available. Please check installation.")
            return
        
        if not self.validate_single_user_inputs():
            return
        
        self.is_running = True
        self.single_start_button.config(state=tk.DISABLED)
        self.single_stop_button.config(state=tk.NORMAL)
        self.single_status_var.set("🚀 Starting single user booking...")
        
        # Clear log
        self.log_text.delete(1.0, tk.END)
        
        # Start booking in separate thread
        thread = threading.Thread(target=self.run_single_booking_async, daemon=True)
        thread.start()
    
    def start_multi_booking(self):
        """Start multi-user booking process"""
        if not BOT_AVAILABLE:
            messagebox.showerror("Error", "Bot module not available. Please check installation.")
            return
        
        if not self.validate_multi_user_inputs():
            return
        
        self.is_running = True
        self.multi_start_button.config(state=tk.DISABLED)
        self.multi_stop_button.config(state=tk.NORMAL)
        self.multi_status_var.set("🚀 Starting multi-user booking...")
        
        # Clear log
        self.log_text.delete(1.0, tk.END)
        
        # Start booking in separate thread
        thread = threading.Thread(target=self.run_multi_booking_async, daemon=True)
        thread.start()
    
    def stop_booking(self):
        """Stop the booking process"""
        self.is_running = False
        
        # Re-enable appropriate buttons
        if hasattr(self, 'single_start_button'):
            self.single_start_button.config(state=tk.NORMAL)
        if hasattr(self, 'single_stop_button'):
            self.single_stop_button.config(state=tk.DISABLED)
        if hasattr(self, 'multi_start_button'):
            self.multi_start_button.config(state=tk.NORMAL)
        if hasattr(self, 'multi_stop_button'):
            self.multi_stop_button.config(state=tk.DISABLED)
        
        # Update the correct status variables for both tabs.
        self.single_status_var.set("⏹️ Stopped by user")
        self.multi_status_var.set("⏹️ Stopped by user")
        self.log_message("🛑 Booking stopped by user")
    
    def run_single_booking_async(self):
        """Run single user booking in async context"""
        try:
            asyncio.run(self.run_single_booking())
        except Exception as e:
            self.log_message(f"❌ Error: {e}")
            self.single_status_var.set("❌ Error")
        finally:
            if hasattr(self, 'single_start_button'):
                self.single_start_button.config(state=tk.NORMAL)
            if hasattr(self, 'single_stop_button'):
                self.single_stop_button.config(state=tk.DISABLED)
    
    def run_multi_booking_async(self):
        """Run multi-user booking in async context"""
        try:
            asyncio.run(self.run_multi_booking())
        except Exception as e:
            self.log_message(f"❌ Error: {e}")
            self.multi_status_var.set("❌ Error")
        finally:
            if hasattr(self, 'multi_start_button'):
                self.multi_start_button.config(state=tk.NORMAL)
            if hasattr(self, 'multi_stop_button'):
                self.multi_stop_button.config(state=tk.DISABLED)
    
    async def run_single_booking(self):
        """Single user booking logic with dynamic Bright Data proxy."""
        config = self.get_current_config()
        exam_url = self.single_exam_url_var.get().strip()
        
        # Use the static proxy list 
        proxies = config['proxies']
        
        if len(proxies) < 2:
            self.log_message(f"❌ Error: Single user booking requires at least 2 proxies, but only {len(proxies)} provided.")
            self.single_status_var.set("❌ Not Enough Proxies")
            self.stop_booking()
            return
            
        monitor_proxy = None # Use server IP
        booking_proxies = proxies # Use the generated sticky sessions

        modules = self.get_selected_modules()
        email = self.email_var.get().strip()
        password = self.password_var.get().strip()
        
        self.log_message("🚀 Starting optimal single-user booking...")
        self.log_message(f"👀 Monitoring with main server IP (No Proxy)...")
        
        try:
            # --- Step 1: Monitoring with the main server IP ---
            self.single_status_var.set("👀 Monitoring with server IP...")
            monitor_manager = GoetheBookingManager(
                "CAP-684E5CCF1ECF9DFAD69F1AC6BCDB2C26D6177FE4B53ED3F1FB4720FEDD3C082A",
                "capsolver",  # CapSolver service
                proxy=monitor_proxy # This will be None
            )
            async with GoetheAPIBot(monitor_manager.captcha_api_key, monitor_manager.captcha_service, proxy=monitor_proxy) as monitor_bot:
                monitor_response = await monitor_bot.phase_1_monitor_exam_url(exam_url)

                if not monitor_response or not self.is_running:
                    self.log_message("❌ Monitoring failed or was stopped. Halting.")
                    self.single_status_var.set("❌ Monitoring Failed")
                    return

                self.log_message("✅ SLOT FOUND! Switching to clean proxy pool for booking.")
                
                # --- Step 2: Booking with the clean, purchased proxy pool ---
                booking_successful = False
                for i, proxy in enumerate(booking_proxies):
                    if not self.is_running: break
                    
                    proxy_info = f"Booking Proxy {i+1}/{len(booking_proxies)} ({proxy.split('@')[-1]})"
                    self.log_message("-" * 50)
                    self.log_message(f"⚡ Attempting booking with clean IP: {proxy_info}")
                    self.single_status_var.set(f"⚡ Booking with {proxy_info}")

                    booking_bot = GoetheAPIBot(
                        monitor_manager.captcha_api_key, 
                        monitor_manager.captcha_service,
                        proxy=proxy,
                        # Pass the action from the GUI. If empty, it's treated as None.
                        recaptcha_v3_action=self.recaptcha_action_var.get().strip() or None
                    )
                    
                    status = await booking_bot.book_slot(
                        exam_url, email, password, modules, skip_monitoring=False
                    )
                    
                    if status == 'SUCCESS':
                        self.single_status_var.set("✅ Booking Successful!")
                        self.log_message("🎉 Booking completed successfully!")
                        booking_successful = True
                        break
                    elif status == 'RATE_LIMITED':
                        self.log_message(f"IP Banned ⚠️ Rate limited on {proxy_info}. Switching to the next proxy...")
                        continue
                    else: # 'FAILED'
                        self.log_message(f"😞 Booking failed on {proxy_info} due to a non-recoverable error.")
                        break
                
                if not booking_successful:
                    self.single_status_var.set("❌ All booking attempts failed")
                    self.log_message("😞 Booking failed after trying all available clean proxies.")

        except Exception as e:
            self.log_message(f"❌ A critical error occurred in the single-booking process: {e}")
            self.single_status_var.set("❌ Critical Error")
        finally:
            self.stop_booking()
    
    async def run_multi_booking(self):
        config = self.get_current_config()
        exam_url = self.multi_exam_url_var.get().strip()
        num_candidates = len(self.csv_users_data)

        # Validate configuration
        if not exam_url:
            self.log_message("❌ Error: Please configure exam URL in the Config tab first.")
            self.multi_status_var.set("❌ No Exam URL")
            return
            
        if not self.csv_users_data:
            self.log_message("❌ Error: Please load a CSV file with user data first.")
            self.multi_status_var.set("❌ No User Data")
            return

        # --- NEW: Advanced Proxy Pool Management ---
        primary_proxies = []
        fallback_proxy_queue = asyncio.Queue()

        # Only manage and validate the proxy pool if the user has enabled proxies.
        if self.use_proxies_var.get():
            all_proxies = config['proxies']
            
            # Check if there are enough proxies for the number of candidates.
            if len(all_proxies) < num_candidates:
                self.log_message(f"❌ Error: You have {num_candidates} candidates but only provided {len(all_proxies)} proxies.")
                self.multi_status_var.set("❌ Not Enough Proxies")
                # No need to call self.stop_booking() here, just return.
                return
            
            # Assign a primary proxy to each candidate.
            primary_proxies = all_proxies[:num_candidates]
            # The rest form a shared queue of fallback proxies.
            for proxy in all_proxies[num_candidates:]:
                await fallback_proxy_queue.put(proxy)
            
            self.log_message(f"🤖 Proxy Pool: {len(primary_proxies)} primary assignments, {fallback_proxy_queue.qsize()} available as fallbacks.")
        else:
            # If proxies are disabled, create an empty list of primary proxies.
            # The bot will run using the server IP for all candidates.
            primary_proxies = [None] * num_candidates
            self.log_message("🤖 Proxy Pool: Proxies disabled. All tasks will use the server IP.")
        # --- END of New Logic ---

        stop_signal = asyncio.Event()
        
        self.log_message(f"🎯 Target URL: {exam_url}")
        self.log_message(f"👥 Found {num_candidates} candidates.")
        
        try:
            self.multi_status_var.set("👀 Monitoring for exam slot...")
            
            # Assign the first proxy for monitoring if proxies are enabled
            monitor_proxy = None
            if self.use_proxies_var.get() and primary_proxies:
                monitor_proxy = primary_proxies[0]
                # Remove the proxy used for monitoring from the primary_proxies list
                primary_proxies = primary_proxies[1:]
                # Add the remaining proxies to the user assignments
                primary_proxies = [None] + primary_proxies  # Ensure we still have enough for all users
                
                self.log_message(f"Creating a dedicated monitor bot using proxy: {monitor_proxy.split('@')[-1] if monitor_proxy else 'server IP'}...")
            else:
                self.log_message("Creating a dedicated monitor bot (using server IP)...")
                
            monitor_manager = GoetheBookingManager(".", "capsolver")

            async with GoetheAPIBot(monitor_manager.captcha_api_key, monitor_manager.captcha_service, 
                                  proxy=monitor_proxy, stop_signal=stop_signal) as monitor_bot:
                monitor_response = await monitor_bot.phase_1_monitor_exam_url(exam_url)

                if not monitor_response or not self.is_running:
                    if not self.is_running:
                        self.log_message("🛑 Monitoring stopped by user.")
                    else:
                        self.log_message("❌ Monitoring failed or timed out. Halting.")
                    self.multi_status_var.set("❌ Monitoring Failed")
                    return

                self.log_message("✅ SLOT FOUND! Starting parallel booking attempts...")
                self.multi_status_var.set(f"⚡ Slot found! Starting {num_candidates} bookings...")
                
                # --- Create individual log tabs for each candidate ---
                def create_candidate_tabs():
                    """Create individual tabs for each candidate in the log notebook."""
                    for i, user_data in enumerate(self.csv_users_data):
                        tab_name = f"[{i+1}] {user_data['email']}"
                        tab_frame = ttk.Frame(self.log_notebook)
                        self.log_notebook.add(tab_frame, text=tab_name)
                        
                        # Create scrolled text widget for this candidate
                        candidate_log_widget = scrolledtext.ScrolledText(
                            tab_frame, height=25, width=100, wrap=tk.WORD
                        )
                        candidate_log_widget.pack(fill=tk.BOTH, expand=True)
                        
                        # Store in the log_widgets dictionary for routing
                        self.log_widgets[str(i+1)] = candidate_log_widget
                
                # Execute tab creation in the main thread
                self.root.after(0, create_candidate_tabs)
                
                # --- NEW: Wrapper function with advanced fallback ---
                async def book_candidate_with_fallback(user_data, user_index):
                    """Handles booking for one candidate with multiple fallback attempts."""
                    # 1. First attempt with the primarily assigned proxy
                    primary_proxy = primary_proxies[user_index]
                    proxies_to_try = [primary_proxy]

                    # 2. Add a fallback from the shared pool if available
                    if not fallback_proxy_queue.empty():
                        try:
                            fallback_proxy = fallback_proxy_queue.get_nowait()
                            proxies_to_try.append(fallback_proxy)
                            self.log_message(f"[*] [{user_index+1}] {user_data['email']}: Reserved fallback proxy {fallback_proxy.split('@')[-1]}")
                        except asyncio.QueueEmpty:
                            pass # Another task took it, which is fine
                    
                    # 3. Add the server's main IP as the last resort
                    proxies_to_try.append(None)
                    
                    final_status = 'FAILED'
                    for i, proxy_attempt in enumerate(proxies_to_try):
                        if stop_signal.is_set():
                            return 'CANCELLED'
                            
                        proxy_display = proxy_attempt.split('@')[-1] if proxy_attempt else 'Main Server IP'
                        self.log_message(f"-> [{user_index+1}] {user_data['email']}: Attempt {i+1} using IP: {proxy_display}")
                        
                        log_prefix_str = f"[{user_index+1}] {user_data['email']} - "
                        
                        bot = GoetheAPIBot(
                            monitor_manager.captcha_api_key, 
                            monitor_manager.captcha_service,
                            proxy=proxy_attempt,
                            stop_signal=stop_signal,
                            log_prefix=log_prefix_str,
                            # For multi-user, we assume the same action for all.
                            # We will add a GUI field for this later if needed. For now, hardcode or leave empty.
                            # IMPORTANT: You must manually find and enter the correct action here.
                            recaptcha_v3_action=self.recaptcha_action_var.get().strip() or None
                        )
                        
                        # --- CRITICAL FIX: Each bot starts fresh with original exam_url ---
                        try:
                            status = await bot.book_slot(
                                exam_url, # Changed from direct_booking_url to force fresh sessions
                                user_data['email'], 
                                user_data['password'], 
                                user_data['modules'],
                                is_flexible=user_data['flexible'],
                                skip_monitoring=False # Changed from True to ensure each bot builds its own session
                            )
                        except PersistentServerException:
                            self.log_message(f"⚠️ [{user_index+1}] {user_data['email']}: Persistent server errors on IP {proxy_display}. Trying next fallback...")
                            continue # This will move to the next proxy in the loop
                        except RateLimitException:
                            self.log_message(f"⚠️ [{user_index+1}] {user_data['email']}: IP {proxy_display} was blocked. Trying next fallback...")
                            continue
                        # --- END OF FIX ---
                        
                        if status == 'SUCCESS':
                            # Capture the actual booked modules from the bot instance
                            actual_booked_modules = getattr(bot, 'final_booked_modules', user_data['modules'])
                            return ('SUCCESS', actual_booked_modules)
                        elif status == 'RATE_LIMITED':
                            self.log_message(f"⚠️ [{user_index+1}] {user_data['email']}: IP {proxy_display} was blocked. Trying next fallback...")
                            continue # Loop to the next proxy
                        else: # FAILED
                            final_status = 'FAILED'
                            break # A non-IP-related error occurred, stop trying for this user.
                    
                    return final_status

                tasks = []
                for i, user in enumerate(self.csv_users_data):
                    # --- Each task now starts fresh and builds its own session ---
                    task = book_candidate_with_fallback(user, i)
                    tasks.append(task)
                
                if tasks:
                    self.log_message(f"🚀 Executing {len(tasks)} bookings in parallel...")
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                else:
                    results = []
                    self.log_message("No tasks to run.")
                
            # Process results with explicit SUCCESS check
            successful_count = 0
            # --- Results processing is now MUCH simpler ---
            successful_count = 0
            for i, result in enumerate(results):
                email = self.csv_users_data[i]['email']
                if isinstance(result, Exception):
                    self.log_message(f"❌ [{i+1}] {email}: Booking failed with an error: {result}")
                elif isinstance(result, tuple) and result[0] == 'SUCCESS':
                    successful_count += 1
                    actual_modules = result[1]
                    # We no longer call open_browser_for_user here
                    self.log_message(f"✅ [{i+1}] {email}: Booking successful! Browser was opened.")
                    self.log_message(f"✅ [{i+1}] {email}: Actual modules booked: {', '.join(actual_modules)}")
                elif result == 'SUCCESS':  # Fallback for old format
                    successful_count += 1
                    self.log_message(f"✅ [{i+1}] {email}: Booking successful! Browser was opened.")
                else:
                    self.log_message(f"❌ [{i+1}] {email}: Booking failed with status: {result}")

            self.log_message(f"📊 Final Tally: {successful_count} out of {len(results)} bookings were successful.")
            self.multi_status_var.set(f"✅ Finished: {successful_count}/{len(results)} successful")

        except Exception as e:
            self.log_message(f"❌ A critical error occurred in the multi-booking process: {e}")
            self.multi_status_var.set("❌ Critical Error")
        finally:
            self.stop_booking()
    
    async def book_single_user_parallel(self, exam_url: str, email: str, password: str, modules: list, user_index: int):
        """Book for a single user in parallel with separate browser instance"""
        try:
            # Create separate manager instance for this user
            manager = GoetheBookingManager(
                "YOUR_CAPSOLVER_API_KEY_HERE",  # CapSolver API key
                "capsolver"  # CapSolver service
            )
            
            self.log_message(f"🌐 [{user_index}] {email}: Starting booking process...")
            self.log_message(f"📚 [{user_index}] {email}: Required modules: {', '.join(modules)}")
            
            # Use the enhanced booking method that opens payment page in browser
            success = await manager.book_single(exam_url, email, password, modules)
            
            if success:
                self.log_message(f"✅ [{user_index}] {email}: All modules available and booking completed!")
            else:
                self.log_message(f"❌ [{user_index}] {email}: Booking failed - modules may be fully booked")
                self.log_message(f"🚫 [{user_index}] {email}: Could not secure slots for: {', '.join(modules)}")
            
            return success
            
        except Exception as e:
            self.log_message(f"❌ [{user_index}] {email}: Parallel booking error - {e}")
            self.log_message(f"🚫 [{user_index}] {email}: Failed to check module availability")
            return False
    
    def save_config(self):
        """Save current configuration to file"""
        config = {
            "exam_url": self.exam_url_var.get(),
            "captcha_service": "anticaptcha",  # Default captcha service
            "captcha_api_key": "",  # No captcha key needed
            "email": self.email_var.get(),
            "password": self.password_var.get(),
            "csv_file": self.csv_file_var.get(),
            "modules": {
                "reading": self.reading_var.get(),
                "listening": self.listening_var.get(),
                "writing": self.writing_var.get(),
                "speaking": self.speaking_var.get()
            },
            "monitor_interval": self.interval_var.get()
        }
        
        filename = filedialog.asksaveasfilename(
            title="Save Configuration",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(config, f, indent=2)
                messagebox.showinfo("Success", "Configuration saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save configuration: {e}")
    
    def load_config_file(self):
        """Load configuration from a selected file"""
        filename = filedialog.askopenfilename(
            title="Load Configuration",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            self.load_config_from_file(filename)
    
    def load_config_from_file(self, config_file):
        """Load configuration from specific file"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Handle nested JSON structure from config_template.json
            if "exam_urls" in config:
                # New nested format
                exam_urls = config.get("exam_urls", {})
                if exam_urls:
                    # Get the first exam URL
                    first_url = list(exam_urls.values())[0] if exam_urls else ""
                    self.exam_url_var.set(first_url)
                
                # CAPTCHA settings
                # Skip captcha configuration - not needed in new GUI
                
                # User credentials
                users = config.get("users", [])
                if users:
                    first_user = users[0]
                    self.email_var.set(first_user.get("email", ""))
                    self.password_var.set(first_user.get("password", ""))
                
                # Booking settings
                booking_config = config.get("booking", {})
                modules = booking_config.get("modules", [])
                self.reading_var.set("READING" in modules)
                self.listening_var.set("LISTENING" in modules)
                self.writing_var.set("WRITING" in modules)
                self.speaking_var.set("SPEAKING" in modules)
                
                self.interval_var.set(str(booking_config.get("monitor_interval", "0.1")))
                
            else:
                # Old flat format (backward compatibility)
                self.exam_url_var.set(config.get("exam_url", ""))
                # Skip captcha variables - not needed in new GUI
                self.email_var.set(config.get("email", ""))
                self.password_var.set(config.get("password", ""))
                self.csv_file_var.set(config.get("csv_file", ""))
                self.interval_var.set(str(config.get("monitor_interval", "0.1")))
                
                modules = config.get("modules", {})
                self.reading_var.set(modules.get("reading", True))
                self.listening_var.set(modules.get("listening", True))
                self.writing_var.set(modules.get("writing", False))
                self.speaking_var.set(modules.get("speaking", False))
            
            self.log_message(f"Configuration loaded from {config_file}")
            messagebox.showinfo("Success", f"Configuration loaded from {os.path.basename(config_file)}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load configuration: {e}")
            self.log_message(f"Error loading config: {e}")
    
    def load_config(self):
        """Load configuration from file"""
        # Try to load config.json first, then config_template.json
        config_files = ["config.json", "config_template.json"]
        config_file = None
        
        for file in config_files:
            if os.path.exists(file):
                config_file = file
                break
        
        if config_file:
            try:
                self.load_config_from_file(config_file)
            except Exception as e:
                self.log_message(f"[INFO] Could not load {config_file}: {e}")
    
    def run(self):
        """Start the GUI"""
        self.root.mainloop()

def main():
    """Main function"""
    if not BOT_AVAILABLE:
        print("❌ Goethe API Bot module not found!")
        print("Please ensure goethe_ultimate_api_bot.py is in the same directory.")
        return
    
    app = GoetheAPIBotGUI()
    app.run()

if __name__ == "__main__":
    main()