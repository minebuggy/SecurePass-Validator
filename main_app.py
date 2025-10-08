import tkinter as tk
from tkinter import ttk, messagebox
import re
import math
import hashlib
import time
import pyotp
import qrcode
from PIL import Image, ImageTk
import io

#simulating the password (for the Sonar Cube)
SECRET_KEY = "this_is_a_very_weak_and_obvious_secret_key" 

# Define a simulated user database with 2FA 


USERS = {
    "admin": {
        "password": "AdminPassword123!",
        "role": "admin",
        "otp_secret": pyotp.random_base32()
    },
    "user": {
        "password": "UserPassword123!",
        "role": "user",
        "otp_secret": pyotp.random_base32()
    }
}

class PasswordStrengthCheckerApp:
    # Initialize the application window
    def __init__(self, root):
        self.root = root
        self.root.title("SecurePass Validator")
        self.root.withdraw()  # Hide the main window until login is successful
        self.show_login_window()

    # Display the login window
    def show_login_window(self):
        self.login_window = tk.Toplevel(self.root)
        self.login_window.title("Login")
        self.login_window.geometry("300x180")

        # Label for username input
        ttk.Label(self.login_window, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(self.login_window)
        self.username_entry.pack()

        # Label for password input
        ttk.Label(self.login_window, text="Password:").pack(pady=5)
        self.password_entry_login = ttk.Entry(self.login_window, show="*")
        self.password_entry_login.pack()

        # Login button to validate credentials
        ttk.Button(self.login_window, text="Login", command=self.check_login).pack(pady=20)

        # Handle window close event
        self.login_window.protocol("WM_DELETE_WINDOW", self.root.destroy)

    # Check login credentials and proceed with 2FA
    def check_login(self):
        username = self.username_entry.get()
        password = self.password_entry_login.get()

        # Validate credentials
        if username in USERS and USERS[username]["password"] == password:
            self.current_user = username
            self.login_window.destroy()  # Close login window
            self.show_2fa_window()  # Show 2FA window
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    # Show 2FA window with QR code for authentication
    def show_2fa_window(self):
        self.two_fa_window = tk.Toplevel(self.root)
        self.two_fa_window.title("Two-Factor Authentication")

        # Generate OTP secret and provisioning URI for 2FA
        secret = USERS[self.current_user]['otp_secret']
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=self.current_user, issuer_name="SecurePassApp")

        # Generate and display QR code for 2FA
        qr_img = qrcode.make(uri)
        qr_img_bytes = io.BytesIO()
        qr_img.save(qr_img_bytes, format='PNG')
        qr_img_bytes.seek(0)
        
        pil_img = Image.open(qr_img_bytes)
        self.qr_photo = ImageTk.PhotoImage(pil_img)

        ttk.Label(self.two_fa_window, text="Scan this QR code with your Authenticator app:").pack(pady=10)
        qr_label = ttk.Label(self.two_fa_window, image=self.qr_photo)
        qr_label.pack()

        # Entry field for 2FA code
        ttk.Label(self.two_fa_window, text="Enter 6-digit code:").pack(pady=10)
        self.two_fa_entry = ttk.Entry(self.two_fa_window)
        self.two_fa_entry.pack()

        # Button to verify the 2FA code
        ttk.Button(self.two_fa_window, text="Verify", command=self.verify_2fa).pack(pady=10)

    # Verify the entered 2FA code
    def verify_2fa(self):
        secret = USERS[self.current_user]['otp_secret']
        totp = pyotp.TOTP(secret)
        entered_code = self.two_fa_entry.get()

        # Check if the entered code is valid
        if totp.verify(entered_code):
            self.two_fa_window.destroy()
            self.root.deiconify()  # Show main app window
            self.setup_main_app_ui()  # Set up main UI
        else:
            messagebox.showerror("2FA Failed", "Invalid 2FA code.")

    # Set up the main app UI after successful 2FA
    def setup_main_app_ui(self):
        self.root.geometry("450x550")
        self.root.resizable(False, False)

        # Try to load common passwords from a file
        try:
            with open("common_passwords.txt", "r") as f:
                self.common_passwords = set(line.strip().lower() for line in f)
        except FileNotFoundError:
            messagebox.showerror("Error", "common_passwords.txt not found!")
            self.common_passwords = set()

        # Styling the UI elements
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("Red.Horizontal.TProgressbar", background='red')
        self.style.configure("Orange.Horizontal.TProgressbar", background='orange')
        self.style.configure("Yellow.Horizontal.TProgressbar", background='yellow')
        self.style.configure("Green.Horizontal.TProgressbar", background='green')

        # Main frame for password strength checker
        main_frame = ttk.Frame(self.root, padding="20 10 20 10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Welcome message with current user and role
        ttk.Label(main_frame, text=f"Welcome, {self.current_user} ({USERS[self.current_user]['role']})", font=("Helvetica", 10)).pack(pady=(0, 10))
        ttk.Label(main_frame, text="Password Strength Checker", font=("Helvetica", 16, "bold")).pack(pady=(0, 20))
        
        # Password input field
        ttk.Label(main_frame, text="Enter your password:").pack(anchor="w")
        self.password_entry_main = ttk.Entry(main_frame, show="*")
        self.password_entry_main.pack(fill=tk.X, pady=(5, 10))
        self.password_entry_main.bind("<KeyRelease>", self.evaluate_password)

        # Progress bar for password strength
        self.strength_meter = ttk.Progressbar(main_frame, orient="horizontal", length=300, mode="determinate")
        self.strength_meter.pack(pady=(10, 5))
        self.strength_label = ttk.Label(main_frame, text="", font=("Helvetica", 10, "italic"))
        self.strength_label.pack()

        # Label for entropy value
        self.entropy_label = ttk.Label(main_frame, text="Entropy: 0 bits", font=("Helvetica", 10, "bold"))
        self.entropy_label.pack(pady=(10, 20))

        # Suggestions text area
        ttk.Label(main_frame, text="Suggestions:").pack(anchor="w")
        self.feedback_text = tk.Text(main_frame, height=6, state="disabled", wrap="word", bg="#f0f0f0")
        self.feedback_text.pack(fill=tk.BOTH, expand=True, pady=(5,10))
        
        # Advanced feature for admin users to simulate password cracking
        if USERS[self.current_user]['role'] == 'admin':
            self.crack_button = ttk.Button(main_frame, text="Simulate Crack Time (Hashcat)", command=self.simulate_crack_time)
            self.crack_button.pack(pady=10)
            self.crack_time_label = ttk.Label(main_frame, text="Estimated time to crack: N/A", font=("Helvetica", 10, "bold"))
            self.crack_time_label.pack()

    # Evaluate password strength and provide suggestions
    def evaluate_password(self, event=None):
        password = self.password_entry_main.get()
        suggestions = []
        
        if not password:
            self.update_ui(0, 0, [])
            return
            
        # Check password complexity
        score = 0
        if len(password) >= 8: score += 20; suggestions.append("✔ At least 8 characters long.")
        else: suggestions.append("✘ Should be at least 8 characters long.")
        if re.search(r"[a-z]", password): score += 10; suggestions.append("✔ Contains lowercase letters.")
        else: suggestions.append("✘ Add lowercase letters.")
        if re.search(r"[A-Z]", password): score += 20; suggestions.append("✔ Contains uppercase letters.")
        else: suggestions.append("✘ Add uppercase letters.")
        if re.search(r"\d", password): score += 20; suggestions.append("✔ Contains numbers.")
        else: suggestions.append("✘ Add numbers.")
        if re.search(r"[\W_]", password): score += 30; suggestions.append("✔ Contains special characters.")
        else: suggestions.append("✘ Add special characters.")

        # Check if the password is too common
        if password.lower() in self.common_passwords:
            score = 5 # Drastically reduce score
            suggestions.append("✘ VERY COMMON PASSWORD!")

        # Calculate password entropy
        pool_size = 0
        if re.search(r'[a-z]', password): pool_size += 26
        if re.search(r'[A-Z]', password): pool_size += 26
        if re.search(r'\d', password): pool_size += 10
        if re.search(r'[\W_]', password): pool_size += 32 
        
        entropy = 0
        if pool_size > 0:
            entropy = len(password) * math.log2(pool_size)
        
        self.update_ui(score, entropy, suggestions)

    # Update the UI with the password strength and entropy
    def update_ui(self, score, entropy, suggestions):
        self.strength_meter["value"] = score
        self.entropy_label.config(text=f"Entropy: {entropy:.2f} bits")

        if entropy < 40:
            self.strength_label.config(text="Very Weak", foreground="red")
            self.strength_meter.config(style="Red.Horizontal.TProgressbar")
        elif entropy < 60:
            self.strength_label.config(text="Moderate", foreground="orange")
            self.strength_meter.config(style="Orange.Horizontal.TProgressbar")
        elif entropy < 80:
            self.strength_label.config(text="Strong", foreground="yellow")
            self.strength_meter.config(style="Yellow.Horizontal.TProgressbar")
        else:
            self.strength_label.config(text="Very Strong", foreground="green")
            self.strength_meter.config(style="Green.Horizontal.TProgressbar")

        # Update suggestions text box
        self.feedback_text.config(state="normal")
        self.feedback_text.delete("1.0", tk.END)
        self.feedback_text.insert(tk.END, "\n".join(suggestions))
        self.feedback_text.config(state="disabled")

        if USERS[self.current_user]['role'] == 'admin':
            self.crack_time_label.config(text="Estimated time to crack: N/A")

    # Simulate password crack time
    def simulate_crack_time(self):
        password = self.password_entry_main.get()
        if not password:
            messagebox.showinfo("Info", "Please enter a password to simulate.")
            return

        pool_size = 0
        if re.search(r'[a-z]', password): pool_size += 26
        if re.search(r'[A-Z]', password): pool_size += 26
        if re.search(r'\d', password): pool_size += 10
        if re.search(r'[\W_]', password): pool_size += 32
        
        entropy = 0
        if pool_size > 0:
            entropy = len(password) * math.log2(pool_size)

        # Assume GPU cracking speed and calculate crack time
        HASHES_PER_SECOND = 10_000_000_000  # 10 billion hashes/sec

        time_in_seconds = (2**entropy) / HASHES_PER_SECOND
        
        human_readable_time = self.format_time(time_in_seconds)
        self.crack_time_label.config(text=f"Estimated time to crack: {human_readable_time}")

    # Format time into human-readable format
    def format_time(self, seconds):
        if seconds < 1: return "Instantly"
        if seconds < 60: return f"{seconds:.2f} seconds"
        minutes = seconds / 60
        if minutes < 60: return f"{minutes:.2f} minutes"
        hours = minutes / 60
        if hours < 24: return f"{hours:.2f} hours"
        days = hours / 24
        if days < 365: return f"{days:.2f} days"
        years = days / 365
        if years < 1000: return f"{years:.2f} years"
        return "Centuries"

# Main execution of the app
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthCheckerApp(root)
    root.mainloop()



