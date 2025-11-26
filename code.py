import tkinter as tk
from tkinter import ttk
import re

class PasswordStrengthChecker:
    def __init__(self, master):
        self.master = master
        master.title("Password Strength Checker")
        master.geometry("400x350") # Slightly taller window
        master.resizable(False, False)

        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Variable to track the state of the checkbox
        self.show_password_var = tk.BooleanVar(value=False)

        # --- Password Input Frame ---
        self.input_frame = ttk.Frame(master, padding="15")
        self.input_frame.pack(fill="x")

        ttk.Label(self.input_frame, text="Enter Password:").pack(anchor="w", pady=(0, 5))
        
        # Password Entry field - starts hidden with show="*"
        self.password_entry = ttk.Entry(self.input_frame, show="*", width=40)
        self.password_entry.pack(fill="x", ipady=3)
        self.password_entry.bind("<KeyRelease>", self.check_password_strength)

        # Show/Hide Checkbox
        self.show_hide_check = ttk.Checkbutton(
            self.input_frame, 
            text="Show Password", 
            variable=self.show_password_var, 
            command=self.toggle_password_visibility
        )
        self.show_hide_check.pack(anchor="w", pady=(5, 0))


        # --- Strength Indicator ---
        self.strength_frame = ttk.Frame(master, padding="15")
        self.strength_frame.pack(fill="x", pady=(10, 0))

        ttk.Label(self.strength_frame, text="Strength:").pack(side="left")
        
        self.strength_label = ttk.Label(self.strength_frame, text="N/A", font=('Arial', 12, 'bold'))
        self.strength_label.pack(side="left", padx=5)

        self.strength_progress = ttk.Progressbar(self.strength_frame, orient="horizontal", length=200, mode="determinate")
        self.strength_progress.pack(side="left", fill="x", expand=True)

        # --- Criteria Display Frame ---
        self.criteria_frame = ttk.Frame(master, padding="15")
        self.criteria_frame.pack(fill="both", expand=True)

        ttk.Label(self.criteria_frame, text="Criteria:", font=('Arial', 10, 'bold')).pack(anchor="w", pady=(0, 5))

        self.length_label = ttk.Label(self.criteria_frame, text="Minimum 8 characters (❌)")
        self.length_label.pack(anchor="w")

        self.uppercase_label = ttk.Label(self.criteria_frame, text="Contains uppercase letters (❌)")
        self.uppercase_label.pack(anchor="w")

        self.lowercase_label = ttk.Label(self.criteria_frame, text="Contains lowercase letters (❌)")
        self.lowercase_label.pack(anchor="w")

        self.number_label = ttk.Label(self.criteria_frame, text="Contains numbers (❌)")
        self.number_label.pack(anchor="w")

        self.special_char_label = ttk.Label(self.criteria_frame, text="Contains special characters (❌)")
        self.special_char_label.pack(anchor="w")

        # Initialize check
        self.check_password_strength()

    def toggle_password_visibility(self):
        """Toggles the 'show' property of the Entry widget."""
        if self.show_password_var.get():
            # If checkbox is checked (True), show the text
            self.password_entry.config(show="")
        else:
            # If checkbox is unchecked (False), hide the text with '*'
            self.password_entry.config(show="*")
            
    def update_criteria_label(self, label, condition, text_if_true, text_if_false):
        """Helper to update criteria labels with checkmarks or crosses and colors."""
        if condition:
            label.config(text=f"{text_if_true} (✅)", foreground="green")
            return 1
        else:
            label.config(text=f"{text_if_false} (❌)", foreground="red")
            return 0

    def check_password_strength(self, event=None):
        """Assesses password strength based on various criteria."""
        password = self.password_entry.get()
        score = 0
        
        # --- Criteria Checks ---
        
        # 1. Length (at least 8 characters)
        has_min_length = len(password) >= 8
        score += self.update_criteria_label(self.length_label, has_min_length,
                                            "Minimum 8 characters", "Minimum 8 characters")

        # 2. Uppercase Letters
        has_uppercase = bool(re.search(r'[A-Z]', password))
        score += self.update_criteria_label(self.uppercase_label, has_uppercase,
                                            "Contains uppercase letters", "Contains uppercase letters")

        # 3. Lowercase Letters
        has_lowercase = bool(re.search(r'[a-z]', password))
        score += self.update_criteria_label(self.lowercase_label, has_lowercase,
                                            "Contains lowercase letters", "Contains lowercase letters")

        # 4. Numbers
        has_number = bool(re.search(r'[0-9]', password))
        score += self.update_criteria_label(self.number_label, has_number,
                                            "Contains numbers", "Contains numbers")

        # 5. Special Characters (using a common set)
        has_special_char = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?`~]', password))
        score += self.update_criteria_label(self.special_char_label, has_special_char,
                                            "Contains special characters", "Contains special characters")

        # --- Determine Overall Strength ---
        strength_text = "Very Weak"
        strength_color = "red"
        
        if score == 5:
            strength_text = "Excellent"
            strength_color = "green"
        elif score >= 4:
            strength_text = "Strong"
            strength_color = "darkgreen"
        elif score >= 3:
            strength_text = "Medium"
            strength_color = "orange"
        elif score >= 1:
            strength_text = "Weak"
            strength_color = "red"
        
        if not password: # If password field is empty
            strength_text = "N/A"
            strength_color = "grey"
            score = 0 # Reset score for progress bar

        self.strength_label.config(text=strength_text, foreground=strength_color)
        self.strength_progress['value'] = (score / 5) * 100

# --- Main Application Start ---
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthChecker(root)
    root.mainloop()
