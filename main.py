import random
import hashlib
import json
from tkinter import *
from tkinter import messagebox
                                                                                                                                                                                                                                                                                                   
letters_uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
letters_lowercase = "abcdefghijklmnopqrstuvwxyz"
numbers = "0123456789"
special_characters = "!@#$%^&*"
def request_password_length():
    def validate_length_and_generate():
        try:
            length = int(entry_length.get())
            if 8 <= length <= 15:
                generate_password(length)
            else:
                messagebox.showwarning("Error", "Length must be between 8 and 15.")
        except ValueError:
            messagebox.showwarning("Error", "Please enter a valid number.")
        password_length_window.destroy()
    
    password_length_window = Toplevel(window)
    password_length_window['bg'] = '#F6A2B7'
    password_length_window.title("Password Length")

    label_length = Label(password_length_window, text="Please enter the password length:", font='fixedsys', bg='#F6A2B7', fg='white')
    label_length.pack(pady=1)

    entry_length = Entry(password_length_window)
    entry_length.pack()

    button_validate_length = Button(password_length_window, text="Validate", command=validate_length_and_generate, bg='#E03E59', fg='white')
    button_validate_length.pack(pady=10)

# Modify the generate_password function to accept a length parameter
def generate_password(length=None):
    if length is None:
        length = random.randint(8, 15)
    password = ''.join(random.choices(letters_uppercase + letters_lowercase + numbers + special_characters, k=length))
    password_entry.delete(0, END)
    password_entry.insert(0, password)
    password_check(password)

def password_check(password):
    # Verify password requirements and update labels' colors accordingly
    length_label.config(fg='green' if len(password) >= 8 else 'red')
    uppercase_label.config(fg='green' if any(c in letters_uppercase for c in password) else 'red')
    lowercase_label.config(fg='green' if any(c in letters_lowercase for c in password) else 'red')
    digit_label.config(fg='green' if any(c in numbers for c in password) else 'red')
    special_label.config(fg='green' if any(c in special_characters for c in password) else 'red')


def checkbox_hide_password():
    if password_show_var.get() == 0:
        password_entry.config(show='•')
    else:
        password_entry.config(show='')

def hashing(password):
    # Hash the password using SHA-256
    hash_obj = hashlib.sha256(password.encode('utf-8'))
    return hash_obj.hexdigest()

def save_to_json(username, hashed_password):
    # Path to the JSON file
    filename = "user_credentials.json"
    # Initialize data as an empty dictionary
    data = {}
    try:
        # Try to read the file if it exists
        with open(filename, "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        # If the file does not exist or is empty/corrupted, initialize data as empty
        print("File not found or empty. A new file will be created.")
    
    # Update the dictionary with the new username and hashed password
    data[username] = hashed_password

    # Rewrite the JSON file with updated data
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

def user_exist(username):
    filename = "user_credentials.json"
    try:
        with open(filename, "r") as file:
            data = json.load(file)
            if username in data:
                return True
    except (FileNotFoundError, json.JSONDecodeError):
        return False
    return False
            
def password_exist(password):
    hashed_password = hashing(password)  
    filename = "user_credentials.json"
    try:
        with open(filename, "r") as file:
            data = json.load(file)
            if hashed_password in data.values():  #check if the password already exist
                return True
    except (FileNotFoundError, json.JSONDecodeError):
        return False
    return False
            
def password_conditions():
    if all([condition.cget('fg') == 'green' for condition in [length_label, uppercase_label, lowercase_label, digit_label, special_label]]):
        return True

def print_and_save():
    username = username_entry.get()
    password = password_entry.get()
    if user_exist(username):
        messagebox.showwarning("Error", "Username already exists. Please choose a different username.")
        return
    if password_exist(password):
        messagebox.showwarning("Error", "Choose another password")
        return
    if not password_conditions():
        messagebox.showwarning("Error", "Your password does not meet the necessary criteria.")
        return
    hashed_password = hashing(password)
    save_to_json(username, hashed_password)
    messagebox.showinfo("Success", "Your account has been created successfully!")


def password_settings():
    # Check password criteria and show success or error message
    password = password_entry.get()
    password_check(password)
    password_conditions()
    print_and_save()

def hash_password_window():
    # Display a window with hashed passwords from the JSON file
    try:
        with open("user_credentials.json", "r") as file:
            data = json.load(file)
            display_text = "".join(f"Username: {username}\nHashed Password: {hashed_password}\n" for username, hashed_password in data.items())
    except FileNotFoundError:
        messagebox.showerror("Error", "File not found.")
        return


    hashed_passwords_win = Toplevel()
    hashed_passwords_win.title("Hashed Passwords")
    hashed_passwords_win.config(background='#35374B')
    hashed_passwords_win.geometry("800x600")

    label1 = Label(hashed_passwords_win, text='Hashed Passwords', font=('Arial', 30), bg='#35374B', fg='#78A083')
    label1.pack(side=TOP, pady=10)

    text_widget = Text(hashed_passwords_win)
    text_widget.pack(padx=10, pady=10)
    text_widget.insert(END, display_text)
    text_widget.config(state=DISABLED)

    hashed_passwords_win.mainloop()
    
# Create the GUI window
window = Tk()
window.title("REGISTER")
window.geometry("1280x720")
window.minsize(640, 480)
window.config(background='#35374B')

password_show_var = IntVar(value=0)

# Title at the top of the window
title = Label(window, text="create an account", font=('Arial', 30), bg='#35374B', fg='#78A083')
title.pack(side=TOP)

# Frame for the password entry elements
frame = Frame(window, bg='#35374B', bd=1, relief=SUNKEN)
frame.pack(expand=YES)

# Username entry field
username = Label(frame, text="Username", font=('Arial', 15), bg='#35374B', fg='#78A083')
username.pack(pady=5, padx=5)
username_entry = Entry(frame, width=40, bg='white', fg='#78A083')
username_entry.pack(pady=5, padx=5)

# Password entry field
password_text = Label(frame, text="Password", font=('Arial', 15), bg='#35374B', fg='#78A083')
password_text.pack(pady=5, padx=5)
password_entry = Entry(frame, width=40, bg='white', fg='#78A083', show="•")
password_entry.pack(pady=5, padx=5)
password_show = Checkbutton(frame, text='show password', bg='#35374B', fg='#78A083', variable=password_show_var, onvalue=1, offvalue=0, command=checkbox_hide_password)
password_show.pack()

# Buttons for generating password and displaying hashed passwords
password_generator = Button(frame, text="Generate Password", bg='#78A083', fg='#35374B', command=request_password_length)
password_generator.pack(pady=5, padx=5, fill=X)

hashed_password_link = Button(frame, text="Show hashed passwords", bg='#78A083', fg='#35374B', command=hash_password_window)
hashed_password_link.pack(pady=5, padx=5, fill=X)

# Button to create account
creat_acc_btn = Button(frame, text="Create Account", bg='#78A083', fg='#35374B', command=password_settings)
creat_acc_btn.pack(pady=5, padx=5, fill=X)

# Labels for password criteria
conditions = Label(frame, text="The password requires at least:", bg='#35374B', fg='#78A083')
conditions.pack()
length_label = Label(frame, text="8 Minimum Characters", bg='#35374B', fg='red')
length_label.pack(side=LEFT)
uppercase_label = Label(frame, text="1 Uppercase", bg='#35374B', fg='red')
uppercase_label.pack(side=LEFT)
lowercase_label = Label(frame, text="1 Lowercase", bg='#35374B', fg='red')
lowercase_label.pack(side=LEFT)
digit_label = Label(frame, text="1 Digit", bg='#35374B', fg='red')
digit_label.pack(side=LEFT)
special_label = Label(frame, text="1 Special Character", bg='#35374B', fg='red')
special_label.pack(side=LEFT)

# Bind the password change event to the verification function
def on_password_change(event):
    password = password_entry.get()
    password_check(password)
password_entry.bind("<KeyRelease>", on_password_change)

# Keep the window running
window.mainloop()
