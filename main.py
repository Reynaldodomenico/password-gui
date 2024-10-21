from tkinter import *
from tkinter import messagebox
from random import choice, randint, shuffle
import pyperclip
from cryptography.fernet import Fernet
import os

# ---------------------------- ENCRYPTION SETUP ------------------------------- #
def load_or_create_key():
    """ Load or create an encryption key. """
    if not os.path.exists("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
    else:
        with open("key.key", "rb") as key_file:
            key = key_file.read()
    return key

def load_or_create_master_password():
    """ Load or create the master password. """
    if not os.path.exists("master_password.txt"):
        return None
    else:
        with open("master_password.txt", "rb") as master_file:
            encrypted_password = master_file.read()
            return fer.decrypt(encrypted_password).decode()

def save_master_password(master_password):
    """ Encrypt and save the master password. """
    encrypted_password = fer.encrypt(master_password.encode())
    with open("master_password.txt", "wb") as master_file:
        master_file.write(encrypted_password)

key = load_or_create_key()
fer = Fernet(key)
master_password = load_or_create_master_password()

# ---------------------------- PASSWORD GENERATOR ------------------------------- #
def generate_password():
    """ Generate a random password and insert it into the password entry field. """
    letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    numbers = '0123456789'
    symbols = '!#$%&()*+'

    password_letters = [choice(letters) for _ in range(randint(8, 10))]
    password_symbols = [choice(symbols) for _ in range(randint(2, 4))]
    password_numbers = [choice(numbers) for _ in range(randint(2, 4))]

    password_list = password_letters + password_symbols + password_numbers
    shuffle(password_list)

    password = "".join(password_list)
    password_entry.insert(0, password)
    pyperclip.copy(password)

# ---------------------------- SAVE PASSWORD ------------------------------- #
def save():
    """ Save the password for the given website and email. """
    website = website_entry.get()
    email = email_entry.get()
    password = password_entry.get()

    if len(website) == 0 or len(password) == 0:
        messagebox.showinfo(title="Oops", message="Please make sure you haven't left any fields empty.")
    else:
        is_ok = messagebox.askokcancel(title=website, message=f"These are the details entered: \nEmail: {email} "
                                                              f"\nPassword: {password} \nIs it ok to save?")
        if is_ok:
            encrypted_password = fer.encrypt(password.encode()).decode()
            with open("data.txt", "a") as data_file:
                data_file.write(f"{website} | {email} | {encrypted_password}\n")
            website_entry.delete(0, END)
            password_entry.delete(0, END)

# ---------------------------- COPY PASSWORD FUNCTION ------------------------------- #
def copy_password_to_clipboard(password):
    """ Copy the given password to the clipboard. """
    pyperclip.copy(password)
    messagebox.showinfo(title="Copied", message="Password copied to clipboard.")

def delete_password(website, email, encrypted_password):
    """ Delete a password entry based on the website, email, and encrypted password. """
    try:
        with open("data.txt", "r") as data_file:
            lines = data_file.readlines()
    except FileNotFoundError:
        messagebox.showinfo(title="Error", message="No data file found.")
        return

    with open("data.txt", "w") as data_file:
        for line in lines:
            if line.strip() != f"{website} | {email} | {encrypted_password}":
                data_file.write(line)

    messagebox.showinfo(title="Deleted", message=f"Password for {website} has been deleted.")
    view_passwords() 

# ---------------------------- VIEW PASSWORDS GUI ------------------------------- #
def view_passwords():
    """ View all saved passwords. """
    try:
        with open("data.txt", "r") as data_file:
            data = data_file.readlines()
    except FileNotFoundError:
        messagebox.showinfo(title="Error", message="No data file found.")
        return

    view_window = Toplevel()
    view_window.title("Stored Passwords")
    view_window.geometry("600x400")

    row = 0
    for line in data:
        website, email, encrypted_password = line.strip().split(" | ")
        decrypted_password = fer.decrypt(encrypted_password.encode()).decode()

        Label(view_window, text=f"Website: {website} | Email: {email}", anchor="w").grid(row=row, column=0, padx=10, pady=5, sticky="w")
        Label(view_window, text=f"Password: {decrypted_password}", anchor="w").grid(row=row, column=1, padx=10, pady=5, sticky="w")

        copy_button = Button(view_window, text="Copy", command=lambda pwd=decrypted_password: copy_password_to_clipboard(pwd))
        copy_button.grid(row=row, column=2, padx=10, pady=5)

        delete_button = Button(view_window, text="Delete", command=lambda w=website, e=email, ep=encrypted_password: delete_password(w, e, ep))
        delete_button.grid(row=row, column=3, padx=10, pady=5)

        row += 1

# ---------------------------- RESET FUNCTION ------------------------------- #
def reset():
    """ Reset the application by deleting all data and the master password. """
    confirm = messagebox.askyesno(title="Reset Confirmation", message="Are you sure you want to reset?\nThis will delete all saved passwords and reset the master password.")
    if confirm:
        if os.path.exists("data.txt"):
            os.remove("data.txt")
        if os.path.exists("master_password.txt"):
            os.remove("master_password.txt") 
        if os.path.exists("key.key"):
            os.remove("key.key") 
        messagebox.showinfo(title="Reset", message="All passwords and the master password have been deleted.")
        window.destroy()

# ---------------------------- MAIN PASSWORD MANAGER GUI ------------------------------- #
def open_password_manager():
    """ Open the main password manager window. """
    global website_entry, password_entry, email_entry

    for widget in window.winfo_children():
        widget.destroy()

    window.title("ShieldPass - Password Manager")
    window.config(padx=20, pady=20)
    canvas = Canvas(window, height=400, width=400)

    try:
        logo_img = PhotoImage(file="SHIELDPASS_LOGO.png")
        canvas.create_image(200, 200, image=logo_img)
        canvas.image = logo_img  
    except TclError as e:
        print(f"Error loading image: {e}")
    canvas.grid(row=0, column=1)

    website_label = Label(window, text="Website:")
    website_label.grid(row=1, column=0, sticky="w", padx=5, pady=5)
    
    email_label = Label(window, text="Email/Username:")
    email_label.grid(row=2, column=0, sticky="w", padx=5, pady=5)
    
    password_label = Label(window, text="Password:")
    password_label.grid(row=3, column=0, sticky="w", padx=5, pady=5)

    website_entry = Entry(window, width=35)
    website_entry.grid(row=1, column=1, columnspan=2)
    website_entry.focus()
    
    email_entry = Entry(window, width=35)
    email_entry.grid(row=2, column=1, columnspan=2)
    email_entry.insert(0, "user@example.com")
    
    password_entry = Entry(window, width=35)
    password_entry.grid(row=3, column=1, columnspan=2, padx=(0, 10)) 

    generate_password_button = Button(window, text="Generate Password", command=generate_password)
    generate_password_button.grid(row=3, column=2, padx=(0, 10))
    
    add_button = Button(window, text="Add", width=36, command=save)
    add_button.grid(row=4, column=1, columnspan=2)
    
    view_button = Button(window, text="View Passwords", width=36, command=view_passwords)
    view_button.grid(row=6, column=1, columnspan=2)

# ---------------------------- MASTER PASSWORD CHECK ------------------------------- #
def check_master_password():
    """ Check the master password and open the password manager if correct. """
    global master_password

    entered_password = master_password_entry.get()

    if master_password is None:
        if len(entered_password) == 0:
            messagebox.showerror("Error", "Please set a master password.")
        else:
            save_master_password(entered_password)
            master_password = entered_password
            messagebox.showinfo("Success", "Master password has been set!")
            open_password_manager()
    else:
        if entered_password == master_password:
            open_password_manager()
        else:
            messagebox.showerror("Error", "Incorrect master password.")

# ---------------------------- UI SETUP FOR MASTER PASSWORD ------------------------------- #
window = Tk()
window.title("ShieldPass - Master Password")
window.config(padx=50, pady=50)

master_password_label = Label(window, text="Enter Master Password:" if master_password else "Set a Master Password:")
master_password_label.grid(row=0, column=0)

master_password_entry = Entry(window, width=35, show="*")
master_password_entry.grid(row=0, column=1)
master_password_entry.focus()

submit_button = Button(window, text="Submit", command=check_master_password)
submit_button.grid(row=1, column=1)

reset_button = Button(window, text="Forgot Master Password (Reset)", command=reset)
reset_button.grid(row=2, column=1)

window.mainloop()
