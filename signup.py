from tkinter import *
from PIL import ImageTk
from tkinter import messagebox
import tkinter as tk
from tkinter import ttk
import pymysql
import re
import hashlib

signup_window = Tk()
signup_window.geometry('970x640+50+50')
signup_window.title('Scan-Web-Vulns')
signup_window.resizable(False, False)
background = ImageTk.PhotoImage(file='img/bg.png')

def lSigninButton():
    signup_window.destroy()
    import login

def clear():
    usernameEntry.delete(0, END)
    emailEntry.delete(0, END)
    passwordEntry.delete(0, END)
    confirmpassEntry.delete(0, END)
    check.set(0)

def validate_password(password):
    if len(password) < 8 or len(password) > 12:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*]", password):
        return False
    return True

def encrypt_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def connect_database():
    if emailEntry.get() == '' or usernameEntry.get() == '' or passwordEntry.get() == '' or confirmpassEntry.get() == '':
        messagebox.showerror('Error', 'All Fields are required')

    elif passwordEntry.get() != confirmpassEntry.get():
        messagebox.showerror('Error', 'Both passwords do not match')

    elif check.get() == 0:
        messagebox.showerror('Error', 'Please Accept the Terms & Conditions')

    elif not validate_password(passwordEntry.get()):
        messagebox.showerror('Error', 'Password must be between 8 to 12 characters and include at least one uppercase letter, one lowercase letter, one number, and one special character (!@#$%^&*)')

    else:
        try:
            con = pymysql.connect(host='localhost', user='root', password='Dipclash789*', database='Scan_Web_Vulns')
            mycursor = con.cursor()
        except:
            messagebox.showerror('Error', 'Database connectivity issue, Please try again!')
            return

        try:
            query = 'CREATE TABLE IF NOT EXISTS userDetails(id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(100), email VARCHAR(50), password VARCHAR(64))'
            mycursor.execute(query)
        except:
            pass

        query = 'SELECT * FROM userDetails WHERE username=%s'
        mycursor.execute(query, (usernameEntry.get(),))

        row = mycursor.fetchone()
        if row is not None:
            messagebox.showerror('Error', 'Username already exists')

        else:
            encrypted_password = encrypt_password(passwordEntry.get())
            query = 'INSERT INTO userDetails(username, email, password) VALUES(%s, %s, %s)'
            mycursor.execute(query, (usernameEntry.get(), emailEntry.get(), encrypted_password))
            con.commit()
            con.close()
            messagebox.showinfo('Success', 'Registration is successful')
            clear()
            signup_window.destroy()
            import login

bgLabel = Label(signup_window, image=background)
bgLabel.place(x=0, y=0)

frame = Frame(signup_window, bg='white')
frame.place(x=558, y=103)

heading = Label(frame, text='CREATE AN ACCOUNT', font=('Microsoft Yahei UI Ligt', 18, 'bold'), bg='white', fg='black')
heading.grid(row=0, column=0, padx=10, pady=10)

usernameLabel = Label(frame, text='Username', font=('Microsoft Yahei UI Ligt', 10, 'bold'), bg='white')
usernameLabel.grid(row=1, column=0, sticky='w', padx=25, pady=(10, 0))

usernameEntry = Entry(frame, width=33, font=('Microsoft Yahei UI Ligt', 10, 'bold'))
usernameEntry.grid(row=2, column=0, sticky='w', padx=25)

emailLabel = Label(frame, text='Email', font=('Microsoft Yahei UI Ligt', 10, 'bold'), bg='white')
emailLabel.grid(row=3, column=0, sticky='w', padx=25, pady=(10, 0))

emailEntry = Entry(frame, width=33, font=('Microsoft Yahei UI Ligt', 10, 'bold'))
emailEntry.grid(row=4, column=0, sticky='w', padx=25)

# Password field

passwordLabel = Label(frame, text='Password', font=('Microsoft Yahei UI Ligt', 10, 'bold'), bg='white')
passwordLabel.grid(row=5, column=0, sticky='w', padx=25, pady=(10, 0))

passwordEntry = Entry(frame, width=33, font=('Microsoft Yahei UI Ligt', 10, 'bold'))
passwordEntry.grid(row=6, column=0, sticky='w', padx=25)

# confirm password field

confirmpassLabel = Label(frame, text='Confirm Password', font=('Microsoft Yahei UI Ligt', 10, 'bold'), bg='white')
confirmpassLabel.grid(row=7, column=0, sticky='w', padx=25, pady=(10, 0))

confirmpassEntry = Entry(frame, width=33, font=('Microsoft Yahei UI Ligt', 10, 'bold'))
confirmpassEntry.grid(row=8, column=0, sticky='w', padx=25)

check = IntVar()
termsandconditions = Checkbutton(frame, text='I Agree to the Term & Conditions', font=('Microsoft Yahei UI Ligt', 10, 'bold'), bg='white', cursor='hand2', variable=check)
termsandconditions.grid(row=9, column=0, pady=15, padx=2)

signupButton = Button(frame, text='Sign Up', font=('Open Sans', 16, 'bold'), border=0, fg='white', bg='black', bd=0, width=14, command=connect_database)
signupButton.grid(row=10, column=0)

accountholder = Label(frame, text='Have an account?', font=('Open Sans', 9, 'bold'), bg='white', width=15)
accountholder.grid(row=11, column=0, sticky='w', padx=50, pady=15)

signinButton = Button(frame, text='Log In', font=('Open Sans', 9, 'bold underline'), bg='white', fg='blue', bd=0, cursor='hand2', activebackground='white', activeforeground='blue', width=5, command=lSigninButton)
signinButton.place(x=163, y=372)

signup_window.mainloop()
