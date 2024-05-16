from tkinter import *
from PIL import ImageTk
from tkinter import messagebox
import tkinter as tk
from tkinter import ttk
import pymysql
import hashlib
import time

# Global variables to track login attempts and lockout time
login_attempts = 0
lockout_time = 30  # Lockout time in seconds

def hidepass():
    openeye.config(file='img/closeye.png')
    code.config(show='*')
    eyeButton.config(command=showpass)

def showpass():
    openeye.config(file='img/openeye.png')
    code.config(show='')
    eyeButton.config(command=hidepass)

def signin_button():
    global login_attempts

    # Get the username and password inputs
    username = user.get()
    password = code.get()

    # Check if all fields are filled

    if username == '' or password == '':
        messagebox.showerror('Error', 'All fields are required')
    else:
        # connect to database
        try:
            con = pymysql.connect(host='localhost', user='root', password='Dipclash789*', database='Scan_Web_Vulns')
            mycursor = con.cursor()
        except:
            messagebox.showerror('Error', 'Database connectivity issue, Please try again!')
            return

        # Using parameterized query to prevent SQL injection
        query = 'SELECT * FROM userdetails WHERE username = %s'
        mycursor.execute(query, (username,))
        row = mycursor.fetchone()

        if row is None:
            login_attempts += 1
            if login_attempts == 3:
                messagebox.showerror('Error', 'Too many incorrect login attempts. Please try again later.')
                loginButton.config(state=DISABLED)  # Disable login button
                root.after(1000 * lockout_time, enable_login_button)  # Re-enable login button after lockout time
            else:
                messagebox.showerror('Error', 'Invalid Username or Password')
        else:
            stored_password = row[3]  # Password is saved in 4th column

            # Hash the user-provided password
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            # Compare the hashed passwords
            if hashed_password != stored_password:
                login_attempts += 1
                if login_attempts == 3:
                    messagebox.showerror('Error', 'Too many incorrect login attempts. Please try again later.')
                    loginButton.config(state=DISABLED)  # Disable login button
                    root.after(1000 * lockout_time, enable_login_button)  # Re-enable login button after lockout time
                else:
                    messagebox.showerror('Error', 'Invalid Username or Password')
            else:
                messagebox.showinfo('Welcome', 'Login successful!')
                login_attempts = 0  # Reset login attempts counter
                root.destroy()
                create_main_window()

def enable_login_button():
    global login_attempts
    login_attempts = 0  # Reset login attempts counter
    loginButton.config(state=NORMAL)  # Re-enable login button

def signup_button():
    root.destroy()
    import signup

def create_main_window():
    import main

root = Tk()
root.geometry('950x640+50+50')
root.resizable(0, 0)
root.title('Scan-Web-Vulns')
bgImage = ImageTk.PhotoImage(file='img/bg.png')


bgLabel = Label(root, image=bgImage)
bgLabel.place(x=-5, y=0)

heading = Label(root, text='USER LOGIN', font=('Microsoft Yahei UI Ligt', 18, 'bold')
                , bg='white', fg='black')
heading.place(x=620, y=120)


def on_enter(e):
    user.delete(0, 'end')


def on_leave(e):
    name = user.get()
    if name == '':
        user.insert(0, 'Username')


user = Entry(root, width=25, fg='black', border=0, bg='white', font=('Microsoft YaHei UI Light', 11))
user.place(x=588, y=190)
user.insert(0, 'Username')
user.bind('<FocusIn>', on_enter)
user.bind('<FocusOut>', on_leave)

Frame(root, width=230, height=2, bg='black').place(x=588, y=215)


def on_enter(e):
    code.delete(0, 'end')


def on_leave(e):
    name = code.get()
    if name == '':
        code.insert(0, 'Password')


code = Entry(root, width=25, fg='black', border=0, bg='white', font=('Microsoft YaHei UI Light', 11))
code.place(x=588, y=250)
code.insert(0, 'Password')
code.bind('<FocusIn>', on_enter)
code.bind('<FocusOut>', on_leave)

Frame(root, width=230, height=2, bg='black').place(x=588, y=275)

openeye = PhotoImage(file='img/openeye.png')
eyeButton = Button(root, image=openeye, bd=0, bg='white', activebackground='white', command=hidepass)
eyeButton.place(x=788, y=248)

forgetButton = Button(root, text='Forgot Password?', bd=0, bg='white', activebackground='white', font=('Microsoft YaHei UI Light', 8, 'bold'))
forgetButton.place(x=705, y=298)

loginButton = Button(root, text='Login', bg='black', fg='white', font=('Open Sans', 16, 'bold'), width=15, activebackground='black', activeforeground='white', command=signin_button)
loginButton.place(x=600, y=350)

facebook_logo = PhotoImage(file='img/facebook.png')
fbLabel = Button(root, image=facebook_logo, bg='white', bd=0, fg='white')
fbLabel.place(x=640, y=440)

google_logo = PhotoImage(file='img/google.png')
googleLabel = Button(root, image=google_logo, bg='white', bd=0, fg='white')
googleLabel.place(x=690, y=440)

twitter_logo = PhotoImage(file='img/twitter.png')
twitterLabel = Button(root, image=twitter_logo, bg='white', bd=0, fg='white')
twitterLabel.place(x=740, y=440)

signupLabel = Label(root, text="Don't have an account?", font=('Open Sans', 9, 'bold'), bg='white')
signupLabel.place(x=595, y=500)

signupButton = Button(root, text="Create Account", font=('Open Sans', 9, 'bold underline'), bg='white', fg='blue', bd=0, command=signup_button)
signupButton.place(x=730, y=500)

root.mainloop()
