import tkinter as tk
import customtkinter
import socket
import pymysql
from PIL import Image, ImageTk
from tkinter import messagebox, ttk, scrolledtext, colorchooser
import os
from censys.search import CensysCerts
from censys.common.exceptions import (
    CensysUnauthorizedException,
    CensysRateLimitExceededException,
    CensysException,
)
import requests
import bs4
import threading

# Home window geometry

root = tk.Tk()
style = ttk.Style()
style.configure('Content.TFrame', background='#1e2739')
root.title("Scan-Web-Vulns")
root.geometry('950x720+70+70')

root.grid_rowconfigure((0, 1, 2), weight=5)

# Sidebar - Home, Port scan, Vulnerability scan, Sub Domain scan button, profile and settings button

def create_sidebar_buttons(sidebar, home_content, nscan_content, vscan_content, sdcan_content, profile_content, settings_content):
    home_button = customtkinter.CTkButton(sidebar, text="Home", command=lambda: show_content(home_content), width=150)
    home_button.grid(row=0, column=0, pady=(20, 10), padx=10, sticky="ew")

    nscan_button = customtkinter.CTkButton(sidebar, text="Port Scan", command=lambda: show_nscan_content(nscan_content),
                                           width=150)
    nscan_button.grid(row=1, column=0, pady=25, padx=10, sticky="ew")

    vscan_button = customtkinter.CTkButton(sidebar, text="Vulnerability Scan", command=lambda: show_vscan_content(vscan_content),
                                           width=150)
    vscan_button.grid(row=2, column=0, pady=10, padx=10, sticky="ew")

    sdcan_button = customtkinter.CTkButton(sidebar, text="Sub Domain Scan",
                                           command=lambda: show_sdcan_content(sdcan_content),
                                           width=150)
    sdcan_button.grid(row=3, column=0, pady=(25, 5), padx=10, sticky="ew")

    profile_button = customtkinter.CTkButton(sidebar, text="Profile",
                                             command=lambda: show_profile_content(profile_content),
                                             compound="left", width=150)
    profile_button.grid(row=4, column=0, pady=(350, 5), padx=10, sticky="ew")

    settings_button = customtkinter.CTkButton(sidebar, text="Settings", command=lambda: show_content(settings_content),
                                              width=150)
    settings_button.grid(row=5, column=0, pady=(5, 20), padx=10, sticky="ew")


def show_content(content):
    home_content.grid_remove()
    nscan_content.grid_remove()
    vscan_content.grid_remove()
    sdcan_content.grid_remove()
    profile_content.grid_remove()
    settings_content.grid_remove()
    content.grid(row=0, column=0, sticky="nsew")

    # Show settings buttons only when settings content is displayed
    if content == settings_content:
        show_settings_buttons()
    else:
        hide_settings_buttons()

def show_settings_buttons():
    logout_button.grid(row=0, column=0, pady=(580, 250), padx=530, sticky="ew")

def hide_settings_buttons():
    logout_button.grid_forget()

# Show the content of the Port scan window
def show_nscan_content(content):
    home_content.grid_remove()
    nscan_content.grid_remove()
    vscan_content.grid_remove()
    sdcan_content.grid_remove()
    profile_content.grid_remove()
    settings_content.grid_remove()

    nscan_content.grid(row=0, column=0, sticky="nsew")
    create_nscan_interface(nscan_content)

# Show the content of the Vulnerability scan window
def show_vscan_content(content):
    home_content.grid_remove()
    nscan_content.grid_remove()
    vscan_content.grid_remove()
    sdcan_content.grid_remove()
    profile_content.grid_remove()
    settings_content.grid_remove()

    vscan_content.grid(row=0, column=0, sticky="nsew")
    create_vscan_interface(vscan_content)

# Show the content of the Sub Domain scan window
def show_sdcan_content(content):
    home_content.grid_remove()
    nscan_content.grid_remove()
    vscan_content.grid_remove()
    sdcan_content.grid_remove()
    profile_content.grid_remove()
    settings_content.grid_remove()

    sdcan_content.grid(row=0, column=0, sticky="nsew")
    create_sdcan_interface(sdcan_content)

# Show the content of the Profile window
def show_profile_content(profile_content):
    home_content.grid_remove()
    nscan_content.grid_remove()
    vscan_content.grid_remove()
    sdcan_content.grid_remove()
    profile_content.grid_remove()
    settings_content.grid_remove()
    profile_content.grid(row=0, column=0, sticky="nsew")

# Port Scanning Interface and its applications
def create_nscan_interface(parent):
    # Create frame to hold scanning interface
    scan_frame = customtkinter.CTkFrame(parent, bg_color='black', border_color='black', border_width=10)
    scan_frame.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)

    # Add heading for the port scanning
    scan_heading = tk.Label(scan_frame, text="Scan for Open Ports", font=("Arial", 20), bg='black', fg='white')
    scan_heading.grid(row=0, column=0, columnspan=3, pady=10, padx=50)

    # Create input fields
    host_label = tk.Label(scan_frame, text="Enter IP Address or Domain Name:")
    host_label.grid(row=1, column=0, sticky="w", padx=25)

    def on_host_entry_click(event):
        if host_entry.get() == "Enter IP Address or Domain Name:":
            host_entry.delete(0, tk.END)
            host_entry.config(fg="white")  # Change text color to black

    host_entry = tk.Entry(scan_frame, width=35)
    host_entry.insert(0, "Enter IP Address or Domain Name:")  # Placeholder text
    host_entry.config(fg="white")  # Set text color to grey
    host_entry.bind("<FocusIn>", on_host_entry_click)  # Bind the function to the entry field
    host_entry.grid(row=1, column=1, padx=20, pady=5)

    start_port_label = tk.Label(scan_frame, text="Enter Start Port:")
    start_port_label.grid(row=2, column=0, sticky="w", padx=25)
    start_port_entry = tk.Entry(scan_frame, width=35)
    start_port_entry.grid(row=2, column=1, padx=20, pady=5)

    end_port_label = tk.Label(scan_frame, text="Enter End Port:")
    end_port_label.grid(row=3, column=0, sticky="w", padx=25)
    end_port_entry = tk.Entry(scan_frame, width=35)
    end_port_entry.grid(row=3, column=1, padx=20, pady=5)

    result_text = scrolledtext.ScrolledText(scan_frame, width=60, height=20)
    result_text.grid(row=4, column=0, columnspan=3, padx=20, pady=5)

    # Function to start scanning when button is clicked
    def start_scan():
        host = host_entry.get()
        startPort = int(start_port_entry.get())
        endPort = int(end_port_entry.get())
        threading.Thread(target=scanHost, args=(host, startPort, endPort, result_text)).start()

    # Create scan button
    scan_button = tk.Button(scan_frame, text="Start Scan", command=start_scan)
    scan_button.place(x=20, y=500)

    # Create clear button
    clear_button = tk.Button(scan_frame, text="Clear Results", command=lambda: clear_result(result_text))
    clear_button.place(x=100, y=500)

    # Function to clear the result text
    def clear_result(result_text):
        result_text.delete(1.0, tk.END)

    # Function to generate the report
    def generate_report():
        report_content = result_text.get(1.0, tk.END)
        save_report_to_file(report_content)

    # Create the "Generate Report" button
    report_button = tk.Button(scan_frame, text="Generate Report", command=generate_report)
    report_button.grid(row=5, column=2, padx=(10, 20), pady=20)


def scanHost(host, startPort, endPort, result_text):
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        result_text.insert(tk.END, "Invalid host or domain name.\n")
        return

    result_text.insert(tk.END, '[*] Starting TCP port scan on host %s\n' % ip)
    # Begin TCP scan on host
    tcp_scan(ip, startPort, endPort, result_text)
    result_text.insert(tk.END, '[+] TCP scan on host %s complete\n' % ip)


def scanRange(network, startPort, endPort, result_text):
    result_text.insert(tk.END, '[*] Starting TCP port scan on network %s.0\n' % network)
    for host in range(1, 255):
        ip = network + '.' + str(host)
        tcp_scan(ip, startPort, endPort, result_text)

    result_text.insert(tk.END, '[+] TCP scan on network %s.0 complete\n' % network)


def tcp_scan(ip, startPort, endPort, result_text):
    for port in range(startPort, endPort + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
                tcp.settimeout(0.02)  # Set a shorter timeout
                if tcp.connect_ex((ip, port)) == 0:
                    result_text.insert(tk.END, '[+] %s:%d/TCP Open\n' % (ip, port))
        except Exception:
            pass

# Vulnerability Scanning Interface and its applications

def create_vscan_interface(parent):
    # Create frame to hold scanning interface
    scan_frame = customtkinter.CTkFrame(parent, bg_color='black', border_color='black', border_width=10)
    scan_frame.grid(row=0, column=1, sticky="nsew", padx=0)
    # Align to the center
    parent.grid_columnconfigure(0, weight=1)
    parent.grid_rowconfigure(0, weight=1)

    # Add the heading for Vulnerability Scan
    vscan_heading = tk.Label(scan_frame, text="Scan for Vulnerabilities", font=("Arial", 20), bg='black', fg='white')
    vscan_heading.grid(row=0, column=0, columnspan=2, pady=10, padx=50)

    # Create input fields
    url_label = tk.Label(scan_frame, text="Enter Target URL:")
    url_label.grid(row=1, column=0, sticky="w", padx=20)

    def on_url_entry_click(event):
        if url_entry.get() == "https://www.example.com":
            url_entry.delete(0, tk.END)
            url_entry.config(fg="white")  # Change text color to black

    url_entry = tk.Entry(scan_frame, width=53)
    url_entry.grid(row=1, column=1, padx=0, pady=5)
    url_entry.place(x=120, y=58)
    url_entry.insert(0, "https://www.example.com")  # Placeholder text
    url_entry.config(fg="white")  # Set text color to grey
    url_entry.bind("<FocusIn>", on_url_entry_click)  # Bind the function to the entry field

    result_text = scrolledtext.ScrolledText(scan_frame, width=60, height=20)
    result_text.grid(row=2, column=0, columnspan=2, padx=20, pady=5)

    # Function to clear the result text
    def clear_result(result_text):
        result_text.config(state="normal")
        result_text.delete(1.0, tk.END)
        result_text.config(state="disabled")

    # Disable insecure request warnings
    requests.packages.urllib3.disable_warnings()

    # Create scan button
    scan_button = tk.Button(scan_frame, text="Start Scan",
                            command=lambda: start_scan(url_entry.get(), result_text))
    # scan_button.grid(row=3, column=0, columnspan=2, pady=10)
    scan_button.place(x=20, y=430)

    # Create clear button
    clear_button = tk.Button(scan_frame, text="Clear Results", command=lambda: clear_result(result_text))
    # clear_button.grid(row=4, column=0, columnspan=2, pady=15)
    clear_button.place(x=100, y=430)

    # Function to generate the report
    def generate_report():
        report_content = result_text.get(1.0, tk.END)
        save_report_to_file(report_content)

    # Create the "Generate Report" button
    report_button = tk.Button(scan_frame, text="Generate Report", command=generate_report)
    report_button.grid(row=5, column=1, padx=10, pady=20)


    def update_result_text(text_widget, message):
        text_widget.insert(tk.END, message + "\n")

    def start_scan(url, result_text):
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return

        # Add http:// if not present in the URL
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url

        # Clear previous results
        result_text.delete(1.0, tk.END)

        # Disable the scan button during scanning
        scan_button.config(state=tk.DISABLED)

        # Update the button text with an animated ellipsis
        animate_scan_button()

        # Perform vulnerability testing in a separate thread
        threading.Thread(target=perform_scan, args=(url, result_text)).start()

    # Function to animate the scan button text
    def animate_scan_button():
        scan_button.config(text="Scanning")
        root.after(300, lambda: scan_button.config(text="Scanning."))
        root.after(600, lambda: scan_button.config(text="Scanning.."))
        root.after(900, lambda: scan_button.config(text="Scanning..."))
        # Continue the animation recursively
        root.after(1200, animate_scan_button)

    # Function to perform vulnerability testing
    def perform_scan(url, result_text):
        try:
            result_text.insert(tk.END, "Starting vulnerability scan...\n")
            result_text.update_idletasks()  # Update the GUI to show the message

            result_text.insert(tk.END, "Testing Reflected XSS...\n")
            result_text.update_idletasks()
            reflected_xss_test(url, result_text)

            result_text.insert(tk.END, "Testing SQL Injection...\n")
            result_text.update_idletasks()
            sql_injection_test(url, result_text)

            result_text.insert(tk.END, "Testing LFI...\n")
            result_text.update_idletasks()
            rce_test(url, result_text)

            result_text.insert(tk.END, "Vulnerability scan completed for URL: " + url + "\n")
        except Exception as e:
            result_text.insert(tk.END, "An error occurred during scanning: " + str(e) + "\n")
        finally:
            # Re-enable the scan button after scanning is complete
            scan_button.config(state=tk.NORMAL)

    # Function to test for Reflected XSS vulnerability
    def reflected_xss_test(url, result_text):
        response_data = requests.get(url, verify=False)
        if response_data is None:
            result_text.insert(tk.END, "Error: No response data received from the server.\n")
            return

        response_text = response_data.text
        potential_xss = []

        # Open the XSS payload file and iterate through each payload
        with open("payload/xss.txt", encoding="utf-8") as file:
            xss_tests = file.readlines()

        try:
            host_base, host_ext = url.split('?')
            host_base = host_base + "?"
        except:
            host_base = url

        parse = bs4.BeautifulSoup(response_text, 'html.parser')
        all_forms = parse.find_all('form')
        if all_forms:
            for payload in xss_tests:
                testload = payload.strip()
                for form in all_forms:
                    if any(field_name in form for field_name in
                           ["username", "name", "user", "client", "account", "accountname", "id", "userid", "query",
                            "search", "textfile", "file", "subject", "comment", "email", "contact", "input"]):
                        login_form = form
                        login_action = login_form.get('action')
                        login_method = login_form.get('method')
                        form_fields = form.findAll('input')
                        form_fields = form_fields + form.findAll('select')
                        form_data = dict((field.get('name'), field.get('value')) for field in form_fields)

                        for key, value in form_data.items():
                            form_data_modded = form_data.copy()
                            form_data_modded[key] = testload
                            if (("get") in login_method) or (("GET") in login_method):
                                get_request = requests.get(host_base, params=form_data_modded, verify=False)
                                get_data = get_request.text
                                parse_get = bs4.BeautifulSoup(get_data, 'html5lib')
                                if ("alert(\"KOALA\")" or r"alert(\"KOALA\")") in str(parse_get):
                                    potential_xss.append(str(get_request.url))
                            elif (("post") in login_method) or (("POST") in login_method):
                                post_request = requests.post(url, data=form_data_modded, verify=False)
                                post_data = post_request.text
                                parse_post = bs4.BeautifulSoup(post_data, 'html5lib')
                                if ("alert(\"KOALA\")" or "alert(\\\"KOALA\\\")") in str(parse_post):
                                    potential_xss.append(str(post_request.url))
        if potential_xss:
            result_text.insert(tk.END, "Potential Reflected XSS vulnerabilities found:\n")
            for url in potential_xss:
                result_text.insert(tk.END, url + "\n")
        else:
            result_text.insert(tk.END, "No Reflected XSS vulnerabilities found.\n")

    def sql_injection_test(url, result_text):
        try:
            response_data = requests.get(url, verify=False)
            if response_data is None:
                result_text.insert(tk.END, "Error: No response data received from the server.\n")
                return

            response_text = response_data.text
            potential_sql = []
            sql_tests = []
            file = open("payload/sql.txt", encoding="utf-8")
            sql_tests_pre = file.readlines()
            for test in sql_tests_pre:
                test = test.strip()
                sql_tests.append(test)
            total_params = []
            try:
                host_base, host_ext = url.split('?')
                host_base = host_base + "?"
            except:
                host_base = url

            parse = bs4.BeautifulSoup(response_text, 'html.parser')
            all_forms = parse.find_all('form')
            if all_forms:
                for i in range(len(sql_tests)):
                    payload_base = sql_tests[i]
                    payload_full = "'" + payload_base + "'"
                    for form in all_forms:
                        form_action = form.get('action')
                        form_method = form.get('method')
                        form_fields = form.findAll('input')
                        form_fields = form_fields + form.findAll('select')
                        form_data_original = dict((field.get('name'), field.get('value')) for field in form_fields)

                        for key, value in form_data_original.items():
                            form_data = form_data_original.copy()
                            form_data[key] = payload_full
                            if ("get" in form_method) or ("GET" in form_method):
                                get_request = requests.get(host_base, params=form_data, verify=False)
                                get_data = get_request.text
                                if any(error in get_data for error in
                                       ["SQL syntax.*MySQL", "Warning.*mysql_.*", "valid MySQL "
                                                                                  "result",
                                        "MySqlClient\\.", "MySQL Error", "Error executing query",
                                        "SQL syntax"]):
                                    potential_sql.append(str(get_request.url))
                            elif ("post" in form_method) or ("POST" in form_method):
                                post_request = requests.post(url, data=form_data, verify=False)
                                post_data = post_request.text
                                if any(error in post_data for error in
                                       [r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result",
                                        r"MySqlClient\.",
                                        r"MySQL Error", r"Error executing query", r"SQL syntax"]):
                                    potential_sql.append(str(post_request.url))

                if potential_sql:
                    result_text.insert(tk.END, "Potential SQL Injection vulnerabilities found:\n")
                    for url in potential_sql:
                        result_text.insert(tk.END, url + "\n")
                else:
                    result_text.insert(tk.END, "No SQL Injection vulnerabilities found.\n")
            else:
                result_text.insert(tk.END, "No forms found to test for SQL Injection vulnerabilities.\n")

        except Exception as e:
            result_text.insert(tk.END, f"An error occurred during SQL injection testing: {str(e)}\n")

    # Function to test for Local File Inclusion vulnerability
    def rce_test(url, result_text):
        response = requests.get(url, verify=False)
        if response is None:
            result_text.insert(tk.END, "Error: No response data received from the server.\n")
            return

        soup = bs4.BeautifulSoup(response.text, "html.parser")
        potential_rce = []
        for form in soup.find_all('form'):
            action = form.get('action')
            if action and action.startswith("http"):
                potential_rce.append(action)

        if potential_rce:
            result_text.insert(tk.END, "Potential Remote Code Execution vulnerabilities found:\n")
            for url in potential_rce:
                result_text.insert(tk.END, url + "\n")
        else:
            result_text.insert(tk.END, "No Remote Code Execution vulnerabilities found.\n")

# Sub Domain Scanner and it's applications

MAX_PER_PAGE = 100
COMMUNITY_PAGES = 10

# API ID and API secret
CENSYS_API_ID = "777541a1-b52c-470e-9979-633d6dec4dce"
CENSYS_API_SECRET = "mmFs280QYfgjvBEVjYJ0s3XmrbuhIIQ1"

def find_subdomains(domain, result_text):
    try:
        censys_certificates = CensysCerts(
            api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET
        )
        certificate_query = "names: %s" % domain
        certificates_search_results = censys_certificates.search(
            certificate_query,
            per_page=MAX_PER_PAGE,
            pages=COMMUNITY_PAGES
        )

        subdomains = set()
        for page in certificates_search_results:
            for search_result in page:
                subdomains.update(search_result.get("names", []))

        if subdomains:
            result_text.config(state="normal")
            result_text.delete("1.0", tk.END)
            result_text.insert(tk.END, f"Found {len(subdomains)} unique subdomains of {domain}:\n\n")
            for subdomain in subdomains:
                result_text.insert(tk.END, f"- {subdomain}\n")
            result_text.config(state="disabled")
        else:
            result_text.config(state="normal")
            result_text.delete("1.0", tk.END)
            result_text.insert(tk.END, "No subdomains found.")
            result_text.config(state="disabled")

    except CensysUnauthorizedException:
        messagebox.showerror("Error", "Your Censys credentials look invalid.")
    except CensysRateLimitExceededException:
        messagebox.showerror("Error", "Looks like you exceeded your Censys account limits rate.")
    except CensysException as e:
        messagebox.showerror("Error", f"Something bad happened: {repr(e)}")

def create_sdcan_interface(parent):
    # Create frame to hold scanning interface
    scan_frame = customtkinter.CTkFrame(parent, bg_color='black', border_color='black', border_width=10)
    scan_frame.grid(row=0, column=0, sticky="nsew", padx=0)

    # Align to the center
    parent.grid_columnconfigure(0, weight=1)
    parent.grid_rowconfigure(0, weight=1)

    # Add heading for the subdomain scanning
    scan_heading = tk.Label(scan_frame, text="Scan for Subdomains", font=("Arial", 20), bg='black', fg='white')
    scan_heading.grid(row=0, column=0, columnspan=2, pady=10, padx=50)

    # Create input field
    domain_label = tk.Label(scan_frame, text="Enter Domain Name:")
    domain_label.grid(row=1, column=0, sticky="w", padx=20)

    def on_domain_entry_click(event):
        if domain_entry.get() == "www.example.com":
            domain_entry.delete(0, tk.END)
            domain_entry.config(fg="white")  # Change text color to black

    domain_entry = tk.Entry(scan_frame, width=48)
    domain_entry.grid(row=1, column=1, padx=0, pady=5)
    domain_entry.place(x=150, y=58)
    domain_entry.insert(0, "www.example.com")  # Placeholder text
    domain_entry.config(fg="white")  # Set text color to grey
    domain_entry.bind("<FocusIn>", on_domain_entry_click)  # Bind the function to the entry field

    result_text = scrolledtext.ScrolledText(scan_frame, width=60, height=20)
    result_text.grid(row=2, column=0, columnspan=2, padx=20, pady=5)

    # Function to generate the report
    def generate_report():
        report_content = result_text.get(1.0, tk.END)
        save_report_to_file(report_content)

    # Create the "Generate Report" button
    report_button = tk.Button(scan_frame, text="Generate Report", command=generate_report)
    report_button.grid(row=5, column=1, padx=10, pady=20)

    # Function to start scanning when button is clicked
    def start_scan():
        domain = domain_entry.get()
        if not domain:
            messagebox.showwarning("Warning", "Please enter a domain name.")
            return


        threading.Thread(target=find_subdomains, args=(domain, result_text)).start()

    # Create scan button
    scan_button = tk.Button(scan_frame, text="Start Scan", command=start_scan)
    # scan_button.grid(row=5, column=0, columnspan=2, pady=10)
    scan_button.place(x=20, y=430)

    # Function to clear the result text
    def clear_result():
        result_text.config(state="normal")
        result_text.delete("1.0", tk.END)
        result_text.config(state="disabled")


    # Create clear button
    clear_button = tk.Button(scan_frame, text="Clear Results", command=clear_result)
    # clear_button.grid(row=6, column=0, columnspan=2, pady=15)
    clear_button.place(x=100, y=430)

# Report saving logic
def save_report_to_file(report_content):
    # Get the user's home directory
    home_dir = os.path.expanduser("~")
    # Define the file path for the report
    report_path = os.path.join(home_dir, "Downloads", "scan_report.txt")
    # Write the report content to the file
    with open(report_path, "w") as report_file:
        report_file.write(report_content)
    # Show a message box indicating the report has been saved
    messagebox.showinfo("Report Generated", f"The report has been saved to:\n{report_path}")


# Sidebar design

sidebar = customtkinter.CTkFrame(root, width=200, height=600, bg_color='#1e2739', corner_radius=0, border_color='black',
                                 border_width=4)
sidebar.grid(row=0, column=0, rowspan=4, sticky="nsew")
sidebar.grid_rowconfigure(4, weight=1)

content_frame = ttk.Frame(root, width=1800, height=600, style="Content.TFrame", borderwidth=5)
content_frame.place(x=175, y=5)

home_content = ttk.Frame(content_frame, style="Content.TFrame", width=950, height=640)
home_content.grid(row=0, column=0, sticky="nsew")

# Set background color of the frame
root.tk_setPalette(background='#1e2739')

home_text_frame = ttk.Frame(home_content, style="Content.TFrame", width=900, height=540)
home_text_frame.place(relx=0.4, rely=0.3, anchor="center")

home_heading = tk.Label(home_text_frame, text="Scan Web Vulns", font=("Arial", 25))
home_heading.pack(pady=(20, 10), padx=(0, 0))

home_text = tk.Label(home_text_frame,
                     text="In today's rapidly evolving digital landscape, web applications have become indispensable tools for businesses and individuals alike. However, with the increase of web-based technologies, there arises a pressing need for robust security measures to safeguard against potential vulnerabilities. The consequences of a security breach in a web application can be severe, ranging from data theft and financial loss to damage to reputation and trust. To address this critical issue, we propose the development of a comprehensive Web Application Vulnerability Scanner. This scanner will serve as a proactive defense mechanism, enabling organizations and individuals to identify and mitigate potential security risks within their web applications before malicious actors can exploit them.",
                     wraplength=700, justify="center", anchor="center")
home_text.pack(pady=50, padx=50)

# Content Editing

nscan_content = ttk.Frame(content_frame, style="Content.TFrame", borderwidth=14)
nscan_content.grid(row=0, column=2, sticky="nsew", padx=65, pady=60)

vscan_content = ttk.Frame(content_frame, style="Content.TFrame", borderwidth=10)
vscan_content.grid(row=0, column=2, sticky="nsew", padx=100, pady=90)

sdcan_content = ttk.Frame(content_frame, style="Content.TFrame", borderwidth=14)
sdcan_content.grid(row=0, column=2, sticky="nsew", padx=100, pady=90)

profile_content = ttk.Label(content_frame, text="Profile Content", style="Content.TLabel")
profile_content.grid(row=0, column=0, sticky="nsew")

settings_content = ttk.Frame(content_frame, style="Content.TFrame", borderwidth=10)
settings_content.grid(row=0, column=2, sticky="nsew", padx=65, pady=60)

def logout():
    if messagebox.askokcancel("Logout", "Are you sure you want to logout?"):
        # Destroy the root window
        root.destroy()

# Create settings buttons
logout_button = customtkinter.CTkButton(settings_content, text="Logout", command=logout, width=150)
logout_button.place(x=300, y=500)


create_sidebar_buttons(sidebar, home_content, nscan_content, vscan_content, sdcan_content, profile_content, settings_content)

show_content(home_content)

root.mainloop()
