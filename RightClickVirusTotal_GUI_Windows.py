from os.path import basename, dirname, join, realpath
from time import sleep
from threading import Thread
import sys
import tkinter as tk
import vt
from hashlib import md5
from ttkthemes import ThemedTk
from ctypes import windll
import asyncio
import winreg
from webbrowser import open_new_tab
from PIL import Image, ImageTk

def interface(print_stage, widget, file_name=None, loading_dots=None, stats=None):
    if (print_stage == "uploading"):
        # Indicate that the file is being uploaded
        widget.insert(tk.END, '[    ] File Uploading...', 'success')
        widget.see(tk.END)
        
    elif (print_stage == "uploaded"):
        # Delete the uploading message
        widget.delete('1.0', tk.END)
        # Update the text widget
        widget.insert(tk.END, '[✓] File Uploaded\n', 'success')
        widget.see(tk.END)
        
    elif (print_stage == "analysing"):
        # Loading animation
        widget.delete('1.0', tk.END)
        widget.insert(tk.END, '[✓] File Uploaded\n', 'success')
        widget.insert(tk.END, '[    ] File Analysing', 'success')
        widget.insert(tk.END, '.' * loading_dots, 'success')
        widget.see(tk.END)

    elif (print_stage == "analysing_please_wait"):
        # Loading animation
        widget.delete('1.0', tk.END)
        widget.insert(tk.END, '[✓] File Uploaded\n', 'success')
        widget.insert(tk.END, f'[    ] File Still Analysing' + '.' * loading_dots + '\n        don\'t worry it\'s not stuck', 'success')
        widget.see(tk.END)
        
    elif (print_stage == "analysed"):
        # Redraw as complete
        widget.delete('1.0', tk.END)
        widget.insert(tk.END, '[✓] File Uploaded\n', 'success')
        widget.insert(tk.END, '[✓] Analysis Complete\n\n', 'success')
        widget.see(tk.END)

        
    elif (print_stage == "results"):
        # Update the text widget
        widget.insert(tk.END, f'File: {file_name}\n', 'file')
        widget.insert(tk.END, f'Harmless: {stats["harmless"]}\n', 'harmless')
        widget.insert(tk.END, f'Malicious: {stats["malicious"]}\n', 'malicious')
        widget.insert(tk.END, f'Suspicious: {stats["suspicious"]}\n', 'suspicious')
        widget.insert(tk.END, f'Undetected: {stats["undetected"]}\n', 'undetected')
        widget.see(tk.END)
    
    elif (print_stage == "error"):
        # Update the text widget
        widget.insert(tk.END, 'An error occurred\n', 'malicious')
        widget.see(tk.END)

def create_window():
    # Create a new ThemedTk window
    window = ThemedTk(theme="arc")

    # Set the size of the window
    window.geometry("300x300")
    
    # Attempt to help smooth text in Windows
    windll.shcore.SetProcessDpiAwareness(1)

    # Set the background color of the window
    window.configure(background='white')

    # Set the title of the window
    window.title("RightClickVirusTotal")

    # Load Github logo for button
    image = Image.open("gh_logo.png")
    gh_logo = ImageTk.PhotoImage(image)

    # Create a frame at the bottom for the exit button
    exit_frame = tk.Frame(window, bg='white')
    exit_frame.pack(side='bottom', fill='x')

    # Exit button
    exit_button = tk.Button(exit_frame, text="Exit", command=window.destroy, padx=0, pady=10, font=("Helvetica", 12),
                            bg='#2c2c2c', fg='#f5f6fa', activebackground='#3c3c3c', activeforeground='#f5f6fa',
                            bd=0, highlightthickness=0)
    exit_button.pack(side='bottom', fill='x')

    # Create a frame for the GitHub and "Add to Right Click" buttons
    button_frame = tk.Frame(window, bg='white')
    button_frame.pack(side='bottom', fill='x', padx=10, pady=10)

    # GitHub logo button
    visit_github_button = tk.Button(button_frame, image=gh_logo, command=lambda: open_new_tab("https://github.com/smp46/RightClickVirusTotal"),
                                    borderwidth=0, highlightthickness=0, bg='white')
    visit_github_button.pack(side='left', padx=(0, 20))
    visit_github_button.image = gh_logo  # Keep a reference to avoid garbage collection

    # Add to Context Menu button, aligned to the right
    add_to_context_button = tk.Button(button_frame, text="Add to Right Click", command=lambda: add_to_context_menu(window),
                                      padx=10, pady=5, font=("Helvetica", 10), bd=0, highlightthickness=0,
                                      bg='white', fg='black')
    add_to_context_button.pack(side='right')

    # add_to_context_button = tk.Button(window, text="Add to Context Menu", command=lambda: check_for_reg_key(window), padx=0, pady=10, font=("Helvetica", 10),
    #                                   bd=0, highlightthickness=0)
    # add_to_context_button.pack(side='bottom', fill='x', expand=True)
    # visit_github_button = tk.Button(window, command=lambda: open_new_tab("https://github.com/smp46/RightClickVirusTotal"), image=gh_logo)
    # visit_github_button.pack(side='bottom')

    # Create a new text widget with padding
    widget = tk.Text(window, padx=10, pady=10, wrap="word", font=("Helvetica", 12))
    widget.pack(fill=tk.BOTH, expand=True)
    
    # Define text colors
    widget.tag_configure('success', foreground='green')
    widget.tag_configure('error', foreground='red')
    widget.tag_configure('file', foreground='blue')
    widget.tag_configure('harmless', foreground='green')
    widget.tag_configure('malicious', foreground='red')
    widget.tag_configure('suspicious', foreground='orange')
    widget.tag_configure('undetected', foreground='grey')

    Thread(target=main, args=(widget,), daemon=True).start()
    window.mainloop()

def hash_file(file_path):
    # Open the file in binary mode and hash it
    try:
        with open(file_path, 'rb') as file_to_check:
            data = file_to_check.read() 
            md5_hash = md5(data).hexdigest()
    except:
        sys.exit()
    return md5_hash

def scan_file(client, file_path, widget):
    loading_dots = 0
    api_counter = 0
    
    with open(file_path, "rb") as f:
        analysis = client.scan_file(f)

    # Poll the analysis endpoint until the analysis is complete
    analysis_complete = False
    while not analysis_complete:
        # Loading animation
        if api_counter <= 30:
            interface("analysing", widget, loading_dots=loading_dots)
        else:
            interface("analysing_please_wait", widget, loading_dots=loading_dots)
            
        loading_dots = (loading_dots + 1) % 4

        sleep(1)

        # Perform the API request every 15 seconds
        if api_counter % 15 == 0:
            analysis = client.get_object("/analyses/{}", analysis.id)
            if analysis.status == "completed":
                analysis_complete = True

        api_counter += 1
    return


def main(widget):
    # Create a new event loop for the current thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    VIRUSTOTALAPIKEY = sys.argv[1].strip()
    file_path = sys.argv[2].strip()

    # Get file name
    file_name = basename(file_path)

    # Update the text widget
    interface("uploading", widget)
    
    # Initialise vt-api client
    client = vt.Client(VIRUSTOTALAPIKEY)
    md5_hash = hash_file(file_path)

    # Determine if file has already been scanned
    try:
        file_object = client.get_object("/files/" + md5_hash)
        interface("uploaded", widget)
    except:
        scan_file(client, file_path, widget)
        try:
            file_object = client.get_object("/files/" + md5_hash)
            interface("uploaded", widget)
        except:
            interface("error", widget)
            return
    
    interface("analysed", widget)
    interface("results", widget, file_name=file_name, stats=file_object.last_analysis_stats)

    # Close the client
    client.close()
    
    # Close the event loop
    loop.close()

    sys.exit()          

def add_to_context_menu(parent_window):
    context_window = tk.Toplevel(parent_window)
    context_window.geometry("300x200")
    
    api_key_var = tk.StringVar()

    if getattr(sys, 'frozen', False):
        # If running as a standalone executable
        base_path = dirname(realpath(sys.executable))
        executable_name = basename(sys.executable)
        # Construct the path to the executable that will be added to the right-click menu
        executable_path = join(base_path, executable_name)
    else:
        # If running as a script, don't try continue
        sys.exit()

    # Try bring this window to the front of the screen    
    context_window.attributes('-topmost', 1)
    
    # Set window title
    context_window.title("RCVT Helper")

    # Add user input
    api_key_label = tk.Label(context_window, text="Enter API Key", font=("Helvetica", 12), fg='#2c2c2c')
    api_key_label.pack(pady=(10, 0))

    api_key_entry = tk.Entry(context_window, textvariable=api_key_var)
    submit_button = tk.Button(context_window, text="Add to Right Click Menu", command=lambda: submit(api_key_var, 
                        executable_path, context_window), padx=0, pady=10, font=("Helvetica", 12),
                        bg='#2c2c2c', fg='#f5f6fa', activebackground='#3c3c3c', activeforeground='#f5f6fa',
                        bd=0, highlightthickness=0)
    
    api_key_label.pack()
    api_key_entry.pack()
    submit_button.pack(side='bottom', fill='x', expand=True)

def submit(api_key_var, executable_path, window):
    api_key = api_key_var.get()
    try:
        shell = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, r"*\shell", 0, winreg.KEY_WOW64_64KEY | winreg.KEY_ALL_ACCESS)
        newKey = winreg.CreateKeyEx(shell, r"Upload to VirusTotal\command", 0, winreg.KEY_WOW64_64KEY | winreg.KEY_ALL_ACCESS)
        winreg.CloseKey(shell)
        print("Created Key")
        default_value = executable_path + " " + "\"" + api_key + "\"" + " " + "\"%1\""
        winreg.SetValueEx(newKey, "", 0, winreg.REG_SZ, default_value)
        winreg.CloseKey(newKey)
        print("Created 'command' Key with default value")
        window.destroy()
    
    except WindowsError:
        # Display an error message
        tk.messagebox.showerror("Error", "An error occurred while trying to create reg key. The program will now exit.")
        window.destroy()

def check_for_reg_key(parent_window):
    #Check if program already exists in context menu
    try:
        key_path = r"*\shell\Upload to VirusTotal\command"
        key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, key_path)
        winreg.CloseKey(key)
    #Attempt to create key if there is none
    except FileNotFoundError:
        # admin priv is required to continue
        # check if program has admin priv
        if not is_admin():
            # Re-run the program with admin rights
            windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit()

        add_to_context_menu(parent_window)

def is_admin():
    try:
        return windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    create_window()
