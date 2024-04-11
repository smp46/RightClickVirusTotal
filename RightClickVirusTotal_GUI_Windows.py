from os.path import basename, dirname, join, realpath
from time import sleep
from threading import Thread
import sys
import tkinter as tk
import vt
from hashlib import md5
from ctypes import windll
import asyncio
import winreg
from webbrowser import open_new_tab
from PIL import Image, ImageTk

MAIN_WINDOW_WIDTH = 300
MAIN_WINDOW_HEIGHT = 300
CHILD_WINDOW_WIDTH = 300
CHILD_WINDOW_HEIGHT = 200

launch_helper = 0

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
        widget.insert(tk.END, f'[    ] File Still Analysing' 
                      + '.' * loading_dots + '\n        don\'t worry it\'s not stuck', 'success')
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
        
        # Disable text widget to prevent further editing after results
        widget.config(state="disabled")
    
    elif (print_stage == "error"):
        # Update the text widget
        widget.insert(tk.END, 'An error occurred\n', 'malicious')
        widget.see(tk.END)
        
    elif (print_stage == "noargs"):
        # Without args the program will only launch the helper window
        widget.insert(tk.END, 'Without arguments the program assumes you are trying to add it to the context menu. ', 'error')
        widget.insert(tk.END, 'If you have already added it, close this window and use the context menu to launch it with args.\n', 'error')
        widget.insert(tk.END, 'Usage: RightClickVirusTotal.exe <API_KEY> <FILE_PATH>\n', 'error')
        widget.see(tk.END)

def create_window():
    # Create a new ThemedTk window
    window = tk.Tk()

    # Set the size of the window
    window.geometry(f"{MAIN_WINDOW_WIDTH}x{MAIN_WINDOW_HEIGHT}")
    
    # Attempt to help smooth text in Windows
    windll.shcore.SetProcessDpiAwareness(1)

    # Set the background color of the window
    window.configure(background='white', borderwidth=0, bd=0, padx=1)

    # Set the title of the window
    window.title("RightClickVirusTotal")

    # Load program icon and Github logo for button
    # Credit to @Kamal for this method of loading images
    if getattr(sys, 'frozen', False):
        ico = ImageTk.PhotoImage(file=join(sys._MEIPASS, "imgs/rcvt.ico"))
        gh_logo = ImageTk.PhotoImage(file=join(sys._MEIPASS, "imgs/gh_logo.png"))
    else:
        ico = ImageTk.PhotoImage(file="imgs/rcvt.ico")
        gh_logo = ImageTk.PhotoImage(file="imgs/gh_logo.png")
    
    # Set program icon
    window.iconphoto(False, ico)

    # Create a frame at the bottom for the exit button
    exit_frame = tk.Frame(window, bg='white')
    exit_frame.pack(side='bottom', fill='x', padx=0, pady=0)

    # Exit button
    exit_button = tk.Button(exit_frame, text="Exit", command=window.destroy, padx=0, pady=10, font=("Helvetica", 12),
                            bg='#2c2c2c', fg='#f5f6fa', activebackground='#3c3c3c', activeforeground='#f5f6fa',
                            bd=0, highlightthickness=0, cursor="hand2")
    exit_button.pack(side='bottom', fill='x', padx=10, pady=10)

    # Create a frame for the GitHub and "Add to Right Click" buttons
    button_frame = tk.Frame(window, bg='white', borderwidth=0)
    button_frame.pack(side='bottom', fill='x', padx=10, pady=0)

    # GitHub logo button
    visit_github_button = tk.Button(button_frame, image=gh_logo, command=lambda: open_new_tab("https://github.com/smp46/RightClickVirusTotal"),
                                    borderwidth=0, highlightthickness=0, bg='white', cursor="hand2")
    visit_github_button.pack(side='left', padx=(0, 20))
    visit_github_button.image = gh_logo  # Keep a reference to avoid garbage collection

    # Add to Context Menu button, aligned to the right
    add_to_context_button = tk.Button(button_frame, text="Add to Right Click Menu", command=lambda: add_to_context_menu(window, ico, add_to_context_button, already_added_label),
                                    pady=5, font=("Helvetica", 8), bd=0, highlightthickness=0,
                                    bg='white', fg='black', cursor="hand2")
    # Add a label to indicate that the program is already in the context menu
    already_added_label = tk.Label(button_frame, text="Already in Right Click Menu", font=("Helvetica", 8), bg='white')
    
    # Pack differently depending on if the program is already in the context menu
    if not check_for_reg_key():
        add_to_context_button.pack(side='right') 
    else:
        already_added_label.pack(side='right')

    # Create a new text widget with padding
    widget = tk.Text(window, padx=10, pady=10, wrap="word", font=("Helvetica", 12), borderwidth=0, bg='white')
    widget.pack(fill=tk.BOTH, expand=True)
    
    # Define text colors
    widget.tag_configure('success', foreground='green')
    widget.tag_configure('error', foreground='red')
    widget.tag_configure('file', foreground='blue')
    widget.tag_configure('harmless', foreground='green')
    widget.tag_configure('malicious', foreground='red')
    widget.tag_configure('suspicious', foreground='orange')
    widget.tag_configure('undetected', foreground='grey')
    
    # Attempt to hide that widget is just a text field
    widget.bind("<1>", disable_event)  # Mouse click
    widget.bind("<B1-Motion>", disable_event)  # Mouse move while button held
    widget.bind("<<Select>>", disable_event)  # Text selection
    
    Thread(target=main, args=(widget,window, ico, add_to_context_button, already_added_label), daemon=True).start()
    window.mainloop()

# Function used to disable mouse events in TK
def disable_event(event):
    return "break"

def hash_file(file_path):
    # Open the file in binary mode and hash it
    try:
        with open(file_path, 'rb') as file_to_check:
            data = file_to_check.read() 
            md5_hash = md5(data).hexdigest()
    except:
        sys.exit(1)
    return md5_hash

def scan_file(client, file_path, widget):
    loading_dots = 0
    api_counter = 0
    
    try:
        with open(file_path, "rb") as f:
            analysis = client.scan_file(f)
    except:
        sys.exit(1)
        
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

def main(widget, parent_window, rcvt_icon, add_to_button, added_label):
    # Create a new event loop for the current thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    if len(sys.argv) == 3:
        VIRUSTOTALAPIKEY = sys.argv[1].strip()
        file_path = sys.argv[2].strip()
    if len(sys.argv) == 4:
        VIRUSTOTALAPIKEY = sys.argv[1].strip()
        file_path = sys.argv[2].strip()
        add_to_context_menu(parent_window, rcvt_icon, add_to_button, added_label, loop=loop, VIRUSTOTALAPIKEY=VIRUSTOTALAPIKEY) 
    
    if len(sys.argv) < 3:
        # If no arguments are provided, launch helper window only if needed.
        interface("noargs", widget)
        if not check_for_reg_key():
            add_to_context_menu(parent_window, rcvt_icon, add_to_button, added_label, loop=loop)
            
    else:
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

def add_to_context_menu(parent_window, rcvt_icon, add_to_button, added_label, loop=None, VIRUSTOTALAPIKEY=None):
    if not is_admin():
        # Re-run the program with admin rights and arg[3] = 1 to auto launch this window again
        args = sys.argv[:] 
        args.append('1')
        lpParameters = " ".join(args[1:])  # Join starting from the second item

        # Execute the command with elevated privileges
        windll.shell32.ShellExecuteW(None, "runas", sys.executable, lpParameters, None, 1)
        cleanup_and_exit(loop, parent_window)
    
    context_window = tk.Toplevel(parent_window)
    context_window.geometry(f"{CHILD_WINDOW_WIDTH}x{CHILD_WINDOW_HEIGHT}")
    
    if VIRUSTOTALAPIKEY is None:
        api_key_var = tk.StringVar()
    else:
        api_key_var = tk.StringVar(value=VIRUSTOTALAPIKEY)

    if getattr(sys, 'frozen', False):
        # If running as a standalone executable
        base_path = dirname(realpath(sys.executable))
        executable_name = basename(sys.executable)
        # Construct the path to the executable that will be added to the right-click menu
        executable_path = join(base_path, executable_name)
    else:
        # If running as a script, don't try continue
        print("This function is only designed to work with the program compiled.")
        cleanup_and_exit(loop, parent_window)

    # Try bring this window to the front of the screen    
    raise_above_all(context_window)
    
    # Position the window to right of the parent window
    parent_x = parent_window.winfo_x()
    parent_y = parent_window.winfo_y()
    # 10 pixels gap from the parent window
    child_window_x = parent_x + MAIN_WINDOW_WIDTH + 10
    child_window_y = parent_y

    context_window.geometry(f"{CHILD_WINDOW_WIDTH}x{CHILD_WINDOW_HEIGHT}+{child_window_x}+{child_window_y}")
    
    # Set window title
    context_window.title("RCVT Helper")
    
    # Set window icon
    if rcvt_icon is not None:
        context_window.iconphoto(False, rcvt_icon)

    # Configure the window, remove border and set background color.
    context_window.configure(background='white', borderwidth=0, bd=0, padx=1)
    
    # Add a button to submit the API key
    submit_button = tk.Button(context_window, text="Add to Right Click Menu", command=lambda: submit(api_key_var, 
                    executable_path, context_window, add_to_button, added_label), padx=0, pady=10, font=("Helvetica", 12),
                    bg='#2c2c2c', fg='#f5f6fa', activebackground='#3c3c3c', activeforeground='#f5f6fa',
                    bd=0, highlightthickness=0)
    submit_button.pack(side='bottom', fill='x', expand=True, padx=10, pady=10)

    # Add user input
    api_key_label = tk.Label(context_window, text="Enter API Key", font=("Helvetica", 12), fg='#2c2c2c',
                             bg='white')
    api_key_label.pack(pady=(10, 0))

    # Add an entry box for the API key
    api_key_entry = tk.Entry(context_window, textvariable=api_key_var, font=("Helvetica", 10), bg='white', fg='#2c2c2c'
                             , border=1, relief='solid')
    api_key_entry.pack(fill='x', padx=10, pady=(0, 10))

def submit(api_key_var, executable_path, window, add_to_button, added_label):
    api_key = api_key_var.get().strip()
    try:
        shell = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, r"*\shell", 0, winreg.KEY_WOW64_64KEY | winreg.KEY_ALL_ACCESS)
        new_exec_key = winreg.CreateKeyEx(shell, r"Upload to VirusTotal\command", 0, winreg.KEY_WOW64_64KEY | winreg.KEY_ALL_ACCESS)
        winreg.CloseKey(shell)
        
        default_value = executable_path + " " + "\"" + api_key + "\"" + " " + "\"%1\""
        
        winreg.SetValueEx(new_exec_key, "", 0, winreg.REG_SZ, default_value)
        winreg.CloseKey(new_exec_key)
        
        icon = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r"*\shell\Upload to VirusTotal", 0, winreg.KEY_WOW64_64KEY | winreg.KEY_ALL_ACCESS)
        winreg.SetValueEx(icon, r"Icon", 0, winreg.REG_SZ, executable_path)
        winreg.CloseKey(icon)
        
        # Indicate that the operation was successful
        complete_label = tk.Label(window, text="Success!", font=("Helvetica", 12), fg='green', bg='white')
        complete_label.pack(pady=(0, 10))
        
        # Update the button to indicate that the program is now in the context menu
        add_to_button.pack_forget()
        added_label.pack(side='right')
        
        # Close the window after 2 seconds
        window.after(2000, window.destroy)
    
    except WindowsError:
        window.destroy()

def check_for_reg_key():
    #Check if program already exists in context menu
    try:
        key_path = r"*\shell\Upload to VirusTotal\command"
        key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, key_path)
        winreg.CloseKey(key)
        return True
    #Attempt to create key if there is none
    except FileNotFoundError:
        return False

# Bring window to front, credit to @nbro on StackOverflow
def raise_above_all(window):
    window.attributes('-topmost', 1)
    window.attributes('-topmost', 0)

def is_admin():
    try:
        return windll.shell32.IsUserAnAdmin()
    except:
        return False

def cleanup_and_exit(loop, root):
    # Close tk event loop
    root.destroy()
    
    # Close the event loop
    if loop.is_running():
        loop.stop()
    loop.close()
    
    # Explicitly exit the program
    sys.exit()

if __name__ == "__main__":
    create_window()
