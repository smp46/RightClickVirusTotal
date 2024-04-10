from os.path import basename
from time import sleep
from threading import Thread
import sys
import tkinter as tk
import vt
from hashlib import md5
from ttkthemes import ThemedTk
from ctypes import windll
import asyncio

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

    # Set the title of the window
    window.title("RightClickVirusTotal")

    # Add an exit button at the bottom of the window
    exit_button = tk.Button(window, text="Exit", command=window.destroy, padx=0, pady=10, font=("Helvetica", 12),
                            bg='#2c2c2c', fg='#f5f6fa', activebackground='#3c3c3c', activeforeground='#f5f6fa',
                            bd=0, highlightthickness=0)
    exit_button.pack(side='bottom', fill='x', expand=True)

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
    with open(file_path, 'rb') as file_to_check:
        data = file_to_check.read() 
        md5_hash = md5(data).hexdigest()
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

if __name__ == "__main__":

    # Obtain the API key and file path from program arguments
    if len(sys.argv) < 3:
        print("Usage: <script> <VirusTotalAPIKey> <FilePath>")
        sys.exit()

    create_window()
