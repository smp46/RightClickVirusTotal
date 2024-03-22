from os.path import basename, abspath, dirname, join
from requests import post, get
from time import sleep
from threading import Thread
import sys
import tkinter as tk
from ttkthemes import ThemedTk

# Obtain the API key and file path from program arguments
if len(sys.argv) < 3:
    print("Usage: <script> <VirusTotalAPIKey> <FilePath>")
    sys.exit()

VIRUSTOTALAPIKEY = sys.argv[1].strip()
file_path = sys.argv[2].strip()

# Define the API endpoint
url = 'https://www.virustotal.com/api/v3/files'

# Define the headers for the API request
headers = {
    'x-apikey': VIRUSTOTALAPIKEY
}

def check_file(file_path, text_widget):
    # Open the file in binary mode
    with open(file_path, 'rb') as file:
        
        # Indicate that the file is being uploaded
        text_widget.insert(tk.END, '[    ] File Uploading...', 'success')
        text_widget.see(tk.END)

        # Define the multipart-encoded data
        data = {'file': file}

        # Send the file to VirusTotal for scanning
        response = post(url, headers=headers, files=data)

        # Delete the uploading message
        text_widget.delete('1.0', tk.END)

        # Check if the request was successful
        if response.status_code == 200:
            # Get the JSON response
            json_response = response.json()

            # Get the ID of the analysis
            analysis_id = json_response['data']['id']

            # Update the text widget
            text_widget.insert(tk.END, '[✓] File Uploaded\n', 'success')
            text_widget.see(tk.END)

            # Get the results of the analysis
            analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
            analysis_response = get(analysis_url, headers=headers)

            # Update the text widget
            text_widget.insert(tk.END, '[    ] File Analysing', 'success')
            text_widget.see(tk.END)

            # Initialize counter for loading dots
            loading_dots = 0
            api_counter = 0

            # Poll the analysis endpoint until the analysis is complete
            analysis_complete = False
            while not analysis_complete:
                sleep(1)

                # Loading animation
                text_widget.delete('1.0', tk.END)
                text_widget.insert(tk.END, '[✓] File Uploaded\n', 'success')
                text_widget.insert(tk.END, '[    ] File Analysing', 'success')
                text_widget.insert(tk.END, '.' * loading_dots, 'success')
                text_widget.see(tk.END)
                loading_dots = (loading_dots + 1) % 4

                # Perform the API request every 15 seconds
                api_counter += 1
                if api_counter % 15 == 0:
                    analysis_response = get(analysis_url, headers=headers)
                    if analysis_response.status_code == 200:
                        analysis_status = analysis_response.json()['data']['attributes']['status']
                        if analysis_status == 'completed':
                            analysis_complete = True

            # Redraw as complete
            text_widget.delete('1.0', tk.END)
            text_widget.insert(tk.END, '[✓] File Uploaded\n', 'success')
            text_widget.insert(tk.END, '[✓] Analysis Complete\n\n', 'success')
            text_widget.see(tk.END)

            # Check if the request was successful
            if analysis_response.status_code == 200:
                # Get the JSON response
                analysis_json_response = analysis_response.json()

                # Get the file name
                file_name = basename(file_path)

                # Get the results of the analysis
                stats = analysis_json_response['data']['attributes']['stats']

                # Update the text widget
                text_widget.insert(tk.END, f'File: {file_name}\n', 'file')
                text_widget.insert(tk.END, f'Harmless: {stats["harmless"]}\n', 'harmless')
                text_widget.insert(tk.END, f'Malicious: {stats["malicious"]}\n', 'malicious')
                text_widget.insert(tk.END, f'Suspicious: {stats["suspicious"]}\n', 'suspicious')
                text_widget.insert(tk.END, f'Undetected: {stats["undetected"]}\n', 'undetected')
                text_widget.see(tk.END)
            else:
                text_widget.insert(tk.END, f'Error: {analysis_response.status_code}\n', 'error')
                text_widget.see(tk.END)
        else:
            text_widget.insert(tk.END, f'Error: {response.status_code}\n', 'error')
            text_widget.see(tk.END)

def create_window():
    # Create a new ThemedTk window
    window = ThemedTk(theme="arc")

    # Set the size of the window
    window.geometry("300x300")

    # Set the title of the window
    window.title("VirusTotal Scanner")

    # Get the path to the directory where the executable is running
    base_path = getattr(sys, '_MEIPASS', dirname(abspath(__file__)))

    # Add an exit button at the bottom of the window
    exit_button = tk.Button(window, text="Exit", command=window.destroy, padx=0, pady=10, font=("Helvetica", 12),
                            bg='#2c2c2c', fg='#f5f6fa', activebackground='#3c3c3c', activeforeground='#f5f6fa',
                            bd=0, highlightthickness=0)
    exit_button.pack(side='bottom', fill='x', expand=True)

    # Create a new text widget with padding
    text_widget = tk.Text(window, padx=10, pady=10, wrap="word", font=("Helvetica", 12))
    text_widget.pack(fill=tk.BOTH, expand=True)
    
    # Define text colors
    text_widget.tag_configure('success', foreground='green')
    text_widget.tag_configure('error', foreground='red')
    text_widget.tag_configure('file', foreground='blue')
    text_widget.tag_configure('harmless', foreground='green')
    text_widget.tag_configure('malicious', foreground='red')
    text_widget.tag_configure('suspicious', foreground='orange')
    text_widget.tag_configure('undetected', foreground='grey')

    # Start the file check in a new thread to avoid freezing the GUI
    Thread(target=check_file, args=(file_path, text_widget), daemon=True).start()

    # Start the Tkinter event loop
    window.mainloop()

if __name__ == "__main__":
    create_window()
