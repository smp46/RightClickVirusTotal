import os
import sys
import tkinter as tk
import winreg

window = tk.Tk()
window.geometry("300x300")

api_key_var = tk.StringVar()

if getattr(sys, 'frozen', False):
    # If running as a standalone executable
    base_path = os.path.dirname(os.path.realpath(sys.executable))
else:
    # If running as a script
    base_path = os.path.dirname(__file__)

# Construct the path to the executable that will be added to the right-click menu
executable_path = os.path.join(base_path, 'RightClickVirusTotal_GUI_Windows.exe')

def submit():
    api_key = api_key_var.get()
    #Check if key already exists
    try:
        key_path = r"*\shell\Upload to VirusTotal\command"
        key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, key_path)
        winreg.CloseKey(key)
        print("Key already exists")
    #Attempt to create key if there is none
    except FileNotFoundError:
        try:
            shell = winreg.CreateKeyEx(winreg.HKEY_CLASSES_ROOT, r"*\shell", 0, winreg.KEY_WOW64_64KEY | winreg.KEY_ALL_ACCESS)
            newKey = winreg.CreateKeyEx(shell, r"Upload to VirusTotal\command", 0, winreg.KEY_WOW64_64KEY | winreg.KEY_ALL_ACCESS)
            winreg.CloseKey(shell)
            print("Created Key")
            default_value = executable_path + " " + api_key + " " + "\"%1\""
            winreg.SetValueEx(newKey, "", 0, winreg.REG_SZ, default_value)
            winreg.CloseKey(newKey)
            print("Created 'command' Key with default value")
            done_label.pack()
        except WindowsError:
            print("Failed to create key")
    

#Add user input
api_key_label = tk.Label(window, text="Enter API Key")
api_key_entry = tk.Entry(window, textvariable=api_key_var)
submit_button = tk.Button(text="Create right-click item", command=submit)
done_label = tk.Label(window, text="Done!")

api_key_label.pack()
api_key_entry.pack()
submit_button.pack()

# Start the Tkinter event loop
window.mainloop()