# RightClickVirusTotal

RightClickVirusTotal is a Python program that provides a simple local interface for the VirusTotalAPI.

Designed to be add to the Windows context menu, it allows you to easily check any files for viruses before running them.

A compiled Windows executable is avaliable in the releases tab.

![demo](https://github.com/smp46/RightClickVirusTotal/assets/27676057/a35113cf-60ce-4a01-a811-35f7f8c5407c)


## Key Features

- Utilizes the VirusTotal API to upload files and retrieve analysis results.
- Displays comprehensive statistics on the file's detection status, including harmless, malicious, suspicious, and undetected classifications.
- Built with a user-friendly graphical interface using the Tkinter library.

**Note:** Before using the program, make sure to obtain a valid VirusTotal API key (these are free for basic personal use).

## Current Issues

- Only files that have already been analysed display results. So the workaround is to quit the program after file upload is complete, then run it again.

## Build Instructions using PyInstaller

1. Make sure you have PyInstaller installed. If not, you can install it using pip by running the following command: `pip install pyinstaller`

2. Install other required dependencies through pip:
	- tk
	- ttkthemes
	- requests
   - hashlib

3. Open your terminal or command prompt.

4. Navigate to the directory where `RightClickVirusTotal.py` is located.

5. Run the following command to build the executable: `pyinstaller --onefile --noconsole RightClickVirusTotal.py`

   This command instructs PyInstaller to create a single executable file (`RightClickVirusTotal.exe` on Windows) that contains your program and its dependencies.

6. Wait for PyInstaller to finish the build process.

7. Once the build process is complete, you will find a new `dist` directory in the same location as your program file.

8. Inside the `dist` directory, you will find the executable file (`RightClickVirusTotal.exe` on Windows).

## Add to Context Menu in Windows 10/11

1. Open the Registry Editor by pressing Win + R, typing "regedit" in the Run dialog, and pressing Enter.

2. In the Registry Editor, navigate to the following key: `Computer\HKEY_CLASSES_ROOT\*\shell\`

3. Right-click on the "shell" key, choose New, and then Key. Give the new key a name that will represent your program (e.g., "Upload to VirusTotal").

4. With the newly created key selected, right-click on the right-side pane, choose New, and then Key. Name this key "command".

5. Select the "command" key you just created, and in the right-side pane, double-click on the `(Default)` value.

6. In the Edit String dialog box, enter the path to your executable followed by your API Key in quotes and "%1" (including the quotes). 
  For example: `"C:\Path\To\Your\Program.exe" "<APIKEY>" "%1"`
  Make sure to replace `"C:\Path\To\Your\Program.exe"` with the actual path to your executable.

7. Click OK to save the value.

8. Close the Registry Editor.

After following these steps, you should be able to right-click on a file in Windows Explorer, navigate to the context menu option you created (e.g., "Upload to VirusTotal"), and your program will be launched with the file path as an argument.

**Please note:** Modifying the Windows Registry can have unintended consequences if not done correctly. Therefore, it's always a good idea to create a backup of your registry or create a system resore point.
