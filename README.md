# RightClickVirusTotal

RightClickVirusTotal is a Python program that provides a simple local interface for the VirusTotalAPI.

## Key Features

- Utilizes the VirusTotal API to upload files and retrieve analysis results.
- Provides real-time updates on the scanning and analysis progress.
- Displays comprehensive statistics on the file's detection status, including harmless, malicious, suspicious, and undetected classifications.
- Built with a user-friendly graphical interface using the Tkinter library.

**Note:** Before using the program, make sure to obtain a valid VirusTotal API key and enter it in the `VIRUSTOTALAPIKEY` variable within the code.

## Build Instructions using PyInstaller

1. Make sure you have PyInstaller installed. If not, you can install it using pip by running the following command: `pip install pyinstaller`

2. Open your terminal or command prompt.

3. Navigate to the directory where `virus_total_scanner.py` is located.

4. Run the following command to build the executable: `pyinstaller --onefile --noconsole virus_total_scanner.py`

   This command instructs PyInstaller to create a single executable file (`virus_total_scanner.exe` on Windows) that contains your program and its dependencies.

5. Wait for PyInstaller to finish the build process.

6. Once the build process is complete, you will find a new `dist` directory in the same location as your program file.

7. Inside the `dist` directory, you will find the executable file (`virus_total_scanner.exe` on Windows).

## Add to Context Menu

1. Open the Registry Editor by pressing Win + R, typing "regedit" in the Run dialog, and pressing Enter.

2. In the Registry Editor, navigate to the following key: `HKEY_CLASSES_ROOT*\shell`

3. Right-click on the "shell" key, choose New, and then Key. Give the new key a name that will represent your program (e.g., "Upload to VirusTotal").

4. With the newly created key selected, right-click on the right-side pane, choose New, and then Key. Name this key "command".

5. Select the "command" key you just created, and in the right-side pane, double-click on the `(Default)` value.

6. In the Edit String dialog box, enter the path to your executable followed by "%1" (including the quotes). 
  For example: `"C:\Path\To\Your\Program.exe" "%1"`
  Make sure to replace `"C:\Path\To\Your\Program.exe"` with the actual path to your executable.

7. Click OK to save the value.

8. Close the Registry Editor.

After following these steps, you should be able to right-click on a file in Windows Explorer, navigate to the context menu option you created (e.g., "Upload to VirusTotal"), and your program will be launched with the file path as an argument.

**Please note:** Modifying the Windows Registry can have unintended consequences if not done correctly. Therefore, it's always a good idea to create a backup of your registry or create a system resore point.
