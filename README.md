# ![rcvt_icon](https://github.com/smp46/RightClickVirusTotal/assets/27676057/432f94bc-72b1-4f67-85e4-18b04ac133a7)  RightClickVirusTotal #


RightClickVirusTotal is a Python program that provides a simple local interface for the VirusTotal API, via the vt-py library.

Designed to be add to the Windows context menu, it allows you to easily check any files for viruses before running them.

Now cross-platform! Checkout the latest releases for Windows and Linux specific builds.

_Demo of Windows GUI_

![Windows_GUI_demo](https://github.com/smp46/RightClickVirusTotal/assets/27676057/edbf8a55-4ee0-41aa-b7ea-6f36d689b224)

_Demo of Universal GUI_

![universal_gui_demo](https://github.com/smp46/RightClickVirusTotal/assets/27676057/a35113cf-60ce-4a01-a811-35f7f8c5407c)

_Screenshot of Universal CLI_

There is also now a CLI version, with builds for both Windows and Linux:
![universal_cli_demo](https://github.com/smp46/RightClickVirusTotal/assets/27676057/69610265-d554-4de0-a432-0c55511716b1)

## Key Features

- Utilizes the VirusTotal API to upload files and retrieve analysis results.
- Displays comprehensive statistics on the file's detection status, including harmless, malicious, suspicious, and undetected classifications.
- Built with a user-friendly graphical interface using the Tkinter library.

**Note:** Before using the program, make sure to obtain a valid VirusTotal API key (these are free for basic personal use).

### Pick the Right Version ###

There are three versions of RightClickVirusTotal, these are:

- Universal_CLI - A Command Line Interface version to be used in the terminal. Use this if most of your work is does in a terminal.
- Universal_GUI - A Graphical User Interface version that can be used anyway a TKinter GUI can be launched, Windows, Linux or OSX. Use this if you want a GUI and you're _not_ using Windows.
- Windows_GUI - A Graphical User Inferface version with specific features and optimisations for Windows 10/11. Use this if you want a good GUI and *Right Click* functionality on Windows.


## Basic Usage Instructions for Windows GUI ##

Unlike the Universal Versions, Windows GUI can be run with no arguments. Opening it without arguments and admin permissions will open the program, which will then relaunch and request
admin permissions. Then you are presented with two windows that look like this:
![image](https://github.com/smp46/RightClickVirusTotal/assets/27676057/8c471a81-2763-4c51-b15e-a42ed865fb03)

Here you can input your VirusTotal API key, and the program will add a shortcut **to the programs current location**, meaning if you move the .exe the shortcut will no longer work, so only 
do this once you have placed it where you want to keep it, to the Windows Right Click Context Menu like shown in the demo at the top of the page. Then you can launch the program from any
folder in file explorer by simply right clicking and selecting `Upload to VirusTotal`.

The usage instructions for the Universal Versions below are also valid for the Windows GUI.

## Basic Usage Instructions for Universal Versions

Arguments must be provided  _to get the program to do anything_, otherwise a usage error will be printed (for the CLI) and program will exit.

The below example is for the Linux executable, but arguments are provided the same regardless of the platform.

`./RightClickVirusTotal_CLI_Universal "VirusTotalAPIKey" "FilePath"`

Ensure you replace the first argument, VirusTotalAPIKey, with your own API key and keep the quotation marks to ensure it is passed as a string.
Then the second argument, FilePath, should be the whole path to the file, again also in quotes.

For example on Linux:

`./RightClickVirusTotal_CLI_Universal "0010101010101abcdefq" "/home/smp/Documents/RightClickVirusTotal/realvirus.txt"`

## Current Issues

- None known.

## FAQ

**Where can I get a VirusTotal API Key?**

Create a free account over at [VirusTotal](https://www.virustotal.com), then click on your profile icon in the top right corner of the homepage, and select "API Key".

**Why is \<insert RightClickVirusTotal build name\> being detected as a virus by my anti-virus and VirusTotal?**

RightClickVirusTotal is both unsigned and compiled with PyInstaller, so it can match anti-virus patterns used to detect malware. Unfortunately if it's easy to use for solo-devs it also can be used to make malware. These _are false positives_.
If you are concerned at all, please review the source code and build it yourself using the instructions below!

**Why do some files take so long to analyse?**

If a file doesn't already exist in the VirusTotal database, it needs to be scanned and analysed this can, at times, take up to two minutes or more depending on the file size.
It is also a limitation of the free API access, when a file is being analysed I can only check in with VirusTotal API every 15 seconds (4 lookups/min).

## Build Instructions using PyInstaller
**Made and built using Python 3.11.2**
### Windows GUI ###

1. Open powershell and run `pip install pyinstaller ; pip install tk ; pip install vt-py ; pip install asyncio ; pip install pillow`

4. Navigate to a directory to store the project in and run `git clone https://github.com/smp46/RightClickVirusTotal.git ; cd RightClickVirusTotal`

5. Run the following command to build the executable: `pyinstaller --onefile --noconsole --icon=imgs/rcvt.ico --add-data="imgs/;imgs" .\RightClickVirusTotal_GUI_Windows.py`

   This command instructs PyInstaller to create a single executable file (`RightClickVirusTotal_GUI_Windows.exe`) that contains your program, its dependencies and resources.

6. Wait for PyInstaller to finish the build process.

7. Once the build process is complete, you will find a new `dist` directory in the same location as your program file.

8. Inside the `dist` directory, you will find the executable file (`RightClickVirusTotal_GUI_Windows.exe`).

9. Move this file to anywhere you want to 'install' it.

### Universal CLI

1. Make sure you have PyInstaller installed. If not, you can install it using pip by running the following command: `pip install pyinstaller`

2. Install other required dependencies through pip:
	- vt-py
	- colorama

3. Open your terminal or command prompt.

4. Navigate to the directory where `RightClickVirusTotal_CLI_Universal.py` is located.

5. Run the following command to build the executable: `pyinstaller --onefile RightClickVirusTotal_CLI_Universal.py`

   This command instructs PyInstaller to create a single executable file (`RightClickVirusTotal_CLI_Universal`) that contains your program and its dependencies.

6. Wait for PyInstaller to finish the build process.

7. Once the build process is complete, you will find a new `dist` directory in the same location as your program file.

8. Inside the `dist` directory, you will find the executable file.


**Please note:** Modifying the Windows Registry can have unintended consequences if not done correctly. Therefore, it's always a good idea to create a backup of your registry or create a system resore point.
