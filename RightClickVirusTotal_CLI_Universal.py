from os.path import basename, getsize
from requests import post, get
from time import sleep
import sys
from colorama import Fore, Style
import vt
from hashlib import md5

def interface(print_stage, file_name=None, loading_dots=None, stats=None):
    if (print_stage == "title"):
        print(r"  ___ _      _   _    ___ _ _    _  __   ___             _____    _        _ ")
        print(r" | _ (_)__ _| |_| |_ / __| (_)__| |_\ \ / (_)_ _ _  _ __|_   ____| |_ __ _| |")
        print(r" |   | / _` | ' |  _| (__| | / _| / /\ V /| | '_| || (_-< | |/ _ |  _/ _` | |")
        print(r" |_|_|_\__, |_||_\__|\___|_|_\__|_\_\ \_/ |_|_|  \_,_/__/ |_|\___/\__\__,_|_|")
        print(r"       |___/                                                                 ")
    elif (print_stage == "uploading"):
        print(f'\nChecking File: {file_name}')
        print(Fore.GREEN + "[ ] File Uploading...")
    elif (print_stage == "uploaded"):
        print("\033[A                             \033[A")
        print('[✓] File Uploaded\n')
    elif (print_stage == "analysing"):
        print("\033[A                             \033[A")
        print(f'[ ] File Analysing' + '.' * loading_dots)
    elif (print_stage == "analysed"):
        print("\033[A                             \033[A")
        print('[✓] Analysis Complete\n')
        print(Style.RESET_ALL, end ="")
    elif (print_stage == "results"):
        print(Fore.BLUE + f'File: {file_name}')
        print(Style.RESET_ALL, end =" ")
        print(Fore.GREEN + f'Harmless: {stats["harmless"]}')
        print(Style.RESET_ALL, end =" ")
        print(Fore.RED + f'Malicious: {stats["malicious"]}')
        print(Style.RESET_ALL, end =" ")
        print(Fore.YELLOW + f'Suspicious: {stats["suspicious"]}')
        print(Style.RESET_ALL, end =" ")
        print(Fore.WHITE, end ="")
        print(Style.DIM + f'Undetected: {stats["undetected"]}')
        print(Style.RESET_ALL, end ="")
        
def hash_file(file_path):
    # Open the file in binary mode and hash it
    with open(file_path, 'rb') as file_to_check:
        data = file_to_check.read() 
        md5_hash = md5(data).hexdigest()
    return md5_hash

def scan_file(client, file_path):
    loading_dots = 0
    api_counter = 28
    
    with open(file_path, "rb") as f:
        analysis = client.scan_file(f)

    # Poll the analysis endpoint until the analysis is complete
    analysis_complete = False
    while not analysis_complete:
        # Loading animation
        interface("analysing", loading_dots=loading_dots)
        loading_dots = (loading_dots + 1) % 4

        # Sleep for 1 second
        sleep(1)

        # Perform the API request every 15 seconds
        if api_counter % 15 == 0:
            analysis = client.get_object("/analyses/{}", analysis.id)
            if analysis.status == "completed":
                analysis_complete = True

        api_counter += 1
    return  

def main():
    # Obtain the API key and file path from program arguments
    VIRUSTOTALAPIKEY = sys.argv[1].strip()
    file_path = sys.argv[2].strip()
    
    # Get file name
    file_name = basename(file_path)
    
    # Print the title
    interface(print_stage="title")
    # Print the uploading message
    interface("uploading", file_name=file_name)
    
    # Initialise vt-api client
    client = vt.Client(VIRUSTOTALAPIKEY)
    md5_hash = hash_file(file_path)

    # Determine if file has already been scanned, if not try scanning it
    try:
        file_object = client.get_object("/files/" + md5_hash)
        interface("uploaded")
    except:
        scan_file(client, file_path)
        try:
            file_object = client.get_object("/files/" + md5_hash)
            interface("uploaded")
        except:
            interface("error")
            return
    
    # Print the analysis complete message
    interface("analysed")
    # Print the results
    interface("results", file_name=file_name, stats=file_object.last_analysis_stats)

    # Close the client
    client.close()

    # Ensure all terminal colouring is reset
    print(Style.RESET_ALL, end ="")

    # Exit the program
    sys.exit()          

if __name__ == "__main__":
    # Ensure the correct number of arguments are provided
    if len(sys.argv) < 3:
        print("Usage: <script> <VirusTotalAPIKey> <FilePath>")
        sys.exit()

    main()
