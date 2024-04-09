from os.path import basename, getsize
from requests import post, get
from time import sleep
import sys
from colorama import Fore, Style

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

def check_file():
    # Open the file in binary mode
    with open(file_path, 'rb') as file:
        # Get the file name
        file_name = basename(file_path)
        print(f'\nChecking File: {file_name}')
        
        # Indicate that the file is being uploaded
        print(Fore.GREEN + '[ ] File Uploading...')
        
        # VirusTotal API requires a different request for files > 32MB
        file_size = getsize(file_path)
        max_size = 32 * 1024 * 1024 

        if file_size > max_size:
            # For large files, first get the upload URL
            response = get("https://www.virustotal.com/api/v3/files/upload_url", headers=headers)
            if response.status_code == 200:
                globals()["url"] = response.json()['data']
            else:
                print(f'Error fetching upload URL: {response.status_code}\n')
                return

        # Define the multipart-encoded data
        data = {'file': file}

        # Send the file to VirusTotal for scanning
        response = post(url, headers=headers, files=data)        

        # Check if the request was successful
        if response.status_code == 200:
            # Get the JSON response
            json_response = response.json()

            # Get the ID of the analysis
            analysis_id = json_response['data']['id']

            # Update the text widget
            print("\033[A                             \033[A")
            print('[✓] File Uploaded\n')

            # Get the results of the analysis
            analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
            analysis_response = get(analysis_url, headers=headers)

            # Initialize counter for loading dots
            loading_dots = 0
            api_counter = 0

            # Poll the analysis endpoint until the analysis is complete
            analysis_complete = False
            while not analysis_complete:
                # Loading animation
                print("\033[A                             \033[A")
                print(f'[ ] File Analysing' + '.' * loading_dots)
                loading_dots = (loading_dots + 1) % 4

                sleep(1)

                # Perform the API request every 15 seconds
                api_counter += 1
                if api_counter % 15 == 0:
                    analysis_response = get(analysis_url, headers=headers)
                    if analysis_response.status_code == 200:
                        analysis_status = analysis_response.json()['data']['attributes']['status']
                        if analysis_status == 'completed':
                            analysis_complete = True

            # Redraw as complete
            print("\033[A                             \033[A")
            print('[✓] Analysis Complete\n')
            print(Style.RESET_ALL, end ="")

            # Check if the request was successful
            if analysis_response.status_code == 200:
                # Get the JSON response
                analysis_json_response = analysis_response.json()

                # Get the results of the analysis
                stats = analysis_json_response['data']['attributes']['stats']

                # Update the text widget
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
            else:
                print(f'Error: {analysis_response.status_code}\n')
        else:
            print(f'Error: {response.status_code}\n')

if __name__ == "__main__":
    check_file()
