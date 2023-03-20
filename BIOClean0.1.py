from pip._vendor import requests
import os
import sys
import winreg

# VirusTotal API Key
API_KEY = "YOUR_API_KEY_HERE"


def scan_file(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': API_KEY}
    files = {'file': (file_path, open(file_path, 'rb'))}
    response = requests.post(url, files=files, params=params)
    if response.status_code == 200:
        return response.json()['resource']
    else:
        return None


def get_report(resource_id):
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': resource_id}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return None




def main():
    # Scan a file
    file_path = input('Enter file path: ')
    resource_id = scan_file(file_path)
    if resource_id is not None:
        input('Scan complete. Press any key to view report...')
        report = get_report(resource_id)
        print(report)
    else:
        print('Scan failed.')

if __name__ == '__main__':
    main()
