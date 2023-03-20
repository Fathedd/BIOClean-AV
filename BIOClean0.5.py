import os
from pip._vendor import requests
from tabulate import tabulate
import sys
import hashlib

API = "f9b9a5c4adf33f646e13082e3759db9d5ef20836581dbf5f42909722dba494a0"
#Users Makes Option
if input == True:
   pass
   


#Scans File
def scan_file(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey' : API }
    with open(file_path, 'rb') as file:
     file = {'file': (os.path.basename(file_path), file)}
     response = requests.post(url, files=file, params=params)
    if response.status_code == 200:
     return response.json()['resource'] 
    else: 
        return None

#Scans Directories
def scan_directory(directory):
   results = []
   for root, dirs, files in os.walk(directory):
      for filename in files:
         file_path = os.path.join(root, filename)
         result = scan_file(file_path)
         results.append((file_path, result))
         headers = ['File', 'Scan Result']
         print(tabulate(results, headers=headers, tablefmt="grid"))
#Deletes Bad Files
def delete_files(directory, num_hits):
 to_delete = []
 for root, dirs, files in os.walk(directory):
  file_path = os.path.join(root, __name__,)
  file_hash = os.read.__hash__
  params = {'api key': API, 'resource': file_hash}
  headers =  ['File', 'Scan Result']
  response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', headers=headers, params=params)
  json_response = response.json()
  if json_response['response_code'] == 1 and json_response['positives'] == num_hits:
     to_delete.append(file_path)
  if len(to_delete) > 0:
     print(tabulate(to_delete, headers=['Files To Delete']))
     confirm = input(f'Delete {len(to_delete)} files? (y/n): ')
     if confirm.lower() == 'y':
        for file_path in to_delete:
           os.remove(file_path)
           print(f'Deleted File: {file_path}')

  else:
     print(f'Deletion Canceled')

 else:
  print(f"No files found with {num_hits} VirusTotal Hits")

#Virus Total Report
def get_report(resource_id):
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API, 'resource': resource_id }
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def main():
    '''
                                                                                             
88888888ba   88    ,ad8888ba,      ,ad8888ba,   88                                       
88      "8b  88   d8"'    `"8b    d8"'    `"8b  88                                       
88      ,8P  88  d8'        `8b  d8'            88                                       
88aaaaaa8P'  88  88          88  88             88   ,adPPYba,  ,adPPYYba,  8b,dPPYba,   
88""""""8b,  88  88          88  88             88  a8P_____88  ""     `Y8  88P'   `"8a  
88      `8b  88  Y8,        ,8P  Y8,            88  8PP"""""""  ,adPPPPP88  88       88  
88      a8P  88   Y8a.    .a8P    Y8a.    .a8P  88  "8b,   ,aa  88,    ,88  88       88  
88888888P"   88    `"Y8888Y"'      `"Y8888Y"'   88   `"Ybbd8"'  `"8bbdP"Y8  88       88  
     : Fathhed                                                                                    
                                                                                         
    '''
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
