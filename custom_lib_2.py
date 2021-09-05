import requests
import subprocess
import time
import socket
import yaml
import os
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
import json
import pandas as pd

#update variable accordingly
URL="127.0.0.1:8081"

scope_url="https://demo.testfire.net/"

headers = { "accept": "*/*", "Content-Type": "application/json","Connection": "close"}

folder_name="reports"
slack_webhook = "https://hooks.slack.com/services/Tx2AXXXF/BXXXXX/Ecxcxcxcx"
parent_folder_id="1dhjdshjdshjhdjshjdshjdshjdhsj"

global arr
global folder_id_child
global drive
global folder_val
global display_folder



#date time for reports
date_value = os.popen('date +%F').read()
date_value=date_value.strip('\n')


#Name of CSV Report for issues.
report_name_csv="Issues_"+date_value
#Name of CSV report for sitemap
report_name_sitemap="Sitemap_"+date_value
#Downloaded HTML Report
report_downloaded="Vulnerability_Report_"+date_value



class custom_lib_2:
    ROBOT_LIBRARY_SCOPE = 'TEST CASE'

    #Start burp-rest-api service and start Burp in headless mode.
    def start_headless_burp(self):
        subprocess.Popen(
            "./burp-rest-api.sh --port=8081 --headless.mode=true --unpause-spider-and-scanner  --project-file=burp-ext/temp-project.burp --user-config-file=burp-ext/user-option.json --burp.ext=burp-ext/activeScan++.py --burp.ext=burp-ext/Asset_Discover.py --burp.ext=burp-ext/Burp-MissingScannerChecks.py --burp.ext=burp-ext/FransLinkfinder.py",shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE,close_fds=True)
        time.sleep(50)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', 8081))
        if result == 0:
            value= ("Headless Burp API Running")
        else:
            value= ("Headless Burp API Failed To Start")
        return ("Status: "+value)

    # Include an Url in scope
    def include_scope(self):
        url_1 = "http://"+URL+"/burp/target/scope?url="+scope_url
        response_1=requests.put(url_1, headers=headers)
        return (response_1.status_code)

    # Query whether a specific URL is within the current Suite-wide scope. Returns true if an url is in scope.
    def validate_scope(self):
        url_2 = "http://"+URL+"/burp/target/scope?url="+scope_url
        response_2=requests.get(url_2, headers=headers)
        if response_2.status_code == 200:
            if response_2.json()['inScope'] == True:
                value_true=str(response_2.json()['inScope'])
                domain_true=str(response_2.json()['url'])
            else:
                value_true = str(response_2.json()['inScope'])
                domain_true = str(response_2.json()['url'])

        return ("Scope URL "+ domain_true+ " is "+value_true)


    # Excludes the specified Url from the Suite-wide scope.
    def exclude_scope(self):
        url_3 = "http://"+URL+"/burp/target/scope?url="+scope_url
        response_3=requests.delete(url_3, headers=headers)
        return (response_3.status_code)

    #Sends a seed URL to the Burp Spider tool. The baseUrl should be in Suite-wide scope for the Spider to run..
    def add_url_burp_spider(self):
        url_4 = "http://"+URL+"/burp/spider?baseUrl="+scope_url
        response_4=requests.post(url_4, headers=headers)
        return (response_4.status_code)


    #Scans through Burp Sitemap and sends all HTTP requests with url starting with baseUrl to Burp Scanner for active scan.
    def add_active_scan(self):
        url_5 = "http://"+URL+"/burp/scanner/scans/active?baseUrl="+scope_url
        response_5=requests.post(url_5, headers=headers)
        return (response_5.status_code)

    # Delete the current active scan.
    def delete_scan(self):
        url_7 = "http://"+URL+"/burp/scanner/scans/active"
        response_7=requests.delete(url_7, headers=headers)
        return (response_7.status_code)

    # Returns an aggregate of percentage completed for all the scan queue items.
    def scan_status(self):
        url_8 = "http://"+URL+"/burp/scanner/status"
        response_8=requests.get(url_8, headers=headers)

        if response_8.status_code == 200:
            response_8=yaml.load(response_8.text,yaml.SafeLoader)
            if (response_8['scanPercentage']) < 100:
                #time.sleep(3600)
                time.sleep(2)
                if (response_8['scanPercentage']) == 100:
                    value="Scan completed: "+(response_8['scanPercentage'])

                else:
                    # time.sleep(7200)
                    time.sleep(2)
                    value="Scan is running for too long, downloading the report"

                return (value)

    # Returns all of the current scan issues for URLs matching the specified urlPrefix.
    def list_scan_issues(self):
        url_9 = "http://"+URL+"/burp/scanner/issues?urlPrefix="+scope_url
        response_9=requests.get(url_9, headers=headers)
        response_yaml = yaml.load(response_9.text, yaml.SafeLoader)
        try:
            if os.path.isfile(folder_name+'/'+f"{report_name_csv}"):
                os.remove(folder_name+'/'+f"{report_name_csv}")
            else:
                pass
        except:
            pass
        for key in ((response_yaml['issues'])):
            val_csv = (key['url'] + " ," + str(key['port']) + " ," + key['issueName'] + " ," + key[
                'severity'] + " ," + str(key['protocol']) + " ," + str(key['remediationDetail']) + " ," + (
                           (str(key['issueBackground'].partition(".")[0])).replace("<p>", "").replace(",", "")))
            if not os.path.exists(folder_name):
                os.makedirs(folder_name)


            with open(folder_name+'/'+f'{report_name_csv}.csv', 'a', newline='') as file:
                file.write(val_csv + "\n")
        # adding header to the csv
        df = pd.read_csv(folder_name + '/' + f"{report_name_csv}" + ".csv", error_bad_lines=False, header=None)
        df.to_csv(folder_name + '/' + f"{report_name_csv}" + ".csv",header=["Url", "Port", "Issue_Name", "Severity", "Protocol", "Remediation", "Issue_Definition"],index=False)
        file_name=(folder_name+'/'+f"{report_name_csv}"+".csv")

       #Return the CSV report with list of current issues.
        return (file_name)


     # Returns details of items in the Burp suite Site map. urlPrefix parameter can be used to specify a URL prefix, in order to extract a specific subset of the site map.
    def extract_sitemap(self):
        url_10 = "http://" + URL + "/burp/target/sitemap?urlPrefix=" + scope_url
        response_10 = requests.get(url_10, headers=headers)
        response_yaml_sitemap = yaml.load(response_10.text, yaml.SafeLoader)
        try:
            if os.path.isfile(folder_name+'/'+f"{report_name_sitemap}"):
                os.remove(folder_name+'/'+f"{report_name_sitemap}")
            else:
                pass
        except:
            pass
        for key in (response_yaml_sitemap['messages']):
            val_sitemap = (key['url']+" ,"+key['protocol']+" ,"+str(key["port"]))
            with open(folder_name+'/'+f'{report_name_sitemap}.csv', 'a', newline='') as file:
                file.write(val_sitemap + "\n")
                
        #adding header to the csv
        df = pd.read_csv(folder_name+'/'+f'{report_name_sitemap}' + ".csv", error_bad_lines=False, header=None)
        df.to_csv(folder_name+'/'+f'{report_name_sitemap}.csv',header=["Url", "Protocol", "Port"],index=False)
        file_name_sitemap = (folder_name+'/'+f"{report_name_sitemap}" + ".csv")

        # Return the CSV report with list of current issues.
        return (file_name_sitemap)

    #Generate and download report in HTML
    def download_report(self):

        url_11 = "http://"+URL+"/burp/report?reportType=HTML&urlPrefix="+scope_url
        response_11=requests.get(url_11, headers=headers)
        try:
            if os.path.isfile(folder_name+'/'+f"{report_downloaded}"):
                os.remove(folder_name+'/'+f"{report_downloaded}")
            else:
                pass
        except:
            pass
        with open(folder_name+'/'+f'{report_downloaded}.html', 'wb') as file:
            file.write(response_11.content)

        file_name_downloaded = (folder_name+'/'+f"{report_downloaded}" + ".html")

        # Return the CSV report with list of current issues.
        return (file_name_downloaded)



    def upload_reports_gdrive(self):
        gauth = GoogleAuth()
        # Try to load saved client credentials
        gauth.LoadCredentialsFile("mycreds.txt")
        if gauth.credentials is None:
            # Authenticate if they're not there
            # This is what solved the issues:
            gauth.GetFlow()
            gauth.flow.params.update({'access_type': 'offline'})
            gauth.flow.params.update({'approval_prompt': 'force'})
            gauth.LocalWebserverAuth()

        elif gauth.access_token_expired:
            # Refresh them if expired
            gauth.Refresh()
        else:
            # Initialize the saved creds
            gauth.Authorize()
        # Save the current credentials to a file
        gauth.SaveCredentialsFile("mycreds.txt")
        drive = GoogleDrive(gauth)
        folder_name_gdrive = f"{date_value}"


        folder_val = drive.CreateFile({'parents': [{'id': f'{parent_folder_id}'}], 'title': folder_name_gdrive,
                                   'mimeType': 'application/vnd.google-apps.folder'})

        # add param={'supportsTeamDrives': True} to upload into shared drive
        folder_val.Upload(param={'supportsTeamDrives': True})



        folder_id_child = folder_val['id']
        display_folder = f"https://drive.google.com/drive/folders/{folder_id_child}"
        payload = "Web Fuzzing complete, please find the attached report: " + display_folder
        arr = os.listdir(folder_name)
        # Change folder to report folder
        os.chdir(folder_name)
        for val in arr:
            file1 = drive.CreateFile({'kind': 'drive#fileLink', 'parents': [{'id': f'{folder_id_child}'}]})
            file1.SetContentFile(val)
            file1.Upload(param={'supportsTeamDrives': True})
            print(val + f" Report PDF : https://drive.google.com/file/d/{file1['id']}/view?usp=sharing",
                  end='\n')
            continue

        response = requests.post(url=slack_webhook, headers={'content-type': 'application/json'},
                                 data=json.dumps({"text": payload}))
        return ("Google Drive Link: " + display_folder)

    #stop the Burpsuite application and Api Service
    def stop_burp_scan(self):
        url_12 = "http://"+URL+"/burp/stop"
        response_12=requests.get(url_12, headers=headers)
        return (response_12.status_code)


