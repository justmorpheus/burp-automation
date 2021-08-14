# <h1 align="center" id="heading">Burp\`O\`Mation</h1>
<h2 align="center" id="heading"> Performing automated scan using Burp Suite Pro &amp; Vmware Burp Rest API with Robot Framework using Python3. </h3>

<p align="center">
   <img alt="GCP Inspector" src="https://i.ibb.co/p0QyJX0/burp-automation-2.png" width="600"/>
</p>


## Blog
**Visit blog for detailed explanation of each step.**
- [Explanation & Installation Blog](https://justm0rph3u5.medium.com/burp-automation-automating-burp-scanning-via-rest-api-robot-framework-using-python3-78aebdd35c53)

## What it does
- One click run using bash installs all the dependencies with verbose prerequisites.
- Uses python3 and robot framework which is easy to automate.
- Uses Burp Suite Rest API and runs Burp Suite Professional (pre-activated) in the headless mode along with multiple Burp Suite extension like additional-scanner-checks, BurpJSLinkFinder and active-scan-plus-plus.
- Automatically performs pentest of API/Web endpoint including scope addition and deletion using robot script.
- Automatically upload reports in CSV & HTML into Google Drive in YYYY-MM-DD format.
- Slack integration for real time alerts.

## Prerequisites (Pre-Setup).
 - **Run this before running automation.sh**
 - Debian OS(Ubuntu).
 - Activated Burp Suite Pro (burpsuite_pro_v2021.6.2.jar) with prefs.xml .
 - [Vmware Burp Suite Rest API](https://github.com/vmware/burp-rest-api) (It will be installed via automated script).
 - Python3 & Pip (It will be installed via automated script).
 - Robot Framework (It will be installed via automated script).
 - Update scope, slack webhook & Google Drive parent folder id in [custom_lib_2.py](https://github.com/justmorpheus/burp-automation/blob/master/custom_lib_2.py).
 - Setting up Google Drive authentication for [PyDrive](https://pythonhosted.org/PyDrive/quickstart.html)
 - Upload credentials (client_secrets.json & mycreds.txt) to GitHub repository for automation script.

## Installation
```
mkdir automation
cd automation
wget https://raw.githubusercontent.com/justmorpheus/burp-automation/master/automation.sh
chmod +x automation.sh
bash automation.sh https://github.com/justmorpheus/burp-automation.git
```

## Usage
`bash automation.sh https://github.com/justmorpheus/burp-automation.git`

**In case of failure**
Run the following command inside the folder `python3 -m robot -d output fuzzing.robot` .

## Note
- A big thanks to [we45](https://we45.com/blog/automating-burp-with-jenkins/), for showing this awesome work.
- This is for educational purpose as [Burp Suite](https://portswigger.net/burp/enterprise) is having enterprise license for running it in CI/CD.
- Do not use this in production, this is for learning and understanding Burp Suite Automation.
- Do not use this for illegal purposes.The author does not keep responsibility for any illegal action you do.

## Reference
- https://we45.com/blog/automating-burp-with-jenkins/
- https://burpsuite.guide/blog/activate-burpsuite-inside-docker-container/
- https://portswigger.net/burp
- https://github.com/vmware/burp-rest-api


[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](http://buymeacoffee.com/justmorpheus)


