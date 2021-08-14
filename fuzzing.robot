*** Settings ***
Library  	custom_lib_2.py

*** Test Cases ***
Burp Automation test:
    [Documentation]  Burp  Automation Via Burp Rest API
    [Tags]  Discovery   Exploitation
    ${START}=       start headless burp
    log to console  ${\n}The scan started with the message "${START}"${\n}
    
    Sleep           30s

    ${INC_SCOPE}=   include scope
    log to console  ${\n}The Scope included with status "${INC_SCOPE}"${\n}

    ${VALIDATE}=    validate scope
    log to console  ${\n}Scope Validation completed with the message "${VALIDATE}"${\n}

    ${ADD_SPIDER}=  add url burp spider
    log to console  ${\n}The Burp spider started with the message "${ADD_SPIDER}"${\n}

    Sleep           10s

    ${ADD_SCAN}=    add active scan
    log to console  ${\n}The active scan has been added "${ADD_SCAN}"${\n}

    Sleep           30s

    ${STATUS}=      scan status
    log to console  ${\n}Current Scan Status: "${STATUS}"${\n}

    log to console  ${\n}You can now relax for approximately 3 minutes ${\n}

    Sleep           180s

    ${LIST}= 	    list scan issues
    log to console  ${\n}Successfully exported all the reported issues in CSV: "${LIST}"${\n}

    Sleep           10s

    ${EX_SITEMAP}=  extract sitemap
    log to console  ${\n}Successfully extracted sitemap details: "${EX_SITEMAP}"${\n}

    Sleep           10s

    ${REPORT}=      download report
    log to console  ${\n}Report Successfully downloaded "${REPORT}"${\n}

    Sleep           10s

    ${GDRIVE}=      upload reports gdrive
    log to console  ${\n}Gdrive Status: ${GDRIVE}"${\n}

    ${STOP_BURP}=   stop_burp_scan
    log to console  ${\n}Burp Stopped with status: "${STOP_BURP}"${\n}





