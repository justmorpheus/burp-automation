## Burp Additonal Scanner Checks Extension
# Copyright 2017 Thomas Patzke <thomas@patzke.org>
#
# Parts of this code (DOMXSS REs) are based on work licensed under LGPL
# and can be found here:
# https://code.google.com/p/domxsswiki/wiki/FindingDOMXSS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from burp import (IBurpExtender, IScannerCheck, IScanIssue, ITab)
from javax.swing import (GroupLayout, JPanel, JCheckBox, JTextField, JLabel, JButton)
from array import array
import re
import pickle

STSMinimum = 60 * 60 * 24 * 90            # Minimum for Strict Transport Security: 90 days
issueTypeDOMXSS = 2097930
issueNameDOMXSS = "Possible DOM-based Cross-site scripting"
issueTypeSTS = 5245380
issueNameSTS = "Strict Transport Security Misconfiguration"
issueTypeXCTO = 8389890
issueNameXCTO = "Content Sniffing not disabled"
issueTypeRedirectFromHTTP2HTTPS = 5244500
issueNameRedirectFromHTTP2HTTPS = "Redirection from HTTP to HTTPS"
issueTypeXXP = 5245361
issueNameXXP = "Browser cross-site scripting filter misconfiguration"

class BurpExtender(IBurpExtender, IScannerCheck, IScanIssue, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Missing Scanner Checks")
        self.out = callbacks.getStdout()

        # define all checkboxes
        self.cbPassiveChecks = self.defineCheckBox("Passive Scanner Checks")
        self.cbDOMXSS = self.defineCheckBox("DOM XSS", False)
        self.cbDOMXSSSources = self.defineCheckBox("Sources", False)
        self.cbDOMXSSSinks = self.defineCheckBox("Sinks")
        self.cbDOMXSSjQuerySinks = self.defineCheckBox("jQuery Sinks", False)
        self.grpDOMXSSSettings = JPanel()
        self.grpDOMXSSSettings.add(self.cbDOMXSSSources)
        self.grpDOMXSSSettings.add(self.cbDOMXSSSinks)
        self.grpDOMXSSSettings.add(self.cbDOMXSSjQuerySinks)
        self.cbSTS = self.defineCheckBox("Strict Transport Security")
        self.lblSTSMin = JLabel("Minimum acceptable max-age")
        self.inSTSMin = JTextField(str(STSMinimum), 9, actionPerformed=self.setSTSMinimum) # TODO: actionPerformed only fires on enter key - focus lost would be better
        self.inSTSMin.setToolTipText("Enter the minimum max-age value which is considered as acceptable. Press return to change setting!")
        self.grpSTSSettings = JPanel()
        self.grpSTSSettings.add(self.lblSTSMin)
        self.grpSTSSettings.add(self.inSTSMin)
        self.cbXCTO = self.defineCheckBox("Content Sniffing")
        self.cbXXP = self.defineCheckBox("Client-side XSS Filter Configuration")
        self.cbRedirToHTTPS = self.defineCheckBox("Redirection from HTTP to HTTPS")
        self.btnSave = JButton("Set as default", actionPerformed=self.saveConfig)
        self.btnRestore = JButton("Restore", actionPerformed=self.restoreConfig)
        self.grpConfig = JPanel()
        self.grpConfig.add(self.btnSave)
        self.grpConfig.add(self.btnRestore)
        self.restoreConfig()

        # definition of config tab
        self.tab = JPanel()
        layout = GroupLayout(self.tab)
        self.tab.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        layout.setHorizontalGroup(
            layout.createSequentialGroup()
            .addGroup(layout.createParallelGroup()
                      .addComponent(self.cbPassiveChecks)
                      )
            .addGroup(layout.createParallelGroup()
                      .addComponent(self.cbDOMXSS)
                      .addComponent(self.cbSTS)
                      .addComponent(self.cbXCTO)
                      .addComponent(self.cbXXP)
                      .addComponent(self.cbRedirToHTTPS)
                      )
            .addGroup(layout.createParallelGroup()
                      .addComponent(self.grpDOMXSSSettings, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                      .addComponent(self.grpSTSSettings, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                      .addComponent(self.grpConfig, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                      )
            )
        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addGroup(layout.createParallelGroup()
                      .addComponent(self.cbPassiveChecks)
                      .addComponent(self.cbDOMXSS)
                      .addComponent(self.grpDOMXSSSettings, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                      )
            .addGroup(layout.createParallelGroup()
                      .addComponent(self.cbSTS)
                      .addComponent(self.grpSTSSettings, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                      )
            .addComponent(self.cbXCTO)
            .addComponent(self.cbXXP)
            .addComponent(self.cbRedirToHTTPS)
            .addComponent(self.grpConfig, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            )

        self.domXSSSourcesRE = re.compile("(location\s*[\[.])|([.\[]\s*[\"']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database)")
        # NOTE: done some optimizations here, original RE caused too much noise
        # - added leading dot in the first part - original recognized "<a href=..." etc.
        # - removed "value" in first part
        self.domXSSSinksRE = re.compile("(\.(src|href|data|location|code|action)\s*[\"'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*[\"'\]]*\s*\()")
        self.domXSSjQuerySinksRE = re.compile("after\(|\.append\(|\.before\(|\.html\(|\.prepend\(|\.replaceWith\(|\.wrap\(|\.wrapAll\(|\$\(|\.globalEval\(|\.add\(|jQUery\(|\$\(|\.parseHTML\(")
        self.headerSTSRE = re.compile("^Strict-Transport-Security:.*?max-age=\"?(\d+)\"?", re.I) # TODO: multiple max-age directives cause confusion!
        self.headerXCTORE = re.compile("^X-Content-Type-Options:\s*nosniff\s*$", re.I)
        self.headerXXP = re.compile("^X-XSS-Protection:\s*(\d)(?:\s*;\s*mode\s*=\s*\"?(block)\"?)?", re.I)
        self.headerLocationHTTPS = re.compile("^(?:Content-)?Location:\s*(https://.*)$", re.I)

        callbacks.registerScannerCheck(self)
        callbacks.addSuiteTab(self)

    def defineCheckBox(self, caption, selected=True, enabled=True):
        checkBox = JCheckBox(caption)
        checkBox.setSelected(selected)
        checkBox.setEnabled(enabled)
        return checkBox

    def setSTSMinimum(self, e=None):
        val = self.inSTSMin.text
        if re.match("^\d+$", val):
            STSMinimum = int(val)
        else:
            self.inSTSMin.setText(str(STSMinimum))   # TODO: doesn't works as desired

    def saveConfig(self, e=None):
        config = {
            'passiveChecks': self.cbPassiveChecks.isSelected(),
            'DOMXSS': self.cbDOMXSS.isSelected(),
            'DOMXSSSources': self.cbDOMXSSSources.isSelected(),
            'DOMXSSSinks': self.cbDOMXSSSinks.isSelected(),
            'DOMXSSjQuerySinks': self.cbDOMXSSjQuerySinks.isSelected(),
            'STS': self.cbSTS.isSelected(),
            'STSMin': self.inSTSMin.text,
            'XCTO': self.cbXCTO.isSelected(),
            'XXP': self.cbXXP.isSelected(),
            'RedirToHTTPS': self.cbRedirToHTTPS.isSelected(),
            }
        self.callbacks.saveExtensionSetting("config", pickle.dumps(config))

    def restoreConfig(self, e=None):
        storedConfig = self.callbacks.loadExtensionSetting("config")
        if storedConfig != None:
            try:
                config = pickle.loads(storedConfig)
                self.cbPassiveChecks.setSelected(config['passiveChecks'])
                self.cbDOMXSS.setSelected(config['DOMXSS'])
                self.cbDOMXSSSources.setSelected(config['DOMXSSSources'])
                self.cbDOMXSSSinks.setSelected(config['DOMXSSSinks'])
                self.cbDOMXSSjQuerySinks.setSelected(config['DOMXSSjQuerySinks'])
                self.cbSTS.setSelected(config['STS'])
                self.inSTSMin.text = config['STSMin'] 
                self.cbXCTO.setSelected(config['XCTO'])
                self.cbXXP.setSelected(config['XXP'])
                self.cbRedirToHTTPS.setSelected(config['RedirToHTTPS'])
                self.setSTSMinimum()
            except:
                print("Classical case of \"shouldn't happen\": something went wrong with config restore. Submit a bug or patch and keep your eyes open for Zombies. Something is really strange here.\nConfig contained: " + storedConfig)
        
    ### ITab ###
    def getTabCaption(self):
        return("Additional Scanner Checks")

    def getUiComponent(self):
        return self.tab

    ### IScannerCheck ###
    def doPassiveScan(self, baseRequestResponse):
        if not self.cbPassiveChecks.isSelected():
            return None
        scanIssues = list()
        requestProtocol = baseRequestResponse.getHttpService().getProtocol()
        analyzedResponse = self.helpers.analyzeResponse(baseRequestResponse.getResponse())
        responseHeaders = analyzedResponse.getHeaders()
        bodyOffset = analyzedResponse.getBodyOffset()
        responseBody = baseRequestResponse.getResponse()[analyzedResponse.getBodyOffset():].tostring()

        # Identify DOMXSS sources and sinks
        domXSSSources = list()
        domXSSSinks = list()
        domXSSjQuerySinks = list()
        
        if self.cbDOMXSS.isSelected():
            if self.cbDOMXSSSources.isSelected():
                domXSSSources = self.domXSSSourcesRE.finditer(responseBody)
            if self.cbDOMXSSSinks.isSelected():
                domXSSSinks = self.domXSSSinksRE.finditer(responseBody)
            if self.cbDOMXSSjQuerySinks.isSelected():
                domXSSjQuerySinks = self.domXSSjQuerySinksRE.finditer(responseBody)

            domXSSSourcesPos = extractMatchPositions(domXSSSources, bodyOffset)
            domXSSSinksPos = extractMatchPositions(domXSSSinks, bodyOffset)
            domXSSjQuerySinksPos = extractMatchPositions(domXSSjQuerySinks, bodyOffset)

            if len(domXSSSourcesPos) + len(domXSSSinksPos) + len(domXSSjQuerySinksPos) > 0: # One of the DOMXSS REs matched
                scanIssues.append(DOMXSSScanIssue(
                    baseRequestResponse,
                    domXSSSourcesPos,
                    domXSSSinksPos,
                    domXSSjQuerySinksPos,
                    self.helpers,
                    self.callbacks
                    ))

        # Identify missing, wrong or multiple occurring HTTP headers
        headersSTS = list()
        headersXCTO = list()
        headersXXP = list()
        headersLocationHTTPS = list()

        offset = 0
        for header in responseHeaders:
            if self.cbSTS.isSelected():
                match = self.headerSTSRE.match(header)
                if match:
                    headersSTS.append((match, offset))

            if self.cbXCTO.isSelected():
                match = self.headerXCTORE.match(header)
                if match:
                    headersXCTO.append(match)

            if self.cbXXP.isSelected():
                match = self.headerXXP.match(header)
                if match:
                    headersXXP.append((match, offset))

            if self.cbRedirToHTTPS.isSelected() and requestProtocol == 'http':
                match = self.headerLocationHTTPS.match(header)
                if match:
                    headersLocationHTTPS.append((match, offset))

            offset += len(header) + 2     # TODO: assumption that CRLF is always used. The world is ugly, make a real check.

        if requestProtocol != "https":
            pass                          # HSTS only valid in HTTPS responses.
        elif self.cbSTS.isSelected():
            if len(headersSTS) == 0:        # No HSTS header
                scanIssues.append(STSScanIssue(
                    baseRequestResponse,
                    STSScanIssue.caseNoHeader,
                    None,
                    self.helpers,
                    self.callbacks
                    ))
            elif len(headersSTS) == 1 and int(headersSTS[0][0].group(1)) < STSMinimum: # HSTS header present, but time frame too short
                scanIssues.append(STSScanIssue(
                    baseRequestResponse,
                    STSScanIssue.caseTooLow,
                    (int(headersSTS[0][0].group(1)), headersSTS[0][1] + headersSTS[0][0].start(1), headersSTS[0][1] + headersSTS[0][0].end(1)),
                    self.helpers,
                    self.callbacks
                    ))
            elif len(headersSTS) > 1:         # multiple HSTS headers
                scanIssues.append(STSScanIssue(
                    baseRequestResponse,
                    STSScanIssue.caseMultipleHeaders,
                    headersSTS,
                    self.helpers,
                    self.callbacks
                    ))

        # Redirection from HTTP to HTTPS
        if self.cbRedirToHTTPS.isSelected() and len(headersLocationHTTPS) > 0:
            scanIssues.append(RedirectFromHTTP2HTTPSScanIssue(
                baseRequestResponse,
                headersLocationHTTPS,
                self.helpers,
                self.callbacks                
                ))

        if self.cbXXP.isSelected():
            if len(headersXXP) == 0:          # No XSS protection header
                scanIssues.append(XXPScanIssue(
                    baseRequestResponse,
                    XXPScanIssue.caseNoHeader,
                    None,
                    self.helpers,
                    self.callbacks
                    ))
            elif len(headersXXP) == 1 and int(headersXXP[0][0].group(1)) == 1 and headersXXP[0][0].group(2) != "block":          # Activated but not in block mode
                scanIssues.append(XXPScanIssue(
                    baseRequestResponse,
                    XXPScanIssue.caseNoBlockMode,
                    headersXXP,
                    self.helpers,
                    self.callbacks
                    ))
            elif len(headersXXP) > 1:          # Multiple XXP headers
                scanIssues.append(XXPScanIssue(
                    baseRequestResponse,
                    XXPScanIssue.caseMultipleHeaders,
                    headersXXP,
                    self.helpers,
                    self.callbacks
                    ))
                # "X-XSS-Protection: 0" already catched by Burp
            

        # X-Content-Type-Options missing
        # NOTE: it is assumed that multiple "X-Content-Type-Options: nosniff" headers can't cause confusion at browser side because they all have the same meaning.
        if self.cbXCTO.isSelected() and len(headersXCTO) == 0:
            scanIssues.append(XCTOScanIssue(
                baseRequestResponse,
                self.helpers,
                self.callbacks
                ))

        return scanIssues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            if newIssue.getIssueName() == issueNameDOMXSS:   # DOMXSS issues are different if response content is different.
                responseExisting = existingIssue.getHttpMessages()[0].getResponse()
                analyzedResponseExisting = self.helpers.analyzeResponse(responseExisting)
                bodyOffsetExisting = analyzedResponseExisting.getBodyOffset()
                responseBodyExisting = responseExisting.getResponse()[analyzedResponseExisting.getBodyOffset():].tostring()

                responseNew = newIssue.getHttpMessages()[0].getResponse()
                analyzedResponseNew = self.helpers.analyzeResponse(responseNew)
                bodyOffsetNew = analyzedResponseNew.getBodyOffset()
                responseBodyNew = responseNew.getResponse()[analyzedResponseNew.getBodyOffset():].tostring()

                if responseBodyExisting == responseBodyNew:
                    return -1
                else:
                    return 0
            elif newIssue.getIssueName() == issueNameRedirectFromHTTP2HTTPS: # Redirection issues are different if target URLs differ
                if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
                    return -1
                else:
                    return 0
            else:                         # In all other cases: keep existing issue
                return -1
        return 0

class DOMXSSScanIssue(IScanIssue):
    def __init__(self, requestResponse, sourcesPos, sinksPos, jQuerySinksPos, helpers, callbacks):
        analyzedRequest = helpers.analyzeRequest(requestResponse)
        self.findingUrl = analyzedRequest.getUrl()
        self.sourcesPos = sourcesPos
        self.sinksPos = sinksPos + jQuerySinksPos
        self.requestResponse = callbacks.applyMarkers(requestResponse, None, normalizePositions(self.sourcesPos + self.sinksPos))

    def getUrl(self):
        return self.findingUrl

    def getIssueName(self):
        return issueNameDOMXSS

    def getIssueType(self):
        return issueTypeDOMXSS

    def getSeverity(self):
        if len(self.sinksPos) > 0:
            return "High"
        else:
            return "Low"

    def getConfidence(self):
        return "Tentative"

    def getIssueBackground(self):
        msg = "<p>DOM-based cross-site scripting (XSS) is a variant of the well-known XSS vulnerabilities where the issue is located in client-side JavaScript code. \
        As in classical XSS, the vulnerability causes code execution in the context of the users session within the application. An attacker can perform a wide \
        variety of actions, like session hijacking etc. The vulnerability is caused by copying data from non-trustworthy sources (user input, URL) into the DOM with \
        insecure methods.</p> \
        <p>Such vulnerabilities are hard to detect with classical methods like checking the response for occurrences of previous inputs or parameters. This scan \
        issue has detected the usage of insecure sources or sinks in the JavaScript code of the page. Further manual checks must be performed to verify the impact \
        of their usage.</p>"
        return msg

    def getRemediationBackground(self):
        msg = "DOM-based XSS can be prevented by usage of secure methods that only operate on the content text of the DOM instead of modifying the DOM structure. E.g. \
        usage of the innerText attribute instead of innerHTML or the text() method of jQuery instead of html() to insert user content into the DOM. If these methods are \
        not applicable in a particular use case, the user input has to be filtered and sanitized before it is passed into the DOM by insecure methods."
        return msg

    def getIssueDetail(self):
        msg = "The scanner check has detected occurrences of unsafe "
        if len(self.sinksPos) > 0 and len(self.sourcesPos) > 0:
            msg += "sources and sinks. If data flows from unsafe sources into unsafe sinks without being sanitized then it is quite certain that the web application is \
            vulnerable against DOM-based XSS. "
        elif len(self.sinksPos) > 0:
            msg += "sinks. Be aware that there are potential unsafe sources which are not detected by the patterns used in the scanner check, e.g. data loaded by the \
            XmlHttpRequest API. Furthermore there is the possibility that the sources and sinks are distributed in different files. "
        elif len(self.sourcesPos) > 0:
            msg += "sources. Generally there must be a sink for code execution caused by unsafe sources. This could be located in a different part of the web application \
            or be unrecognized by the scanner module. "
        msg += "See the response tab to review the occurrences."
        return msg

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return [self.requestResponse]

    def getHttpService(self):
        return self.requestResponse.getHttpService()


class STSScanIssue(IScanIssue):
    caseNoHeader = 1
    caseTooLow = 2
    caseMultipleHeaders = 3
    
    def __init__(self, requestResponse, case, data, helpers, callbacks):
        analyzedRequest = helpers.analyzeRequest(requestResponse)
        self.findingUrl = analyzedRequest.getUrl()
        self.case = case
        self.data = data
        self.STSMinimum = STSMinimum
        if case == self.caseNoHeader:
            self.requestResponse = requestResponse
        elif case == self.caseTooLow:
            self.requestResponse = callbacks.applyMarkers(requestResponse, None, [array('i', (data[1], data[2]))])
        elif case == self.caseMultipleHeaders:
            self.requestResponse = callbacks.applyMarkers(requestResponse, None, normalizePositions(extractMatchPositions(data)))

    def getUrl(self):
        return self.findingUrl

    def getIssueName(self):
        return issueNameSTS

    def getIssueType(self):
        return issueTypeSTS

    def getSeverity(self):
        return "Medium"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "<p>The HTTP Strict Transport Security policy defines a timeframe where a browser must connect to the web server via HTTPS. Without a Strict Transport \
        Security policy the web application may be vulnerable against several attacks:</p> \
        <ul> \
        <li>If the web application mixes usage of HTTP and HTTPS, an attacker can manipulate pages in the unsecured area of the application or change redirection targets \
        in a manner that the switch to the secured page is not performed or done in a manner, that the attacker remains between client and server.</li> \
        <li>If there is no HTTP server, an attacker in the same network could simulate a HTTP server and motivate the user to click on a prepared URL by a social \
        engineering attack.</li> \
        </ul> \
        <p>The protection is effective only for the given amount of time. Multiple occurrence of this header could cause undefined behaviour in browsers and should be avoided.</p>"
        return msg

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        msg = None
        if self.case == self.caseNoHeader:
            msg = "There was no \"Strict-Transport-Security\" header in the server response."
        elif self.case == self.caseTooLow:
            msg = "A \"Strict-Transport-Security\" header was set in the server response and the time frame was set to " + str(self.data[0]) + ". This is considered as too low."
        elif self.case == self.caseMultipleHeaders:
            msg = "Multiple occurrences of the \"Strict-Transport-Security\" header were seen in the HTTP response. This could cause undefined behaviour with browsers, \
            because it is unclear, which header is used."
        return msg

    def getRemediationDetail(self):
        msg = None
        if self.case == self.caseNoHeader:
            msg = "<p>A Strict-Transport-Security HTTP header should be sent with each HTTPS response. The syntax is as follows:</p> \
            <p><pre>Strict-Transport-Security: max-age=&lt;seconds&gt;[; includeSubDomains]</pre></p> \
            <p>The parameter <i>max-age</i> gives the time frame for requirement of HTTPS in seconds and should be chosen quite high, e.g. several months.\
            A value below " + str(self.STSMinimum) + " is considered as too low by this scanner check. \
            The flag <i>includeSubDomains</i> defines that the policy applies also for sub domains of the sender of the response.</p>"
        elif self.case == self.caseTooLow:
            msg = "The given time frame should be increased to a minimum of " + str(self.STSMinimum) + " seconds."
        elif self.case == self.caseMultipleHeaders:
            msg = "There should be only one header defining a strict transport security policy. The Time frame should be set at minimum to " + str(self.STSMinimum) + "."
        return msg

    def getHttpMessages(self):
        return [self.requestResponse]

    def getHttpService(self):
        return self.requestResponse.getHttpService()


class RedirectFromHTTP2HTTPSScanIssue(IScanIssue):
    def __init__(self, requestResponse, headers, helpers, callbacks):
        analyzedRequest = helpers.analyzeRequest(requestResponse)
        self.findingUrl = analyzedRequest.getUrl()
        self.redirectURLs = map(lambda(header): header[0].group(1), headers)
        self.redirectURLs.sort()
        self.requestResponse = callbacks.applyMarkers(requestResponse, None, normalizePositions(extractMatchPositions(headers)))

    def getUrl(self):
        return self.findingUrl

    def getIssueName(self):
        return issueNameRedirectFromHTTP2HTTPS

    def getIssueType(self):
        return issueTypeRedirectFromHTTP2HTTPS

    def getSeverity(self):
        return "Medium"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        msg = "The redirection to a HTTPS URL is transmitted over the insecure HTTP protocol. This makes the redirection itself vulnerable against Man-in-the-Middle attacks. \
        An attacker could redirect the user to a slightly different HTTPS URL which is under his control or keep the connection unencrypted by stripping down to HTTP and relaying \
        between client and server."
        return msg

    def getRemediationBackground(self):
        msg = "<p>Usage of HTTP should be kept at a minimum in web applications where security matters. Users which enter the web application via HTTP, e.g. by entering only the domain name in the \
        URL bar of their browser should be redirected directly to a secure HTTPS URL. All HTTPS resources should provide a Strict-Transport-Security header which ensures that the \
        browser uses only HTTPS for a given amount of time. The syntax for this header is as follows:</p> \
        <p><pre>Strict-Transport-Security: max-age=&lt;seconds&gt;[; includeSubDomains]</pre></p> \
        <p>The parameter <i>max-age</i> gives the time frame for requirement of HTTPS in seconds and should be chosen quite high, e.g. several months. Except the initial redirection the \
        application should be used completely with HTTPS.</p>"
        return msg

    def getIssueDetail(self):
        msg = "The web application redirects the browser from HTTP to the following HTTPS URL"
        if len(self.redirectURLs) == 1:
            msg += ": <b>" + self.redirectURLs[0] + "</b>"
        else:
            msg += "s: <ul>"
            for redirectURL in self.redirectURLs:
                msg += "<li>" + redirectURL + "</li>"
            msg += "</ul><p>Multiple headers were given. The redirection target depends on the used browser.</p>"
        return msg

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return [self.requestResponse]

    def getHttpService(self):
        return self.requestResponse.getHttpService()


class XXPScanIssue(IScanIssue):
    caseNoHeader = 1
    caseNoBlockMode = 2
    caseMultipleHeaders = 3
    
    def __init__(self, requestResponse, case, headers, helpers, callbacks):
        analyzedRequest = helpers.analyzeRequest(requestResponse)
        self.findingUrl = analyzedRequest.getUrl()
        self.case = case
        self.headers = headers
        if case == self.caseNoHeader:
            self.requestResponse = requestResponse
        elif case == self.caseNoBlockMode:
            self.requestResponse = callbacks.applyMarkers(requestResponse, None, [array('i', (headers[0][1], headers[0][1] + headers[0][0].end(0)))])
        elif case == self.caseMultipleHeaders:
            self.requestResponse = callbacks.applyMarkers(requestResponse, None, normalizePositions(extractMatchPositions(headers)))

    def getUrl(self):
        return self.findingUrl

    def getIssueName(self):
        return issueNameXXP

    def getIssueType(self):
        return issueTypeXXP

    def getSeverity(self):
        return "Low"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "Cross-site scripting (XSS) filters in browsers check if the URL contains possible harmful XSS payloads and if they are reflected in the response page. If \
        such a condition is recognized, the injected code is changed in a way, that it is not executed anymore to prevent a succesful XSS attack. The downside of these filters \
        is, that the browser has no possibility to distinguish between code fragments which were reflected by a vulnerable web application in an XSS attack and these which are \
        already present on the page. In the past, these filters were used by attackers to deactivate JavaScript code on the attacked web page. Sometimes the XSS filters itself are \
        vulnerable in a way, that web applications which were protected properly against XSS attacks became vulnerable under certain conditions."

    def getRemediationBackground(self):
        return "It is considered as better practice to instruct the browser XSS filter to never render the web page if an XSS attack is detected."

    def getIssueDetail(self):
        msg = None
        if self.case == self.caseNoHeader:
            msg = "No X-XSS-Protection header was set in the response. This means that the browser uses default behavior that detection of a cross-site scripting attack never prevents rendering."
        elif self.case == self.caseNoBlockMode:
            msg = "A X-XSS-Protection header is set and XSS protection is enabled, but blocking mode is not set."
        elif self.case == self.caseMultipleHeaders:
            msg = "Multiple occurrences of the \"X-XSS-Protection\" header were seen in the HTTP response. This could cause undefined behaviour with browsers, \
            because it is unclear, which header is used."
        return msg

    def getRemediationDetail(self):
        msg = None
        if self.case == self.caseNoHeader:
            msg = "<p>The following header should be set:</p> \
            <p><pre>X-XSS-Protection: 1; mode=block</pre></p>"
        elif self.case == self.caseNoBlockMode:
            msg = "<p>Set the option \"mode=block\" in the X-XSS-Protection HTTP header as follows:</p> \
            <p><pre>X-XSS-Protection: 1; mode=block</pre></p>"
        elif self.case == self.caseMultipleHeaders:
            msg = "There should be only one X-XSS-Protection header present."
        return msg

    def getHttpMessages(self):
        return [self.requestResponse]

    def getHttpService(self):
        return self.requestResponse.getHttpService()


class XCTOScanIssue(IScanIssue):
    def __init__(self, requestResponse, helpers, callbacks):
        analyzedRequest = helpers.analyzeRequest(requestResponse)
        self.findingUrl = analyzedRequest.getUrl()
        self.requestResponse = requestResponse

    def getUrl(self):
        return self.findingUrl

    def getIssueName(self):
        return issueNameXCTO

    def getIssueType(self):
        return issueTypeXCTO

    def getSeverity(self):
        return "Low"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        msg = "There was no \"X-Content-Type-Options\" HTTP header with the value <i>nosniff</i> set in the response. The lack of this header causes that certain browsers, \
        try to determine the content type and encoding of the response even when these properties are defined correctly. This can make the web application \
        vulnerable against Cross-Site Scripting (XSS) attacks. E.g. the Internet Explorer and Safari treat responses with the content type text/plain as HTML, if they contain \
        HTML tags."
        return msg

    def getRemediationBackground(self):
        msg = "Set the following HTTP header at least in all responses which contain user input: <pre>X-Content-Type-Options: nosniff</pre>"
        return msg

    def getIssueDetail(self):
        return None

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return [self.requestResponse]

    def getHttpService(self):
        return self.requestResponse.getHttpService()


### Helpers ###
# Sort and merge overlapping match ranges - needed by Burp for scan issue markers
def normalizePositions(uPos):
    sortedPos = sorted(uPos)
    normPos = list()
    prevPos = None
    for pos in sortedPos:
        if not prevPos:
            prevPos = pos
        elif prevPos[1] > pos[0]:
            if prevPos[1] < pos[1]:
                prevPos[1] = pos[1]
        else:
            normPos.append(prevPos)
            prevPos = pos
    normPos.append(prevPos)
    return normPos

# extract match positions from an array of matches as expected by Burp for scan issue markers
def extractMatchPositions(matches, bodyOffset = 0):
    try:
        if isinstance(matches, list) and isinstance(matches[0], tuple):
            return map(lambda(match, offset): array('i', (match.start() + bodyOffset + offset, match.end() + bodyOffset + offset)), matches)
        else:
            return map(lambda(match): array('i', (match.start() + bodyOffset, match.end() + bodyOffset)), matches)
    except IndexError:
        return list()
