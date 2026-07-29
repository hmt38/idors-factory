#!/usr/bin/env python
# -*- coding: utf-8 -*-

from operator import truediv
import sys
reload(sys)

if (sys.version_info[0] == 2):
    sys.setdefaultencoding('utf8')

sys.path.append("..")

from helpers.http import get_authorization_header_from_message, get_cookie_header_from_message, isStatusCodesReturned, makeMessage, makeRequest, getResponseBody, IHttpRequestResponseImplementation
from gui.table import LogEntry, UpdateTableEDT
from db.database import DatabaseManager
from javax.swing import SwingUtilities
from java.net import URL
import re
import json
from java.lang import Runnable

class HandleMessageRunnable(Runnable):
    def __init__(self, extender, toolFlag, messageIsRequest, messageInfo):
        self.extender = extender
        self.toolFlag = toolFlag
        self.messageIsRequest = messageIsRequest
        self.messageInfo = messageInfo

    def run(self):
        handle_message(self.extender, self.toolFlag, self.messageIsRequest, self.messageInfo)

def tool_needs_to_be_ignored(self, toolFlag):
    for i in range(0, self.IFList.getModel().getSize()):
        if self.IFList.getModel().getElementAt(i).split(":")[0] == "Ignore spider requests":
            if (toolFlag == self._callbacks.TOOL_SPIDER):
                return True
        if self.IFList.getModel().getElementAt(i).split(":")[0] == "Ignore proxy requests":
            if (toolFlag == self._callbacks.TOOL_PROXY):
                return True
        if self.IFList.getModel().getElementAt(i).split(":")[0] == "Ignore target requests":
            if (toolFlag == self._callbacks.TOOL_TARGET):
                return True
    return False

def capture_last_cookie_header(self, messageInfo):
    cookies = get_cookie_header_from_message(self, messageInfo)
    if cookies:
        self.lastCookiesHeader = cookies
        if hasattr(self, 'userTab') and self.userTab:
            for user_id, user_data in self.userTab.user_tabs.items():
                user_data['headers_instance'].fetchCookiesHeaderButton.setEnabled(True)

def capture_last_authorization_header(self, messageInfo):
    authorization = get_authorization_header_from_message(self, messageInfo)
    if authorization:
        self.lastAuthorizationHeader = authorization
        if hasattr(self, 'userTab') and self.userTab:
            for user_id, user_data in self.userTab.user_tabs.items():
                user_data['headers_instance'].fetchAuthorizationHeaderButton.setEnabled(True)

def valid_tool(self, toolFlag):
    result = (toolFlag == self._callbacks.TOOL_PROXY or
              (toolFlag == self._callbacks.TOOL_REPEATER and
               self.interceptRequestsfromRepeater.isSelected()))
    return result

def handle_304_status_code_prevention(self, messageIsRequest, messageInfo):
    should_prevent = False
    if self.prevent304.isSelected():
        if messageIsRequest:
            requestHeaders = list(self._helpers.analyzeRequest(messageInfo).getHeaders())
            newHeaders = list()
            for header in requestHeaders:
                if not "If-None-Match:" in header and not "If-Modified-Since:" in header:
                    newHeaders.append(header)
                    should_prevent = True
        if should_prevent:
            requestInfo = self._helpers.analyzeRequest(messageInfo)
            bodyBytes = messageInfo.getRequest()[requestInfo.getBodyOffset():]
            bodyStr = self._helpers.bytesToString(bodyBytes)
            messageInfo.setRequest(self._helpers.buildHttpMessage(newHeaders, bodyStr))

def message_not_from_autorize(self, messageInfo):
    headers = self._helpers.analyzeRequest(messageInfo).getHeaders()
    if hasattr(self, 'userTab') and self.userTab:
        for user_id, user_data in self.userTab.user_tabs.items():
            headers_text = user_data['headers_instance'].replaceString.getText()
            if headers_text in headers:
                return False
    return True

def no_filters_defined(self):
    return self.IFList.getModel().getSize() == 0

def message_passed_interception_filters(self, messageInfo):
    if messageInfo.getResponse() is None:
        return False
    urlString = str(self._helpers.analyzeRequest(messageInfo).getUrl())
    reqInfo = self._helpers.analyzeRequest(messageInfo)
    reqBodyBytes = messageInfo.getRequest()[reqInfo.getBodyOffset():]
    bodyStr = self._helpers.bytesToString(reqBodyBytes)

    resInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
    resBodyBytes = messageInfo.getResponse()[resInfo.getBodyOffset():]
    resStr = self._helpers.bytesToString(resBodyBytes)

    for i in range(0, self.IFList.getModel().getSize()):
        interceptionFilter = self.IFList.getModel().getElementAt(i)
        try:
            interceptionFilterTitle, interceptionFilterContent = interceptionFilter.split(":", 1)
            interceptionFilterContent = interceptionFilterContent[1:]
        except Exception as e:
            print(interceptionFilter)
            print(e)
            continue

        if interceptionFilterTitle == "Scope items only":
            currentURL = URL(urlString)
            if not self._callbacks.isInScope(currentURL):
                return False

        if interceptionFilterTitle == "URL Contains (simple string)":
            if interceptionFilterContent not in urlString:
                return False

        if interceptionFilterTitle == "URL Contains (regex)":
            regex_string = interceptionFilterContent
            if re.search(regex_string, urlString, re.IGNORECASE) is None:
                return False

        if interceptionFilterTitle == "URL Not Contains (simple string)":
            if interceptionFilterContent in urlString:
                return False

        if interceptionFilterTitle == "URL Not Contains (regex)":
            regex_string = interceptionFilterContent
            if not re.search(regex_string, urlString, re.IGNORECASE) is None:
                return False

        if interceptionFilterTitle == "Request Body contains (simple string)":
            if interceptionFilterContent not in bodyStr:
                return False

        if interceptionFilterTitle == "Request Body contains (regex)":
            regex_string = interceptionFilterContent
            if re.search(regex_string, bodyStr, re.IGNORECASE) is None:
                return False

        if interceptionFilterTitle == "Request Body NOT contains (simple string)":
            if interceptionFilterContent in bodyStr:
                return False

        if interceptionFilterTitle == "Request Body Not contains (regex)":
            regex_string = interceptionFilterContent
            if not re.search(regex_string, bodyStr, re.IGNORECASE) is None:
                return False

        if interceptionFilterTitle == "Response Body contains (simple string)":
            if interceptionFilterContent not in resStr:
                return False

        if interceptionFilterTitle == "Response Body contains (regex)":
            regex_string = interceptionFilterContent
            if re.search(regex_string, resStr, re.IGNORECASE) is None:
                return False

        if interceptionFilterTitle == "Response Body NOT contains (simple string)":
            if interceptionFilterContent in resStr:
                return False

        if interceptionFilterTitle == "Response Body Not contains (regex)":
            regex_string = interceptionFilterContent
            if not re.search(regex_string, resStr, re.IGNORECASE) is None:
                return False

        if interceptionFilterTitle == "Request headers contain":
            if not any([
                interceptionFilterContent in h 
                for h in reqInfo.getHeaders()
            ]):
                return False

        if interceptionFilterTitle == "Request headers don't contain":
            if any([
                interceptionFilterContent in h 
                for h in reqInfo.getHeaders()
            ]):
                return False

        if interceptionFilterTitle == "Response headers contain":
            if not any([
                interceptionFilterContent in h 
                for h in resInfo.getHeaders()
            ]):
                return False

        if interceptionFilterTitle == "Response headers don't contain":
            if any([
                interceptionFilterContent in h 
                for h in resInfo.getHeaders()
            ]):
                return False

        if interceptionFilterTitle == "Only HTTP methods (newline separated)":
            filterMethods = interceptionFilterContent.split("\n")
            filterMethods = [x.lower() for x in filterMethods]
            reqMethod = str(self._helpers.analyzeRequest(messageInfo).getMethod())
            if reqMethod.lower() not in filterMethods:
                return False

        if interceptionFilterTitle == "Ignore HTTP methods (newline separated)":
            filterMethods = interceptionFilterContent.split("\n")
            filterMethods = [x.lower() for x in filterMethods]
            reqMethod = str(self._helpers.analyzeRequest(messageInfo).getMethod())
            if reqMethod.lower() in filterMethods:
                return False

        if interceptionFilterTitle == "Ignore OPTIONS requests":
            reqMethod = str(self._helpers.analyzeRequest(messageInfo).getMethod())
            if reqMethod == "OPTIONS":
                return False

    return True

def handle_message(self, toolFlag, messageIsRequest, messageInfo):
    if tool_needs_to_be_ignored(self, toolFlag):
        return

    capture_last_cookie_header(self, messageInfo)
    capture_last_authorization_header(self, messageInfo)

    _valid = valid_tool(self, toolFlag)
    process_for_table = (self.intercept and _valid) or toolFlag == "AUTORIZE"

    if process_for_table:
        handle_304_status_code_prevention(self, messageIsRequest, messageInfo)

        if not messageIsRequest:
            # Check if this traffic belongs to User A or User B and save to DB
            identify_and_save_traffic(self, messageInfo)

            if message_not_from_autorize(self, messageInfo):
                if self.ignore304.isSelected():
                    if isStatusCodesReturned(self, messageInfo, ["304", "204"]):
                        return

                if no_filters_defined(self):
                    checkAuthorizationAllUsers(self, messageInfo, self.doUnauthorizedRequest.isSelected())
                else:
                    if message_passed_interception_filters(self, messageInfo):
                        checkAuthorizationAllUsers(self, messageInfo, self.doUnauthorizedRequest.isSelected())

def identify_and_save_traffic(self, messageInfo):
    try:
        # We need to inspect headers to see if they match any User Identifier
        reqInfo = self._helpers.analyzeRequest(messageInfo)
        headers = list(reqInfo.getHeaders())
        headers_str = "\n".join(headers)
        
        user_identifier = None
        
        # Iterate over all configured users in UserTab
        if hasattr(self, 'userTab') and self.userTab:
            for user_id, user_data in self.userTab.user_tabs.items():
                # Check if this user has an identifier configured
                if 'headers_instance' in user_data:
                    headers_inst = user_data['headers_instance']
                    if hasattr(headers_inst, 'userIdentifierString'):
                        ident_str = headers_inst.userIdentifierString.getText().strip()
                        if ident_str and ident_str in headers_str:
                            # Match found!
                            # In requirements we used 'A' and 'B', but here we have dynamic users.
                            # Let's map User 1 -> A, User 2 -> B, etc. or just use the user_id/name.
                            # For simplicity and compatibility with our requirements doc, let's try to map:
                            # User 1 is usually the Attacker (User A)
                            # User 2 is usually the Victim (User B)
                            # But Autorize logic is: "High privileged user" (User A) runs in browser (original request),
                            # and Autorize replays as "Low privileged user" (User B).
                            # Wait, Autorize standard flow:
                            # 1. Capture High Priv request (Cookie A)
                            # 2. Replay with Low Priv session (Cookie B)
                            #
                            # Our new IDOR flow:
                            # 1. Capture User A traffic (Cookie A) -> Save as User A
                            # 2. Capture User B traffic (Cookie B) -> Save as User B
                            # 
                            # So we need to know if the CURRENT request being captured is from A or B.
                            # The user configures "User Identifier" in the User Tab.
                            # If I browse as User A, headers contain Cookie A.
                            # If I browse as User B, headers contain Cookie B.
                            
                            user_identifier = str(user_data['user_name']) # e.g. "User 1"
                            break
        
        if user_identifier:
            print("[IDOR] Found traffic for " + user_identifier)
            # Extract details
            method = reqInfo.getMethod()
            url = str(reqInfo.getUrl())
            host = reqInfo.getUrl().getHost()
            path = reqInfo.getUrl().getPath()
            
            # Body
            reqBodyBytes = messageInfo.getRequest()[reqInfo.getBodyOffset():]
            body = self._helpers.bytesToString(reqBodyBytes)
            
            # Response Data (New)
            response_headers = None
            response_body = None
            if messageInfo.getResponse():
                resInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
                res_headers_list = list(resInfo.getHeaders())
                response_headers = json.dumps(res_headers_list)
                
                resBodyBytes = messageInfo.getResponse()[resInfo.getBodyOffset():]
                response_body = self._helpers.bytesToString(resBodyBytes)

            # Query Params
            query_params = {}
            parameters = reqInfo.getParameters()
            for p in parameters:
                if p.getType() == 0: # PARAM_URL
                    query_params[p.getName()] = p.getValue()
            
            # Save to DB
            if not hasattr(self, 'db_manager') or self.db_manager is None:
                print("[IDOR] db_manager not ready, skipping save (will retry next traffic)")
                return

            # Map "User 1" to "A", "User 2" to "B" for consistency with requirements if desired,
            # or just store "User 1", "User 2". Let's store "User 1", "User 2" for now as it's more flexible.
            
            save_result = self.db_manager.save_raw_request(
                method, host, url, path, headers, query_params, body, user_identifier, response_headers, response_body
            )
            
            if save_result:
                print("[IDOR] Saved request for " + user_identifier + ": " + url + " (ID: " + str(save_result) + ")")
            
    except Exception as e:
        print("[IDOR] Error saving traffic: " + str(e))
        import traceback
        traceback.print_exc()

def checkAuthorizationAllUsers(self, messageInfo, checkUnauthorized=True):
    if not getattr(self, 'userTab', None) or not hasattr(self.userTab, 'user_tabs'):
        return
    originalHeaders = self._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders()

    requestResponseUnauthorized = None
    impressionUnauthorized = "Disabled"

    all_headers_texts = []
    if hasattr(self, 'userTab') and self.userTab:
        for uid, udata in self.userTab.user_tabs.items():
            all_headers_texts.append(udata['headers_instance'].replaceString.getText())
    combined_headers_text = "\n".join(all_headers_texts) if all_headers_texts else ""
    
    if checkUnauthorized:
        messageUnauthorized = makeMessage(self, messageInfo, True, False, combined_headers_text)
        requestResponseUnauthorized = makeRequest(self, messageInfo, messageUnauthorized)
        if requestResponseUnauthorized and requestResponseUnauthorized.getResponse():
            unauthorizedResponse = requestResponseUnauthorized.getResponse()
            analyzedResponseUnauthorized = self._helpers.analyzeResponse(unauthorizedResponse)
            statusCodeUnauthorized = analyzedResponseUnauthorized.getHeaders()[0]
            contentUnauthorized = getResponseBody(self, requestResponseUnauthorized)

            oldStatusCode = originalHeaders[0]
            oldContent = getResponseBody(self, messageInfo)

            EDFiltersUnauth = self.EDModelUnauth.toArray()
            impressionUnauthorized = checkBypass(self, oldStatusCode, statusCodeUnauthorized,
                                                oldContent, contentUnauthorized,
                                                EDFiltersUnauth, requestResponseUnauthorized,
                                                self.AndOrTypeUnauth.getSelectedItem())
        else:
            pass

    # Do all slow work (makeRequest, getText, etc.) WITHOUT holding the lock so Clear table
    # and other threads can acquire it quickly and we avoid deadlock / long stalls.
    method = self._helpers.analyzeRequest(messageInfo.getRequest()).getMethod()
    original_url = self._helpers.analyzeRequest(messageInfo).getUrl()

    logEntry = LogEntry(None,  # ID assigned inside lock to avoid duplicates when concurrent
                        method,
                        original_url,
                        messageInfo,
                        requestResponseUnauthorized if checkUnauthorized else None,
                        impressionUnauthorized)

    for user_id, user_data in self.userTab.user_tabs.items():
        user_name = user_data['user_name']
        ed_instance = user_data['ed_instance']
        mr_instance = user_data['mr_instance']
        headers_instance = user_data['headers_instance']
        user_headers_text = headers_instance.replaceString.getText()
        mr_model = _get_mr_model(mr_instance)
        mr_rule_count = mr_model.getSize() if mr_model else 0

        print(
            "[Autorize] Building user request for {} with {} match/replace rules".format(
                user_name, mr_rule_count
            )
        )

        isolated_rule_count = _get_isolated_mr_rule_count(mr_instance)
        if isolated_rule_count != mr_rule_count:
            print(
                "[Autorize] MR model mismatch for {} => public: {} | isolated: {}".format(
                    user_name, mr_rule_count, isolated_rule_count
                )
            )

        message = makeUserMessage(self, messageInfo, True, True, mr_instance, user_headers_text)

        header_add_set_rules = []
        if mr_model:
            for i in range(mr_model.getSize()):
                rule_key = mr_model.getElementAt(i)
                rule_data = _get_rule_data(mr_instance, rule_key)
                if rule_data and rule_data.get('type') == "Header Add/Set:":
                    header_add_set_rules.append(rule_data.get('match', '').strip())

        if header_add_set_rules:
            built_headers = list(self._helpers.analyzeRequest(message).getHeaders())
            present_headers = []
            missing_headers = []
            for header_name in header_add_set_rules:
                header_prefix = header_name.lower() + ":"
                if any(h.lower().startswith(header_prefix) for h in built_headers[1:]):
                    present_headers.append(header_name)
                else:
                    missing_headers.append(header_name)
            print(
                "[Autorize] Header Add/Set check for {} => present: {} | missing: {}".format(
                    user_name,
                    ", ".join(present_headers) if present_headers else "-",
                    ", ".join(missing_headers) if missing_headers else "-"
                )
            )

        requestResponse = makeRequest(self, messageInfo, message)

        if requestResponse and requestResponse.getResponse():
            newResponse = requestResponse.getResponse()
            try:
                if not newResponse or len(newResponse) == 0:
                    pass
                else:
                    analyzedResponse = self._helpers.analyzeResponse(newResponse)
                    headers = analyzedResponse.getHeaders()
                    if not headers:
                        pass
                    else:
                        newStatusCode = headers[0]
                        oldContent = getResponseBody(self, messageInfo)
                        newContent = getResponseBody(self, requestResponse)

                        EDFilters = ed_instance.EDModel.toArray()
                        impression = checkBypass(self, originalHeaders[0], newStatusCode, oldContent, newContent,
                                               EDFilters, requestResponse, ed_instance.AndOrType.getSelectedItem())

                        savedRequestResponse = self._callbacks.saveBuffersToTempFiles(requestResponse)
                        logEntry.add_user_enforcement(user_id, savedRequestResponse, impression, message)
            except (IndexError, Exception) as e:
                pass
        else:
            pass

    self._lock.acquire()
    try:
        logEntry._id = self.currentRequestNumber
        row = self._log.size()
        self._log.add(logEntry)
        SwingUtilities.invokeLater(UpdateTableEDT(self,"insert",row,row))
        self.currentRequestNumber += 1
    except Exception as e:
        raise
    finally:
        self._lock.release()

def _get_rule_data(mr_instance, rule_key):
    rule_store = _get_rule_store(mr_instance)
    if rule_store is None:
        return None

    rule_data = rule_store.get(rule_key)
    if rule_data is not None:
        return rule_data

    try:
        rule_key_str = str(rule_key)
    except Exception:
        rule_key_str = rule_key

    return rule_store.get(rule_key_str)

def _get_rule_store(mr_instance):
    rule_store = getattr(mr_instance, 'badProgrammerMRModel', None)
    if rule_store:
        return rule_store

    isolated = getattr(mr_instance, 'isolated_extender', None)
    if isolated is not None:
        return getattr(isolated, 'badProgrammerMRModel', None)

    return None

def _get_mr_model(mr_instance):
    isolated = getattr(mr_instance, 'isolated_extender', None)
    if isolated is not None:
        isolated_model = getattr(isolated, 'MRModel', None)
        if isolated_model is not None and getattr(isolated_model, 'getSize', None):
            return isolated_model

    mr_model = getattr(mr_instance, 'MRModel', None)
    if mr_model is not None and getattr(mr_model, 'getSize', None):
        return mr_model

    return None

def _get_isolated_mr_rule_count(mr_instance):
    isolated = getattr(mr_instance, 'isolated_extender', None)
    if isolated is None:
        return 0

    isolated_model = getattr(isolated, 'MRModel', None)
    if isolated_model is None or not getattr(isolated_model, 'getSize', None):
        return 0

    return isolated_model.getSize()

def _set_query_param_in_request_line(request_line, param_key, param_value):
    try:
        parts = request_line.split(" ")
        if len(parts) < 3:
            return request_line

        method = parts[0]
        uri = parts[1]
        version = " ".join(parts[2:])

        if "?" in uri:
            path_part, query_string = uri.split("?", 1)
        else:
            path_part, query_string = uri, ""

        query_pairs = []
        found = False
        if query_string:
            for pair in query_string.split("&"):
                if pair == "":
                    continue
                if "=" in pair:
                    key, value = pair.split("=", 1)
                else:
                    key, value = pair, ""

                if key == param_key:
                    query_pairs.append("{}={}".format(param_key, param_value))
                    found = True
                else:
                    query_pairs.append(pair)

        if not found:
            query_pairs.append("{}={}".format(param_key, param_value))

        new_uri = path_part
        if query_pairs:
            new_uri += "?" + "&".join(query_pairs)

        return "{} {} {}".format(method, new_uri, version)
    except Exception:
        return request_line

def apply_user_rules_to_request_components(self, request_line, header_lines, body_text, mr_instance, user_headers_text="", apply_user_header_text=True):
    headers = [request_line] + list(header_lines or [])
    mr_model = _get_mr_model(mr_instance)

    def parse_header_lines(header_text):
        parsed = []
        if not header_text:
            return parsed

        for line in header_text.split('\n'):
            line = line.strip()
            if not line or ':' not in line:
                continue
            name, value = line.split(':', 1)
            name = name.strip()
            value = value.strip()
            if name:
                parsed.append((name, value))
        return parsed

    def upsert_header(header_lines_only, header_name, header_value):
        if not header_name:
            return header_lines_only

        updated = []
        replaced = False
        target_name = header_name.lower()

        for line in header_lines_only:
            if ':' in line:
                current_name = line.split(':', 1)[0].strip().lower()
                if current_name == target_name:
                    if not replaced:
                        updated.append("{}: {}".format(header_name, header_value))
                        replaced = True
                    continue
            updated.append(line)

        if not replaced:
            updated.append("{}: {}".format(header_name, header_value))

        return updated

    user_header_pairs = parse_header_lines(user_headers_text)
    queryFlag = self.replaceQueryParam.isSelected()

    if apply_user_header_text and user_header_pairs:
        for name, value in user_header_pairs:
            headers = [headers[0]] + upsert_header(headers[1:], name, value)

    if apply_user_header_text and queryFlag:
        if user_headers_text:
            param = user_headers_text.split("=")
            if len(param) >= 2:
                paramKey = param[0]
                paramValue = "=".join(param[1:])
                headers[0] = _set_query_param_in_request_line(headers[0], paramKey, paramValue)

    for i in range(mr_model.getSize() if mr_model else 0):
        rule_key = mr_model.getElementAt(i)
        rule_data = _get_rule_data(mr_instance, rule_key)

        if rule_data:
            rule_type = rule_data['type']
            match_pattern = rule_data['match']
            replace_pattern = rule_data['replace']
            regex_match = rule_data.get('regexMatch')

            if rule_type == "Headers (simple string):":
                if match_pattern:
                    modifiedHeaders = [h.replace(match_pattern, replace_pattern) for h in headers[1:]]
                    headers = [headers[0]] + modifiedHeaders
            elif rule_type == "Headers (regex):":
                if regex_match and match_pattern:
                    modifiedHeaders = [regex_match.sub(replace_pattern, h) for h in headers[1:]]
                    headers = [headers[0]] + modifiedHeaders
            elif rule_type == "Header Add/Set:":
                header_name = match_pattern.strip()
                if header_name:
                    headers = [headers[0]] + upsert_header(
                        headers[1:], header_name, replace_pattern.strip()
                    )
            elif rule_type == "Query Add/Set:":
                query_name = match_pattern.strip()
                if query_name:
                    headers[0] = _set_query_param_in_request_line(
                        headers[0], query_name, replace_pattern
                    )

    if body_text is None:
        body_text = ""

    for i in range(mr_model.getSize() if mr_model else 0):
        rule_key = mr_model.getElementAt(i)
        rule_data = _get_rule_data(mr_instance, rule_key)

        if rule_data:
            rule_type = rule_data['type']
            match_pattern = rule_data['match']
            replace_pattern = rule_data['replace']
            regex_match = rule_data.get('regexMatch')

            if rule_type == "Path (simple string):":
                uriPath = headers[0].split(" ")[1]
                if match_pattern and match_pattern in uriPath:
                    headers[0] = headers[0].replace(match_pattern, replace_pattern)
            elif rule_type == "Path (regex):":
                if regex_match and match_pattern:
                    uriPath = headers[0].split(" ")[1]
                    if regex_match.search(uriPath):
                        headers[0] = regex_match.sub(replace_pattern, headers[0])

            elif rule_type == "Body (simple string):":
                if match_pattern:
                    body_text = body_text.replace(match_pattern, replace_pattern)
            elif rule_type == "Body (regex):":
                if regex_match and match_pattern:
                    body_text = regex_match.sub(replace_pattern, body_text)

    return headers[0], headers[1:], body_text

def makeUserMessage(self, messageInfo, removeOrNot, authorizeOrNot, mr_instance, user_headers_text=""):
    requestInfo = self._helpers.analyzeRequest(messageInfo)
    headers = list(requestInfo.getHeaders())
    body_bytes = messageInfo.getRequest()[requestInfo.getBodyOffset():]
    body_text = self._helpers.bytesToString(body_bytes) if body_bytes is not None else ""

    request_line, header_lines, body_text = apply_user_rules_to_request_components(
        self,
        headers[0],
        headers[1:],
        body_text,
        mr_instance,
        user_headers_text,
        removeOrNot and authorizeOrNot,
    )

    msgBody = self._helpers.stringToBytes(body_text)
    return self._helpers.buildHttpMessage([request_line] + header_lines, msgBody)

def send_request_to_autorize(self, messageInfo):
    if messageInfo.getResponse() is None:
        message = makeMessage(self, messageInfo,False,False)
        requestResponse = makeRequest(self, messageInfo, message)
        # checkAuthorization(self, requestResponse,self._helpers.analyzeResponse(requestResponse.getResponse()).getHeaders(),self.doUnauthorizedRequest.isSelected())
        checkAuthorizationAllUsers(self, requestResponse, self.doUnauthorizedRequest.isSelected())
    else:
        request = messageInfo.getRequest()
        response = messageInfo.getResponse()
        httpService = messageInfo.getHttpService()
        newHttpRequestResponse = IHttpRequestResponseImplementation(httpService,request,response)
        newHttpRequestResponsePersisted = self._callbacks.saveBuffersToTempFiles(newHttpRequestResponse)
        
        checkAuthorizationAllUsers(self, newHttpRequestResponsePersisted, self.doUnauthorizedRequest.isSelected())

def auth_enforced_via_enforcement_detectors(self, filters, requestResponse, andOrEnforcement):
    response = requestResponse.getResponse()
    analyzedResponse = self._helpers.analyzeResponse(response)
    auth_enforced = False
    if andOrEnforcement == "And":
        andEnforcementCheck = True
        auth_enforced = True
    else:
        andEnforcementCheck = False
        auth_enforced = False

    for filter in filters:
        filter = self._helpers.bytesToString(bytes(filter))
        inverse = "NOT" in filter
        filter = filter.replace(" NOT", "")
        filter_name, filter_content = filter.split(':', 1)
        filter_content = filter_content[1:]  # remove the ' '
        
        if filter_name == "Status code equals":
            statusCode = filter_content
            filterMatched = inverse ^ isStatusCodesReturned(self, requestResponse, statusCode)

        elif filter_name == "Headers (simple string)":
            filterMatched = inverse ^ (filter_content in self._helpers.bytesToString(requestResponse.getResponse()[0:analyzedResponse.getBodyOffset()]))

        elif filter_name == "Headers (regex)":
            regex_string = filter_content
            p = re.compile(regex_string, re.IGNORECASE)
            filterMatched = inverse ^ bool(p.search(self._helpers.bytesToString(requestResponse.getResponse()[0:analyzedResponse.getBodyOffset()])))

        elif filter_name == "Body (simple string)":
            filterMatched = inverse ^ (filter_content in self._helpers.bytesToString(requestResponse.getResponse()[analyzedResponse.getBodyOffset():]))

        elif filter_name == "Body (regex)":
            regex_string = filter_content
            p = re.compile(regex_string, re.IGNORECASE)
            filterMatched = inverse ^ bool(p.search(self._helpers.bytesToString(requestResponse.getResponse()[analyzedResponse.getBodyOffset():])))

        elif filter_name == "Full response (simple string)":
            filterMatched = inverse ^ (filter_content in self._helpers.bytesToString(requestResponse.getResponse()))

        elif filter_name == "Full response (regex)":
            regex_string = filter_content
            p = re.compile(regex_string, re.IGNORECASE)
            filterMatched = inverse ^ bool(p.search(self._helpers.bytesToString(requestResponse.getResponse())))

        elif filter_name == "Full response length":
            filterMatched = inverse ^ (str(len(response)) == filter_content.strip())

        if andEnforcementCheck:
            if auth_enforced and not filterMatched:
                auth_enforced = False
        else:
            if not auth_enforced and filterMatched:
                auth_enforced = True

    return auth_enforced

def checkBypass(self, oldStatusCode, newStatusCode, oldContent,
                 newContent, filters, requestResponse, andOrEnforcement):
    if oldStatusCode == newStatusCode:
        auth_enforced = 0
        if len(filters) > 0:
            auth_enforced = auth_enforced_via_enforcement_detectors(self, filters, requestResponse, andOrEnforcement)
        if auth_enforced:
            return self.ENFORCED_STR
        elif oldContent == newContent:
            return self.BYPASSSED_STR
        else:
            result = self.IS_ENFORCED_STR
            return result
    else:
        result = self.ENFORCED_STR
        return result

def checkAuthorization(self, messageInfo, originalHeaders, checkUnauthorized):
    # Check unauthorized request
    if checkUnauthorized:
        messageUnauthorized = makeMessage(self, messageInfo, True, False)
        requestResponseUnauthorized = makeRequest(self, messageInfo, messageUnauthorized)
        unauthorizedResponse = requestResponseUnauthorized.getResponse()
        try:
            if unauthorizedResponse and len(unauthorizedResponse) > 0:
                analyzedResponseUnauthorized = self._helpers.analyzeResponse(unauthorizedResponse)
                h = analyzedResponseUnauthorized.getHeaders()
                if h:
                    statusCodeUnauthorized = h[0]
                    contentUnauthorized = getResponseBody(self, requestResponseUnauthorized)
                else:
                    checkUnauthorized = False
            else:
                checkUnauthorized = False
        except (IndexError, Exception):
            checkUnauthorized = False

    message = makeMessage(self, messageInfo, True, True)
    requestResponse = makeRequest(self, messageInfo, message)
    newResponse = requestResponse.getResponse()
    try:
        if not newResponse or len(newResponse) == 0:
            raise ValueError("empty response")
        analyzedResponse = self._helpers.analyzeResponse(newResponse)
        newHeaders = analyzedResponse.getHeaders()
        if not newHeaders:
            raise IndexError("no response headers")
        newStatusCode = newHeaders[0]
    except (IndexError, ValueError, Exception) as e:
        return

    oldStatusCode = originalHeaders[0]
    oldContent = getResponseBody(self, messageInfo)
    newContent = getResponseBody(self, requestResponse)

    EDFilters = self.EDModel.toArray()

    impression = checkBypass(self, oldStatusCode, newStatusCode, oldContent, newContent, EDFilters, requestResponse, self.AndOrType.getSelectedItem())

    if checkUnauthorized:
        EDFiltersUnauth = self.EDModelUnauth.toArray()
        impressionUnauthorized = checkBypass(self, oldStatusCode, statusCodeUnauthorized, oldContent, contentUnauthorized, EDFiltersUnauth, requestResponseUnauthorized, self.AndOrTypeUnauth.getSelectedItem())

    # Hold lock only for _log update so Clear table and other threads are not blocked.
    self._lock.acquire()
    try:
        row = self._log.size()
        method = self._helpers.analyzeRequest(messageInfo.getRequest()).getMethod()

        if checkUnauthorized:
            self._log.add(LogEntry(self.currentRequestNumber,self._callbacks.saveBuffersToTempFiles(requestResponse), method, self._helpers.analyzeRequest(requestResponse).getUrl(),messageInfo,impression,self._callbacks.saveBuffersToTempFiles(requestResponseUnauthorized),impressionUnauthorized)) # same requests not include again.
        else:
            self._log.add(LogEntry(self.currentRequestNumber,self._callbacks.saveBuffersToTempFiles(requestResponse), method, self._helpers.analyzeRequest(requestResponse).getUrl(),messageInfo,impression,None,"Disabled")) # same requests not include again.

        SwingUtilities.invokeLater(UpdateTableEDT(self,"insert",row,row))
        self.currentRequestNumber += 1
    except Exception as e:
        raise
    finally:
        self._lock.release()

def checkAuthorizationV2(self, messageInfo):
    checkAuthorization(self, messageInfo, self._extender._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders(), self._extender.doUnauthorizedRequest.isSelected())

def retestAllRequests(self):
    self.logTable.setAutoCreateRowSorter(True)
    for i in range(self.tableModel.getRowCount()):
        logEntry = self._log.get(self.logTable.convertRowIndexToModel(i))
        self.executor.submit(HandleMessageRunnable(self, "AUTORIZE", False, logEntry._originalrequestResponse))
