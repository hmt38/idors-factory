#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import re
import urllib2
import traceback

try:
    basestring
except NameError:
    basestring = str

class LLMHelper:
    _trust_all_ssl_installed = False
    _ssl_warning_logged = False
    _default_ssl_socket_factory = None
    _default_hostname_verifier = None

    def __init__(self, base_url, api_key, model, verify_ssl=True):
        self.base_url = base_url.rstrip('/') if base_url else base_url
        self.api_key = api_key
        self.model = model
        self.verify_ssl = verify_ssl

    def extract_params(self, request_data):
        """
        Analyze request to find potential IDOR parameters using LLM.
        """
        if not self.api_key or not self.base_url:
            print("[LLM] Skipping extract_params: API Key/URL not configured")
            return []

        prompt = """Analyze the following HTTP request and identify dynamic parameters that could be vulnerable to IDOR.
Ignore standard headers.

Request:
{}

Return ONLY a JSON list of objects.
IMPORTANT: Return an empty list [] if no suitable parameters are found.
Each object must have:
- "name": Parameter name
- "value": Current value
- "type": "path", "query", "body", or "header"

Example:
[
  {{"name": "user_id", "value": "123", "type": "path"}}
]
""".format(self._truncate(json.dumps(request_data) if isinstance(request_data, dict) else str(request_data)))
        
        try:
            print("[LLM Debug] Extract Params Prompt: " + prompt[:200] + "...")
            response = self._call_llm(prompt)
            print("[LLM Debug] Extract Params Response: " + str(response))
            
            content = self._extract_content(response)
            
            # Fix common issue: LLM returns string "[]" or just names
            try:
                params = json.loads(content)
            except:
                # Try to clean up json
                import re
                # Sometimes it returns "Parameters: [...]"
                match = re.search(r'\[.*\]', content, re.DOTALL)
                if match:
                    params = json.loads(match.group(0))
                else:
                    raise Exception("Could not find JSON list in response: " + content[:100])
            
            # Validate format
            valid_params = []
            if isinstance(params, list):
                for p in params:
                    if isinstance(p, dict) and 'name' in p and 'value' in p:
                        p['type'] = 'llm' # Mark source as LLM
                        valid_params.append(p)
                    elif isinstance(p, basestring):
                         # LLM returned list of strings?
                         pass
            
            print("[LLM] Extracted {} params".format(len(valid_params)))
            return valid_params
        except Exception as e:
            print("[LLM] Error extracting params: " + str(e))
            # traceback.print_exc()
            return []

    def generate_values(self, request_data, existing_params):
        """
        Generate test values for parameters using LLM.
        """
        if not self.api_key or not self.base_url:
            return []

        prompt = """Analyze the following HTTP request and the list of identified parameters.
Your task is to generate 2 alternative test values for each sensitive parameter to test for IDOR.
For example, if 'user_id' is 100, suggest 101 (sequential) and a random large number.
If it's a UUID, suggest a different valid UUID.

Request:
{}

Identified Params:
{}

Return ONLY a JSON list of objects.
IMPORTANT: Return an empty list [] if no suitable parameters are found.
Each object must have:
- "name": Parameter name
- "value": Suggested test value

Example:
[
  {{"name": "user_id", "value": "101"}}
]
""".format(
            self._truncate(str(request_data)),
            json.dumps(existing_params)
        )

        try:
            print("[LLM Debug] Generate Values Prompt: " + prompt[:200] + "...")
            response = self._call_llm(prompt)
            print("[LLM Debug] Generate Values Response: " + str(response))
            
            content = self._extract_content(response)
            
            # Fix common issue: LLM returns string "[]" or just names
            try:
                values = json.loads(content)
            except:
                import re
                match = re.search(r'\[.*\]', content, re.DOTALL)
                if match:
                    values = json.loads(match.group(0))
                else:
                    raise Exception("Could not find JSON list in response: " + content[:100])
            
            valid_values = []
            if isinstance(values, list):
                for v in values:
                    if isinstance(v, dict) and 'name' in v and 'value' in v:
                        valid_values.append(v)
            
            print("[LLM] Generated {} values".format(len(valid_values)))
            return valid_values
        except Exception as e:
            print("[LLM] Error generating values: " + str(e))
            return []

    def identify_sensitive_api(self, request_data):
        """
        Identify if the API is high-risk (sensitive).
        Returns dict: {'is_sensitive': bool, 'reason': str}
        """
        if not self.api_key or not self.base_url:
            return {'is_sensitive': False, 'reason': 'LLM not configured'}

        prompt = """Analyze the following HTTP request.
Determine if this API endpoint is considered "High Risk" or "Sensitive" from a security perspective.
High Risk includes:
- Administrative actions (granting roles, deleting users)
- Financial transactions (payment, transfer)
- PII access (viewing profiles, downloading data)
- State-changing operations (POST/PUT/DELETE) on critical resources

Request:
{}

Return ONLY a JSON object:
- "is_sensitive": boolean (true/false)
- "reason": Short explanation

Example Output:
{{"is_sensitive": true, "reason": "Deletes user account"}}
""".format(self._truncate(str(request_data)))

        try:
            print("[LLM Debug] Identify Risk Prompt: " + prompt[:200] + "...")
            response = self._call_llm(prompt)
            print("[LLM Debug] Identify Risk Response: " + str(response))
            
            content = self._extract_content(response)
            result = json.loads(content)
            
            return {
                'is_sensitive': result.get('is_sensitive', False),
                'reason': result.get('reason', 'No reason provided')
            }
        except Exception as e:
            print("[LLM] Error identifying risk: " + str(e))
            return {'is_sensitive': False, 'reason': 'Error: ' + str(e)}

    def _truncate(self, s, limit=2000):
        if s and len(s) > limit:
            return s[:limit] + "...(truncated)"
        return s

    def _extract_content(self, response_json):
        if 'choices' not in response_json or not response_json['choices']:
            # Check for error in response
            if 'error' in response_json:
                raise Exception("LLM API Error: " + str(response_json['error']))
            raise Exception("Invalid LLM response format: choices missing")
            
        content = response_json['choices'][0]['message']['content']
        content = content.strip()
        
        # Try to extract JSON from markdown code blocks
        if "```" in content:
            parts = content.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("json"):
                    content = part[4:].strip()
                    break
                elif part.startswith("[") or part.startswith("{"):
                    content = part
                    break
        
        # Fallback: find first [ or {
        if not (content.startswith("[") or content.startswith("{")):
            start_idx = content.find("[")
            if start_idx == -1:
                start_idx = content.find("{")
            
            if start_idx != -1:
                content = content[start_idx:]
                # Try to find matching closing brace? No, let json.loads handle it or fail
                # But we might have trailing text.
                # Heuristic: find last ] or }
                end_idx = content.rfind("]")
                if end_idx == -1:
                    end_idx = content.rfind("}")
                
                if end_idx != -1:
                    content = content[:end_idx+1]

        return content

    def analyze_idor_vulnerability(self, original_req, original_res, attack_req, attack_res):
        """
        Analyze if the attack was successful using LLM.
        Returns a dict with 'result' (VULNERABLE, SAFE, UNCERTAIN), 'reason', and 'confidence'.
        """
        if not self.api_key or not self.base_url:
            return {"result": "UNCERTAIN", "reason": "LLM not configured", "confidence": 0.2}

        heuristic_result = self._analyze_idor_with_heuristics(original_res, attack_res)
        if heuristic_result:
            return heuristic_result

        try:
            prompt = self._construct_prompt(original_req, original_res, attack_req, attack_res)
            response = self._call_llm(prompt)
            return self._parse_response(response)
        except Exception as e:
            print("[LLM] Error analyzing vulnerability: " + str(e))
            traceback.print_exc()
            return {"result": "UNCERTAIN", "reason": "LLM call failed: " + str(e), "confidence": 0.2}

    def _analyze_idor_with_heuristics(self, original_res, attack_res):
        attack_status = self._extract_http_status_code(attack_res)
        attack_body = self._extract_response_body(attack_res)
        attack_body_lower = attack_body.lower()

        if attack_status in [401, 403]:
            return {
                "result": "SAFE",
                "reason": "Attack response returned HTTP {} authorization error.".format(
                    attack_status
                ),
                "confidence": 0.99,
            }

        auth_markers = [
            "unauthorized",
            "forbidden",
            "access denied",
            "permission denied",
            "not authorized",
            "no permission",
            "insufficient permission",
            "do not have authority",
            "no authority",
            "auth failed",
            "authentication failed",
            "login required",
            "please login",
        ]
        for marker in auth_markers:
            if marker in attack_body_lower:
                return {
                    "result": "SAFE",
                    "reason": "Attack response body indicates authorization failure: '{}'".format(
                        marker
                    ),
                    "confidence": 0.97,
                }

        parsed_body = self._try_parse_json(attack_body)
        if isinstance(parsed_body, dict):
            app_code = str(parsed_body.get("code", "") or "").upper()
            app_sc = str(parsed_body.get("sc", "") or "")
            app_message = str(parsed_body.get("message", "") or "").lower()
            if app_code in ["UNAUTHORIZED", "FORBIDDEN", "ACCESS_DENIED", "PERMISSION_DENIED"]:
                return {
                    "result": "SAFE",
                    "reason": "Attack response JSON code indicates authorization failure: {}".format(
                        app_code
                    ),
                    "confidence": 0.99,
                }
            if app_sc in ["401", "403"]:
                return {
                    "result": "SAFE",
                    "reason": "Attack response JSON sc indicates authorization failure: {}".format(
                        app_sc
                    ),
                    "confidence": 0.99,
                }
            if any(marker in app_message for marker in auth_markers):
                return {
                    "result": "SAFE",
                    "reason": "Attack response JSON message indicates authorization failure.",
                    "confidence": 0.96,
                }

        original_body = self._extract_response_body(original_res)
        if attack_status == 200 and self._responses_look_like_success_data(original_body, attack_body):
            return {
                "result": "VULNERABLE",
                "reason": "Attack response appears to return valid business data rather than an authorization failure.",
                "confidence": 0.9,
            }

        if attack_status in [404, 500]:
            return {
                "result": "SAFE",
                "reason": "Attack response returned HTTP {}, which does not indicate successful unauthorized data access.".format(
                    attack_status
                ),
                "confidence": 0.9,
            }

        return None

    def _construct_prompt(self, original_req, original_res, attack_req, attack_res):
        original_req_prepared = self._prepare_http_message_for_prompt(original_req, 2500)
        original_res_prepared = self._prepare_http_message_for_prompt(original_res, 5000)
        attack_req_prepared = self._prepare_http_message_for_prompt(attack_req, 2500)
        attack_res_prepared = self._prepare_http_message_for_prompt(attack_res, 5000)

        prompt = """You are a Web Security Expert specializing in IDOR (Insecure Direct Object Reference) detection.
Your task is to determine whether the ATTACK REQUEST successfully accessed another user's data.

SCENARIO:
- ORIGINAL REQUEST/RESPONSE: baseline request where the user accesses their own resource.
- ATTACK REQUEST/RESPONSE: modified request attempting to access another user's resource.

DECISION RULES:
1. Return SAFE if the attack response is an authorization failure, permission denial, forbidden response, login redirect, not-logged-in response, or any application-level denial even when HTTP status is 200.
2. Treat common denial indicators such as code/message values like UNAUTHORIZED, FORBIDDEN, ACCESS_DENIED, PERMISSION_DENIED, "current user do not have authority", "access denied", "no permission", or JSON fields like sc=401/sc=403 as SAFE.
3. Return VULNERABLE only when the attack response appears to return real business data, resource details, object content, list items, profile information, order data, tokens, or other useful protected information rather than an error/denial message.
4. If the attack response contains structured data that looks like a real object/list/result payload and does not contain denial indicators, prefer VULNERABLE over UNCERTAIN.
5. Use UNCERTAIN only when the evidence is genuinely insufficient, contradictory, heavily truncated, unreadable, or impossible to classify confidently.
6. Large bodies may be truncated or summarized. Focus on the most security-relevant evidence: status line, denial/error markers, and whether the body contains real business data.

OUTPUT FORMAT:
Return ONLY a JSON object:
{{
  "result": "VULNERABLE" | "SAFE" | "UNCERTAIN",
  "confidence": number between 0 and 1,
  "reason": "short explanation"
}}

ORIGINAL REQUEST:
{}

ORIGINAL RESPONSE:
{}

ATTACK REQUEST:
{}

ATTACK RESPONSE:
{}
""".format(
            original_req_prepared,
            original_res_prepared,
            attack_req_prepared,
            attack_res_prepared,
        )
        return prompt

    def _extract_http_status_code(self, response_text):
        if not response_text:
            return None
        first_line = response_text.splitlines()[0] if response_text.splitlines() else ""
        match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", first_line)
        if match:
            try:
                return int(match.group(1))
            except Exception:
                return None
        return None

    def _extract_response_body(self, response_text):
        if not response_text:
            return ""
        if "\r\n\r\n" in response_text:
            return response_text.split("\r\n\r\n", 1)[1]
        if "\n\n" in response_text:
            return response_text.split("\n\n", 1)[1]
        return response_text

    def _try_parse_json(self, text):
        if not text:
            return None
        text = text.strip()
        if not text or not (text.startswith("{") or text.startswith("[")):
            return None
        try:
            return json.loads(text)
        except Exception:
            return None

    def _looks_like_business_data(self, parsed_json):
        if isinstance(parsed_json, list):
            return len(parsed_json) > 0
        if not isinstance(parsed_json, dict):
            return False

        denial_markers = [
            "unauthorized",
            "forbidden",
            "access denied",
            "permission denied",
            "not authorized",
            "no permission",
            "do not have authority",
            "no authority",
            "login required",
        ]

        denial_keys = {
            "error",
            "errors",
            "message",
            "msg",
            "code",
            "status",
            "sc",
            "exception",
        }
        value_keys = [
            "data",
            "result",
            "results",
            "items",
            "list",
            "rows",
            "records",
            "user",
            "users",
            "profile",
            "order",
            "orders",
            "content",
            "detail",
            "details",
        ]

        for key in value_keys:
            if key in parsed_json:
                value = parsed_json.get(key)
                if isinstance(value, dict) and value:
                    message_value = str(parsed_json.get("message", "") or "").lower()
                    code_value = str(parsed_json.get("code", "") or "").lower()
                    if any(marker in message_value for marker in denial_markers):
                        continue
                    if any(marker in code_value for marker in denial_markers):
                        continue
                    return True
                if isinstance(value, list) and value:
                    return True
                if isinstance(value, basestring) and value.strip():
                    return True
                if isinstance(value, (int, float)):
                    return True

        non_denial_keys = [k for k in parsed_json.keys() if str(k).lower() not in denial_keys]
        message_value = str(parsed_json.get("message", "") or "").lower()
        code_value = str(parsed_json.get("code", "") or "").lower()
        if any(marker in message_value for marker in denial_markers):
            return False
        if any(marker in code_value for marker in denial_markers):
            return False
        if len(non_denial_keys) >= 2:
            return True
        return False

    def _responses_look_like_success_data(self, original_body, attack_body):
        parsed_attack = self._try_parse_json(attack_body)
        if self._looks_like_business_data(parsed_attack):
            return True

        parsed_original = self._try_parse_json(original_body)
        if self._looks_like_business_data(parsed_original) and attack_body:
            attack_trimmed = attack_body.strip()
            if len(attack_trimmed) > 20 and not any(
                marker in attack_trimmed.lower()
                for marker in ["unauthorized", "forbidden", "denied", "no authority"]
            ):
                return True
        return False

    def _summarize_large_text(self, text, total_limit=5000, head=1500, tail=2500):
        if not text:
            return ""
        if len(text) <= total_limit:
            return text
        omitted = len(text) - head - tail
        if omitted < 0:
            omitted = 0
        return (
            text[:head]
            + "\n\n...[truncated {} chars]...\n\n".format(omitted)
            + text[-tail:]
        )

    def _prepare_http_message_for_prompt(self, message_text, total_limit):
        if not message_text:
            return ""

        header_part = message_text
        body_part = ""
        if "\r\n\r\n" in message_text:
            header_part, body_part = message_text.split("\r\n\r\n", 1)
            separator = "\r\n\r\n"
        elif "\n\n" in message_text:
            header_part, body_part = message_text.split("\n\n", 1)
            separator = "\n\n"
        else:
            separator = "\n\n"

        header_part = self._truncate(header_part, 1200)
        parsed_json = self._try_parse_json(body_part)
        if isinstance(parsed_json, (dict, list)):
            try:
                body_part = json.dumps(parsed_json, ensure_ascii=False, indent=2)
            except Exception:
                try:
                    body_part = json.dumps(parsed_json, indent=2)
                except Exception:
                    body_part = str(parsed_json)

        body_part = self._summarize_large_text(body_part, max(1000, total_limit - len(header_part)))
        combined = header_part + separator + body_part
        return self._truncate(combined, total_limit)

    def _call_llm(self, prompt):
        # Allow passing custom system prompt or just a string
        url = self.base_url + "/chat/completions"
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": "Bearer " + self.api_key
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a helpful security assistant."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.0
        }
        
        # Jython/urllib2 may fail with "cannot make memory view" when a unicode
        # request body is passed. Always send UTF-8 bytes explicitly.
        body = json.dumps(payload).encode("utf-8")
        if not self.verify_ssl:
            self._install_trust_all_ssl_context()
        else:
            self._restore_default_ssl_context()
        req = urllib2.Request(url, body, headers)
        response = urllib2.urlopen(req, timeout=30) # 30s timeout
        response_data = response.read()
        return json.loads(response_data)

    def _install_trust_all_ssl_context(self):
        if not LLMHelper._ssl_warning_logged:
            print("[LLM] WARNING: SSL certificate verification is disabled for LLM requests.")
            LLMHelper._ssl_warning_logged = True
        if LLMHelper._trust_all_ssl_installed:
            return
        try:
            from javax.net.ssl import SSLContext, HttpsURLConnection, X509TrustManager, HostnameVerifier
            from java.security import SecureRandom

            class TrustAllManager(X509TrustManager):
                def checkClientTrusted(self, chain, authType):
                    pass

                def checkServerTrusted(self, chain, authType):
                    pass

                def getAcceptedIssuers(self):
                    return None

            class TrustAllHostnameVerifier(HostnameVerifier):
                def verify(self, hostname, session):
                    return True

            ssl_context = SSLContext.getInstance("TLS")
            ssl_context.init(None, [TrustAllManager()], SecureRandom())
            if LLMHelper._default_ssl_socket_factory is None:
                LLMHelper._default_ssl_socket_factory = HttpsURLConnection.getDefaultSSLSocketFactory()
            if LLMHelper._default_hostname_verifier is None:
                LLMHelper._default_hostname_verifier = HttpsURLConnection.getDefaultHostnameVerifier()
            HttpsURLConnection.setDefaultSSLSocketFactory(ssl_context.getSocketFactory())
            HttpsURLConnection.setDefaultHostnameVerifier(TrustAllHostnameVerifier())
            LLMHelper._trust_all_ssl_installed = True
        except Exception as e:
            print("[LLM] Failed to disable SSL verification: " + str(e))

    def _restore_default_ssl_context(self):
        if not LLMHelper._trust_all_ssl_installed:
            return
        try:
            from javax.net.ssl import HttpsURLConnection

            if LLMHelper._default_ssl_socket_factory is not None:
                HttpsURLConnection.setDefaultSSLSocketFactory(
                    LLMHelper._default_ssl_socket_factory
                )
            if LLMHelper._default_hostname_verifier is not None:
                HttpsURLConnection.setDefaultHostnameVerifier(
                    LLMHelper._default_hostname_verifier
                )
            LLMHelper._trust_all_ssl_installed = False
        except Exception as e:
            print("[LLM] Failed to restore SSL verification defaults: " + str(e))

    def _normalize_confidence(self, confidence, result_label):
        try:
            confidence = float(confidence)
            if confidence < 0:
                confidence = 0.0
            if confidence > 1:
                confidence = 1.0
            return confidence
        except Exception:
            if result_label == "UNCERTAIN":
                return 0.3
            return 0.7

    def _parse_response(self, response_json):
        try:
            content = self._extract_content(response_json)
            result_obj = json.loads(content)
            
            # Normalize result
            res = result_obj.get("result", "UNCERTAIN").upper()
            if res not in ["VULNERABLE", "SAFE", "UNCERTAIN"]:
                res = "UNCERTAIN"
                
            return {
                "result": res,
                "confidence": self._normalize_confidence(result_obj.get("confidence", None), res),
                "reason": result_obj.get("reason", "No reason provided")
            }
        except Exception as e:
            print("[LLM] Failed to parse LLM response: " + str(e))
            return {"result": "UNCERTAIN", "reason": "Failed to parse LLM output", "confidence": 0.2}

    # ------------------------------------------------------------------
    # Feature 1: AI 剪枝 - 对攻击队列中的 POC 进行价值评分
    # ------------------------------------------------------------------
    def score_attack_potential(self, payload_description, request_data_str, target_user):
        """
        对一个 POC 进行价值评分, 用于剪枝决策.
        Returns: {"score": 0-100, "reason": "...", "should_prune": bool}
        """
        if not self.api_key or not self.base_url:
            return {"score": 50, "reason": "LLM not configured", "should_prune": False}

        prompt = (
            "You are a Web Security Expert. Score the IDOR attack POC value.\n"
            "Higher score means more likely to find a vulnerability.\n\n"
            "POC Description: {}\n"
            "Target User: {}\n"
            "Request Data: {}\n\n"
            "Scoring criteria:\n"
            "- 90-100: Swapping a real user identifier parameter across users (high IDOR potential)\n"
            "- 60-89:  Swapping numeric IDs that likely map to user-specific resources\n"
            "- 30-59:  Swapping generic params (pagination, filters) unlikely to reveal IDOR\n"
            "- 0-29:   Duplicate or nonsensical attacks (e.g., swapping to same value, non-existent resource)\n\n"
            "Return ONLY a JSON object:\n"
            '{{"score": <0-100>, "reason": "<short explanation>", "should_prune": <true if score<30>}}'
        ).format(
            self._truncate(payload_description or "N/A", 500),
            str(target_user or "N/A"),
            self._truncate(request_data_str or "N/A", 1000),
        )

        try:
            response = self._call_llm(prompt)
            content = self._extract_content(response)
            result_obj = json.loads(content)
            score = int(result_obj.get("score", 50))
            score = max(0, min(100, score))
            return {
                "score": score,
                "reason": result_obj.get("reason", "No reason"),
                "should_prune": result_obj.get("should_prune", score < 30),
            }
        except Exception as e:
            print("[LLM] Error scoring attack potential: " + str(e))
            return {"score": 50, "reason": "Scoring failed: " + str(e), "should_prune": False}

    # ------------------------------------------------------------------
    # Feature 2: AI 越权验证 - 带完整上下文的深度验证
    # ------------------------------------------------------------------
    def verify_with_full_context(self, original_req, original_res, attack_req, attack_res, extra_context):
        """
        带完整上下文的深度 IDOR 验证. 越权 AI agent 可提供额外上下文.
        Returns: {"result": "VULNERABLE|SAFE|UNCERTAIN", "reason": "...", "confidence": 0-1, "verified": bool}
        """
        if not self.api_key or not self.base_url:
            return {"result": "UNCERTAIN", "reason": "LLM not configured", "confidence": 0.2, "verified": False}

        # 先走启发式
        heuristic_result = self._analyze_idor_with_heuristics(original_res, attack_res)
        if heuristic_result:
            heuristic_result["verified"] = True
            heuristic_result["source"] = "heuristic"
            return heuristic_result

        original_req_prepared = self._prepare_http_message_for_prompt(original_req, 2500)
        original_res_prepared = self._prepare_http_message_for_prompt(original_res, 5000)
        attack_req_prepared = self._prepare_http_message_for_prompt(attack_req, 2500)
        attack_res_prepared = self._prepare_http_message_for_prompt(attack_res, 5000)
        context_str = self._truncate(str(extra_context or ""), 2000)

        prompt = (
            "You are an expert IDOR Verification Agent with full security context.\n"
            "Analyze whether the ATTACK REQUEST successfully accessed another user's data.\n\n"
            "EXTRA CONTEXT FROM SECURITY AGENT:\n{}\n\n"
            "ORIGINAL REQUEST:\n{}\n\n"
            "ORIGINAL RESPONSE:\n{}\n\n"
            "ATTACK REQUEST:\n{}\n\n"
            "ATTACK RESPONSE:\n{}\n\n"
            "DECISION RULES:\n"
            "1. VULNERABLE: Attack response returns real business data belonging to another user.\n"
            "2. SAFE: Attack response shows authorization failure, denial, or non-existent resource.\n"
            "3. UNCERTAIN: Evidence is insufficient or contradictory.\n\n"
            "Return ONLY a JSON object:\n"
            '{{"result": "VULNERABLE|SAFE|UNCERTAIN", "confidence": <0-1>, "reason": "<explanation>"}}'
        ).format(context_str, original_req_prepared, original_res_prepared,
                 attack_req_prepared, attack_res_prepared)

        try:
            response = self._call_llm(prompt)
            result = self._parse_response(response)
            result["verified"] = True
            result["source"] = "ai_agent"
            return result
        except Exception as e:
            print("[LLM] Error in AI verify with context: " + str(e))
            return {"result": "UNCERTAIN", "reason": "AI verify failed: " + str(e),
                    "confidence": 0.2, "verified": False, "source": "ai_agent"}

    # ------------------------------------------------------------------
    # Feature 3: AI POC 生成 - 建议参数修改
    # ------------------------------------------------------------------
    def generate_poc_modifications(self, request_data_str, existing_params, target_users):
        """
        让 LLM 基于原始请求和已有参数, 建议 IDOR 测试的参数修改方案.
        Returns: list of {"param": "...", "original_value": "...", "new_value": "...",
                          "location": "QUERY|PATH|BODY|HEADER", "reason": "..."}
        """
        if not self.api_key or not self.base_url:
            return []

        prompt = (
            "You are a Web Security Expert specializing in IDOR testing.\n"
            "Given an HTTP request and known parameters, suggest parameter modifications for IDOR testing.\n\n"
            "Request Data: {}\n\n"
            "Known Parameters: {}\n\n"
            "Target Users (try to swap to these users' values): {}\n\n"
            "Rules:\n"
            "1. Focus on user-identifiable parameters (user_id, order_id, account_id, etc.)\n"
            "2. Suggest 1-3 modifications, prioritizing cross-user value swaps\n"
            "3. Include a non-existent value (e.g., 99999) as a control test\n"
            "4. Each modification should target a different parameter\n\n"
            "Return ONLY a JSON list:\n"
            '[{{"param": "<name>", "original_value": "<old>", "new_value": "<new>", '
            '"location": "QUERY|PATH|BODY|HEADER", "reason": "<why>"}}]'
        ).format(
            self._truncate(request_data_str or "N/A", 2000),
            self._truncate(json.dumps(existing_params or []), 1000),
            self._truncate(json.dumps(target_users or []), 500),
        )

        try:
            response = self._call_llm(prompt)
            content = self._extract_content(response)
            modifications = json.loads(content)
            if not isinstance(modifications, list):
                modifications = [modifications] if isinstance(modifications, dict) else []
            valid = []
            for m in modifications:
                if isinstance(m, dict) and "param" in m and "new_value" in m:
                    m.setdefault("location", "QUERY")
                    m.setdefault("original_value", "")
                    m.setdefault("reason", "")
                    valid.append(m)
            print("[LLM] Generated {} POC modifications".format(len(valid)))
            return valid
        except Exception as e:
            print("[LLM] Error generating POC modifications: " + str(e))
            return []
