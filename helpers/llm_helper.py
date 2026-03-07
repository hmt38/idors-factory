#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import urllib2
import traceback

class LLMHelper:
    def __init__(self, base_url, api_key, model):
        self.base_url = base_url
        self.api_key = api_key
        self.model = model

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
        Returns a dict with 'result' (VULNERABLE, SAFE, UNCERTAIN) and 'reason'.
        """
        if not self.api_key or not self.base_url:
            return {"result": "UNCERTAIN", "reason": "LLM not configured"}

        prompt = self._construct_prompt(original_req, original_res, attack_req, attack_res)
        
        try:
            response = self._call_llm(prompt)
            return self._parse_response(response)
        except Exception as e:
            print("[LLM] Error analyzing vulnerability: " + str(e))
            traceback.print_exc()
            return {"result": "UNCERTAIN", "reason": "LLM call failed: " + str(e)}

    def _construct_prompt(self, original_req, original_res, attack_req, attack_res):
        # Truncate large bodies to avoid token limits
        def truncate(s, limit=2000):
            if s and len(s) > limit:
                return s[:limit] + "...(truncated)"
            return s

        prompt = """You are a Web Security Expert specializing in IDOR (Insecure Direct Object Reference) detection.
Your task is to analyze the following HTTP interaction to determine if an IDOR attack was successful.

SCENARIO:
User A (Attacker) is trying to access a resource belonging to User B (Victim) by modifying parameters (e.g., ID) in the request.

CONTEXT 1: ORIGINAL REQUEST (User A accessing their own resource)
Request:
{}
Response:
{}

CONTEXT 2: ATTACK REQUEST (User A trying to access User B's resource)
Request:
{}
Response:
{}

INSTRUCTIONS:
1. Compare the Attack Response with the Original Response.
2. If the Attack Response indicates successful access to User B's data (e.g., HTTP 200 OK with valid data, distinct from an error page), it is VULNERABLE.
3. If the Attack Response is a permission error (401, 403), a generic error (500), or 'Not Found' (404) that implies access control blocked it, it is SAFE.
4. Be careful with 'soft 200' errors (where status is 200 but body says "Access Denied").

OUTPUT FORMAT:
Return ONLY a JSON object with the following fields:
- "result": One of ["VULNERABLE", "SAFE", "UNCERTAIN"]
- "reason": A brief explanation of your decision.

JSON Response:
""".format(
            truncate(original_req), 
            truncate(original_res), 
            truncate(attack_req), 
            truncate(attack_res)
        )
        return prompt

    def _call_llm(self, prompt):
        # Allow passing custom system prompt or just a string
        url = self.base_url + "/chat/completions"
        headers = {
            "Content-Type": "application/json",
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
        
        # print("[LLM] Calling URL: " + url)
        req = urllib2.Request(url, json.dumps(payload), headers)
        response = urllib2.urlopen(req, timeout=30) # 30s timeout
        response_data = response.read()
        return json.loads(response_data)

    def _parse_response(self, response_json):
        try:
            content = response_json['choices'][0]['message']['content']
            # Try to extract JSON from content (it might be wrapped in ```json ... ```)
            if "```" in content:
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            
            content = content.strip()
            result_obj = json.loads(content)
            
            # Normalize result
            res = result_obj.get("result", "UNCERTAIN").upper()
            if res not in ["VULNERABLE", "SAFE", "UNCERTAIN"]:
                res = "UNCERTAIN"
                
            return {
                "result": res,
                "reason": result_obj.get("reason", "No reason provided")
            }
        except Exception as e:
            print("[LLM] Failed to parse LLM response: " + str(e))
            return {"result": "UNCERTAIN", "reason": "Failed to parse LLM output"}
