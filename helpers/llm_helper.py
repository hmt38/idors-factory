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
        
        req = urllib2.Request(url, json.dumps(payload), headers)
        response = urllib2.urlopen(req)
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
