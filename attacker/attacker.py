#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import time

class AttackEngine:
    def __init__(self, db_manager):
        self.db_manager = db_manager

    def generate_attacks(self):
        """
        Scan for requests from User A (or any user) that haven't been attacked yet,
        find matching parameters from other users (User B), and generate attack payloads.
        """
        print("[Attacker] Starting attack generation scan...")
        
        # 0. Global Analysis: Update risk scores based on parameter exclusivity
        try:
            self._update_risk_scores_based_on_exclusivity()
        except Exception as e:
            print("[Attacker] Error in global analysis: " + str(e))
        
        # 1. Find potential target requests
        # We look for requests that are analyzed but not yet in attack_queue (as original_request_id)
        # To avoid complex joins, we can select requests and check if they have attacks.
        # Or simpler: add 'attack_generated' flag to raw_requests?
        # Let's use a simple query: select requests where user_identifier is NOT NULL
        # For MVP, let's just pick recent analyzed requests.
        # TODO: Add 'attack_generated' column to raw_requests for state tracking.
        
        # For now, let's fetch analyzed requests from the last hour?
        # Or just fetch all analyzed requests and check if they are already in attack_queue
        
        # Better approach:
        # SELECT r.id, r.method, r.host, r.url, r.path, r.headers, r.query_params, r.body, r.user_identifier 
        # FROM raw_requests r 
        # WHERE r.is_analyzed = 1 
        # AND r.id NOT IN (SELECT original_request_id FROM attack_queue)
        # LIMIT 50
        
        sql = '''
        SELECT r.id, r.method, r.host, r.url, r.path, r.headers, r.query_params, r.body, r.user_identifier 
        FROM raw_requests r 
        WHERE r.is_analyzed = 1 
        AND r.id NOT IN (SELECT original_request_id FROM attack_queue)
        LIMIT 20
        '''
        
        requests = self.db_manager.fetch_all(sql)
        
        if not requests:
            print("[Attacker] No new requests to generate attacks for.")
            return

        for req in requests:
            try:
                self._process_request(req)
            except Exception as e:
                print("[Attacker] Error processing request {}: {}".format(req[0], str(e)))

    def _update_risk_scores_based_on_exclusivity(self):
        """
        Identify parameters that are present for some users but missing for others on the same API.
        If a parameter is 'exclusive' (not present for all users), increase its risk score.
        """
        print("[Attacker] Analyzing parameter exclusivity...")
        
        # 1. Get all API signatures and their total user count
        # We assume if a user has ANY parameter for an API, they accessed it.
        # This is an approximation. Ideally we check raw_requests, but parameter_pool is faster.
        sql_api_users = '''
        SELECT api_signature, COUNT(DISTINCT user_identifier) as total_users
        FROM parameter_pool
        GROUP BY api_signature
        HAVING total_users > 1
        '''
        api_rows = self.db_manager.fetch_all(sql_api_users)
        
        for api_row in api_rows:
            api_signature, total_users = api_row
            
            # 2. For this API, check each parameter's user count
            sql_param_users = '''
            SELECT param_name, COUNT(DISTINCT user_identifier) as param_users
            FROM parameter_pool
            WHERE api_signature = ?
            GROUP BY param_name
            '''
            param_rows = self.db_manager.fetch_all(sql_param_users, (api_signature,))
            
            for param_row in param_rows:
                param_name, param_users = param_row
                
                # If parameter is NOT present for all users who accessed this API
                if param_users < total_users:
                    # Filter out common optional parameters
                    if param_name.lower() in ["page", "limit", "size", "sort", "order", "lang", "locale", "callback", "_", "t"]:
                        continue
                        
                    # This is an "Exclusive" parameter. Boost its score.
                    print("[Attacker] Found exclusive parameter: {} in {} (Users: {}/{})".format(
                        param_name, api_signature, param_users, total_users))
                    
                    # Update risk score: Add 20 points (cap at 100)
                    # We only update if it hasn't been boosted yet? 
                    # Or we just set a flag? 
                    # Let's just update risk_score directly, ensuring we don't double count excessively.
                    # Maybe check if it's already high?
                    # Simple heuristic: specific update query
                    # Use execute_query to update
                    update_sql = '''
                    UPDATE parameter_pool 
                    SET risk_score = MIN(risk_score + 20, 100)
                    WHERE api_signature = ? AND param_name = ?
                    '''
                    self.db_manager.execute_query(update_sql, (api_signature, param_name))

    def _process_request(self, req):
        req_id, method, host, url, path, headers_json, query_params_json, body, user_identifier = req
        
        print("[Attacker] Analyzing Request ID: {} ({} {}) User: {}".format(req_id, method, path, user_identifier))
        
        # 1. Identify API Signature
        api_signature = self._generate_api_signature(method, host, path)
        
        # 2. Extract parameters from current request
        current_params = self._extract_params_from_request(path, query_params_json, body)
        
        if not current_params:
            return

        # Filter parameters based on risk score threshold
        # We need to fetch risk scores for these parameters
        target_params = [] # List of dicts: {name, value, location, risk_score}
        
        for name, value, location in current_params:
            # Query risk score from pool (assuming we have it stored)
            # If not found, default to 0.
            sql = "SELECT risk_score FROM parameter_pool WHERE api_signature = ? AND param_name = ? AND user_identifier = ?"
            rows = self.db_manager.fetch_all(sql, (api_signature, name, user_identifier))
            score = 0
            if rows:
                score = rows[0][0]
            
            # Threshold Check (Default 0, but user suggested filtering low risk if needed)
            # Let's keep it 0 for now to be inclusive, or maybe 10 to skip complete junk?
            # User said "Threshold (default 0)". So we include everything > 0? Or >= 0?
            # Let's say >= 0.
            if score >= 0:
                target_params.append({
                    "name": name,
                    "value": value,
                    "location": location,
                    "risk_score": score
                })
        
        if not target_params:
            return

        # 3. Find other users who have accessed this API
        # We need to find ONE other user to impersonate (or swap params with).
        # Ideally, we find a user who has values for ALL the target_params.
        # But maybe they only have values for some.
        
        sql_users = "SELECT DISTINCT user_identifier FROM parameter_pool WHERE api_signature = ? AND user_identifier != ?"
        other_users = self.db_manager.fetch_all(sql_users, (api_signature, user_identifier))
        
        for user_row in other_users:
            other_user = user_row[0]
            print("[Attacker] Generating permutations for Target User: " + str(other_user))
            
            # Fetch all params for this other user on this API
            sql_other_params = "SELECT param_name, param_value FROM parameter_pool WHERE api_signature = ? AND user_identifier = ?"
            other_param_rows = self.db_manager.fetch_all(sql_other_params, (api_signature, other_user))
            
            # Convert to dictionary for easy lookup
            other_params_map = {row[0]: row[1] for row in other_param_rows}
            
            # Identify which parameters can be swapped
            # We only swap if the other user has a DIFFERENT value for the same parameter name.
            swappable_params = []
            for tp in target_params:
                p_name = tp["name"]
                p_val = tp["value"]
                if p_name in other_params_map:
                    other_val = other_params_map[p_name]
                    if other_val != p_val:
                        # Found a difference!
                        swappable_params.append({
                            "name": p_name,
                            "current_value": p_val,
                            "new_value": other_val,
                            "location": tp["location"],
                            "risk_score": tp["risk_score"]
                        })
            
            if not swappable_params:
                continue
                
            # 4. Generate Permutations
            # We need to generate combinations:
            # - Single parameter replacement (for each swappable param)
            # - All parameters replacement
            # - (Optional) Subsets? For now, let's do Single + All.
            # User asked for: "Generate 4 packets: Only ID, Only Account, Both ID and Account"
            # This implies All Subsets (Power Set) logic.
            
            import itertools
            
            # If we have too many swappable params, power set is 2^N.
            # Limit N? User said "prune reasonable".
            # If N > 5, maybe just do Single + All?
            # Let's try full combinations if N <= 4. If N > 4, do Single + All.
            
            combinations = []
            n_swappable = len(swappable_params)
            
            if n_swappable <= 4:
                # Generate all non-empty combinations
                for r in range(1, n_swappable + 1):
                    combinations.extend(itertools.combinations(swappable_params, r))
            else:
                # Generate Single replacements
                for p in swappable_params:
                    combinations.append([p])
                # Generate All replacements
                combinations.append(swappable_params)
            
            for combo in combinations:
                self._create_attack_entry_for_combination(req, combo, other_user)

    def _create_attack_entry_for_combination(self, req, combination, target_user):
        req_id, method, host, url, path, headers_json, query_params_json, body, user_identifier = req
        
        # combination is a tuple/list of param dicts to swap
        
        # Calculate combined risk score (max? sum? average?)
        # Let's use Max score of involved params.
        risk_score = max([p["risk_score"] for p in combination])
        
        # Description
        changes = []
        for p in combination:
            changes.append("{}={}->{}".format(p["name"], p["current_value"], p["new_value"]))
        description = "Swap params ({}): {}".format(len(combination), ", ".join(changes))
        
        # Perform replacements
        new_path = path
        
        # Handle Query Params
        new_query_str = query_params_json
        q_dict = {}
        if query_params_json:
            try: q_dict = json.loads(query_params_json)
            except: pass
            
        # Handle Body
        new_body_str = body
        b_dict = {}
        if body and body.strip().startswith("{"):
            try: b_dict = json.loads(body)
            except: pass
            
        # Apply swaps
        for p in combination:
            name = p["name"]
            val = p["new_value"]
            loc = p["location"]
            
            if loc == "PATH":
                # Path replacement
                try:
                    seg_index = int(name.split('_')[-1])
                    parts = new_path.split('/') # Use current state of new_path
                    if seg_index < len(parts):
                        parts[seg_index] = val
                        new_path = "/".join(parts)
                except: pass
                
            elif loc == "QUERY":
                q_dict[name] = val
                
            elif loc == "BODY_JSON":
                self._update_json_value(b_dict, name, val)
        
        # Serialize back
        if q_dict:
            new_query_str = json.dumps(q_dict)
        
        if b_dict:
            new_body_str = json.dumps(b_dict)
            
        # Create Request Data
        request_data = {
            "method": method,
            "host": host,
            "path": new_path,
            "headers": json.loads(headers_json),
            "query_params": json.loads(new_query_str) if new_query_str else {},
            "body": new_body_str
        }
        
        sql = '''
        INSERT INTO attack_queue 
        (original_request_id, target_user, payload_description, request_data, status, vulnerability_score)
        VALUES (?, ?, ?, ?, ?, ?)
        '''
        
        self.db_manager.execute_query(sql, (req_id, target_user, description, json.dumps(request_data), "PENDING", risk_score))
        print("[Attacker] Queued attack: " + description)


    def _update_json_value(self, json_obj, key_path, new_value):
        # key_path is like "user.profile.id" or "items.0.id"
        keys = key_path.split('.')
        current = json_obj
        for i, key in enumerate(keys[:-1]):
            if isinstance(current, list):
                try:
                    idx = int(key)
                    current = current[idx]
                except:
                    return
            else:
                current = current.get(key, {})
        
        last_key = keys[-1]
        if isinstance(current, list):
            try:
                idx = int(last_key)
                current[idx] = new_value
            except:
                pass
        elif isinstance(current, dict):
            current[last_key] = new_value

    def _extract_params_from_request(self, path, query_params_json, body):
        params = [] # (name, value, location)
        
        # Path
        parts = path.split('/')
        for i, part in enumerate(parts):
            if self._is_numeric(part) or self._is_uuid(part):
                params.append(("path_seg_" + str(i), part, "PATH"))
        
        # Query
        if query_params_json:
            try:
                q = json.loads(query_params_json)
                for k, v in q.items():
                    params.append((k, v, "QUERY"))
            except: pass
            
        # Body
        if body and body.strip().startswith("{"):
             try:
                b = json.loads(body)
                self._flatten_json(b, params)
             except: pass
             
        return params

    def _flatten_json(self, json_obj, params, prefix=""):
        if isinstance(json_obj, dict):
            for k, v in json_obj.items():
                self._flatten_json(v, params, prefix + k + ".")
        elif isinstance(json_obj, list):
            for i, item in enumerate(json_obj):
                self._flatten_json(item, params, prefix + str(i) + ".")
        else:
            params.append((prefix.rstrip("."), str(json_obj), "BODY_JSON"))

    def _generate_api_signature(self, method, host, path):
        # Same heuristic as extractor
        parts = path.split('/')
        normalized_parts = []
        for part in parts:
            if self._is_numeric(part):
                normalized_parts.append("{id}")
            elif self._is_uuid(part):
                normalized_parts.append("{uuid}")
            else:
                normalized_parts.append(part)
        return method + " " + host + "/".join(normalized_parts)

    def _is_numeric(self, s):
        return s.isdigit()

    def _is_uuid(self, s):
        import re
        uuid_regex = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
        return bool(uuid_regex.match(s))

    def reconstruct_request(self, request_data, helpers):
        from java.util import ArrayList
        
        # 1. Get Headers
        headers_list = ArrayList()
        for h in request_data['headers']:
            headers_list.add(h)
            
        # 2. Reconstruct Request Line (Method + Path + Query)
        method = request_data['method']
        path = request_data['path']
        query_params = request_data.get('query_params', {})
        
        # Build Query String
        query_string = ""
        if query_params:
            import urllib
            # Note: urllib.urlencode might reorder params, but standard servers shouldn't care.
            # However, to be cleaner, we might want to iterate if we knew the order.
            # Here we just use what we have.
            # Also need to handle list values if any.
            # JSON from DB might have values as strings or lists.
            # Check if query_params is dict
            if isinstance(query_params, dict):
                # We need to encode values.
                # Assuming simple key-value for now as per extraction logic.
                q_pairs = []
                for k, v in query_params.items():
                    if isinstance(v, list):
                        for sub_v in v:
                            q_pairs.append("{}={}".format(k, sub_v))
                    else:
                        q_pairs.append("{}={}".format(k, v))
                query_string = "&".join(q_pairs)
        
        full_path = path
        if query_string:
            full_path += "?" + query_string
            
        # Get HTTP Version from original headers[0]
        original_req_line = headers_list.get(0)
        http_version = "HTTP/1.1" # Default
        if "HTTP/" in original_req_line:
            parts = original_req_line.split(' ')
            if len(parts) >= 3:
                http_version = parts[-1]
                
        new_req_line = "{} {} {}".format(method, full_path, http_version)
        headers_list.set(0, new_req_line)
        
        # 3. Body
        body = request_data['body']
        if body is None:
            body = ""
        if isinstance(body, unicode):
            body = body.encode('utf-8')
            
        return helpers.buildHttpMessage(headers_list, body)

    def execute_attack(self, attack_id, callbacks, helpers, llm_config=None):
        from java.util import ArrayList
        from helpers.llm_helper import LLMHelper
        from java.net import URL
        
        # 1. Fetch attack data
        sql = "SELECT request_data, original_request_id FROM attack_queue WHERE id = ?"
        rows = self.db_manager.fetch_all(sql, (attack_id,))
        if not rows:
            print("[Attacker] Attack ID {} not found.".format(attack_id))
            return None
            
        request_data_json, original_req_id = rows[0]
        request_data = json.loads(request_data_json)
        
        # 2. Reconstruct Request (Correctly updating Request Line)
        new_request_bytes = self.reconstruct_request(request_data, helpers)
        
        # 3. Determine Service Details (Host, Port, Protocol)
        # We fetch original URL to determine port/protocol
        sql_url = "SELECT url FROM raw_requests WHERE id = ?"
        url_rows = self.db_manager.fetch_all(sql_url, (original_req_id,))
        
        host = request_data['host'] # Default host from saved data
        port = 80
        useHttps = False
        
        if url_rows:
            original_url_str = url_rows[0][0]
            try:
                u = URL(original_url_str)
                host = u.getHost() # Use host from URL to be safe
                port = u.getPort()
                protocol = u.getProtocol()
                useHttps = (protocol.lower() == "https")
                
                if port == -1:
                    port = 443 if useHttps else 80
            except:
                pass

        # 4. Send Request
        # Jython Burp API: byte[] makeHttpRequest(java.lang.String host, int port, boolean useHttps, byte[] request)
        response_bytes = callbacks.makeHttpRequest(host, port, useHttps, new_request_bytes)
        
        # 5. Process Response
        response_code = 0
        response_data = ""
        
        if response_bytes:
            response_info = helpers.analyzeResponse(response_bytes)
            headers = response_info.getHeaders()
            if headers:
                # First line is status line (e.g., "HTTP/1.1 200 OK")
                status_line = headers[0]
                try:
                    response_code = int(status_line.split(' ')[1])
                except: pass
            
            response_data = helpers.bytesToString(response_bytes)
        
        # 6. LLM Verification
        llm_result_str = "PENDING"
        status = "SENT"
        
        if 200 <= response_code < 300:
            # Only check if successful
            if llm_config and llm_config.get('enabled', False):
                llm = LLMHelper(llm_config['base_url'], llm_config['api_key'], llm_config['model'])
                
                # Fetch original request string
                orig_req_sql = "SELECT method, url, headers, body FROM raw_requests WHERE id = ?"
                orig_rows = self.db_manager.fetch_all(orig_req_sql, (original_req_id,))
                orig_req_str = ""
                if orig_rows:
                    m, u, h_json, b = orig_rows[0]
                    orig_req_str = "{} {}\n{}\n\n{}".format(m, u, "\n".join(json.loads(h_json)), b)
                
                print("[Attacker] Calling LLM for verification...")
                llm_res = llm.analyze_idor_vulnerability(orig_req_str, "Not Available", helpers.bytesToString(new_request_bytes), response_data)
                llm_result_str = json.dumps(llm_res)
                
                # Update status based on LLM
                if llm_res['result'] == 'VULNERABLE':
                    status = "VULNERABLE"
                elif llm_res['result'] == 'SAFE':
                    status = "SAFE"
                else:
                    status = "UNCERTAIN"
            else:
                status = "CHECKING_SKIPPED" # No LLM
        else:
            status = "FAILED" # Non-2xx
            
        # 7. Update DB
        update_sql = '''
        UPDATE attack_queue 
        SET status = ?, response_data = ?, response_code = ?, llm_verification_result = ?
        WHERE id = ?
        '''
        self.db_manager.execute_query(update_sql, (status, response_data, response_code, llm_result_str, attack_id))
        
        return {"id": attack_id, "status": status, "code": response_code}
