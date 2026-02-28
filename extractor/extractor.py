#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import json
try:
    from urllib import unquote
except ImportError:
    from urllib.parse import unquote

class ParameterExtractor:
    def __init__(self, db_manager):
        self.db_manager = db_manager

    def process_unanalyzed_requests(self):
        """
        Fetch unanalyzed requests from raw_requests table, extract parameters,
        save to parameter_pool, and mark request as analyzed.
        """
        # Step 1: Fetch data first using fetch_all (which opens and closes connection immediately)
        rows = self.db_manager.fetch_all(
            "SELECT id, method, host, url, path, query_params, body, user_identifier FROM raw_requests WHERE is_analyzed = 0 LIMIT 50"
        )
        
        if not rows:
            return

        # Step 2: Process data without holding an open cursor to the table we are reading from
        for row in rows:
            try:
                req_id, method, host, url, path, query_params_json, body, user_identifier = row
                
                print("[Extractor] Processing Request ID: " + str(req_id) + " (" + method + " " + path + ")")

                api_signature = self._generate_api_signature(method, host, path)
                
                # 1. Extract Query Params
                if query_params_json:
                    try:
                        q_params = json.loads(query_params_json)
                        if q_params:
                            for k, v in q_params.items():
                                self._save_param(api_signature, k, v, "QUERY", user_identifier, req_id)
                    except Exception as e:
                        print("[Extractor] Error parsing query params: " + str(e))

                # 2. Extract Body Params (JSON)
                # Simple check for JSON content
                if body and body.strip().startswith("{"):
                    try:
                        body_json = json.loads(body)
                        self._extract_json_params(api_signature, body_json, user_identifier, req_id)
                    except ValueError:
                        # Not valid JSON
                        pass
                    except Exception as e:
                        print("[Extractor] Error parsing body params: " + str(e))
                
                # 3. Extract Path Params (Heuristic: Numeric IDs or UUIDs)
                self._extract_path_params(api_signature, path, user_identifier, req_id)

                # Mark as analyzed with timestamp
                self.db_manager.execute_query(
                    "UPDATE raw_requests SET is_analyzed = 1, analyzed_at = CURRENT_TIMESTAMP WHERE id = ?", 
                    (req_id,)
                )
            except Exception as e:
                print("[Extractor] Error processing request {}: {}".format(req_id, str(e)))
                import traceback
                traceback.print_exc()

    def _generate_api_signature(self, method, host, path):
        # Normalize path to generate a signature
        # e.g. /api/user/123 -> /api/user/{id}
        # This is a simple heuristic.
        parts = path.split('/')
        normalized_parts = []
        for part in parts:
            if self._is_numeric(part):
                normalized_parts.append("{id}")
            elif self._is_uuid(part):
                normalized_parts.append("{uuid}")
            else:
                normalized_parts.append(part)
        
        normalized_path = "/".join(normalized_parts)
        return method + " " + host + normalized_path

    def _extract_path_params(self, api_signature, path, user_identifier, req_id):
        parts = path.split('/')
        for i, part in enumerate(parts):
            if self._is_numeric(part):
                # path_param_index is not ideal but works for position based replacement
                # Using a clearer name like 'path_3' (3rd segment)
                self._save_param(api_signature, "path_seg_" + str(i), part, "PATH", user_identifier, req_id)
            elif self._is_uuid(part):
                self._save_param(api_signature, "path_seg_" + str(i), part, "PATH", user_identifier, req_id)

    def _extract_json_params(self, api_signature, json_obj, user_identifier, req_id, prefix=""):
        if isinstance(json_obj, dict):
            for k, v in json_obj.items():
                key_name = prefix + k if prefix else k
                self._extract_json_params(api_signature, v, user_identifier, req_id, key_name + ".")
        elif isinstance(json_obj, list):
            # For lists, we can try to extract from items if they are primitives or dicts
            for i, item in enumerate(json_obj):
                key_name = prefix + str(i)
                self._extract_json_params(api_signature, item, user_identifier, req_id, key_name + ".")
        else:
            # Leaf node (string, int, bool, etc.)
            # Remove trailing dot from prefix
            param_name = prefix.rstrip(".")
            self._save_param(api_signature, param_name, str(json_obj), "BODY_JSON", user_identifier, req_id)

    def _save_param(self, api_signature, name, value, location, user_identifier, req_id):
        # We only care about "interesting" values? 
        # For now, save everything that looks like an ID or sensitive data.
        # Or save everything to allow full permutation.
        if not value:
            return

        # Calculate Risk Score
        risk_score = self.calculate_risk_score(name, value, location)

        sql = '''
            INSERT OR REPLACE INTO parameter_pool 
            (api_signature, param_name, param_value, location, user_identifier, risk_score)
            VALUES (?, ?, ?, ?, ?, ?)
        '''
        params = (api_signature, name, value, location, user_identifier, risk_score)
        
        # Use execute_query (which handles connection and commit)
        # Note: execute_query handles connection open/close internally for each call.
        # This might be slow for many params. But for safety against locking, it's better.
        self.db_manager.execute_query(sql, params)

    def calculate_risk_score(self, key, value, location):
        score = 0
        key = key.lower()
        
        # 1. Keyword Analysis (Weight: 40%)
        # High Risk
        high_risk_keywords = ["id", "user_id", "userid", "account_id", "member_id", "profile_id", "uuid", "guid", "oid", "pk"]
        for kw in high_risk_keywords:
            if kw == key or key.endswith("_" + kw) or key.endswith(kw):
                score += 40
                break
        
        # Medium Risk (Business Objects)
        if score == 0:
            medium_risk_keywords = ["order_no", "invoice", "ticket", "report", "file", "document", "transaction", "role", "group", "permission", "level", "admin"]
            for kw in medium_risk_keywords:
                if kw in key:
                    score += 20
                    break

        # 2. Value Analysis (Weight: 30%)
        # UUID
        if self._is_uuid(value):
            score += 30
        # Numeric ID (length > 3)
        elif self._is_numeric(value) and len(value) > 3:
            score += 20
        # Hash / Token (High entropy string)
        elif len(value) > 20 and not " " in value: # Rough heuristic for token/hash
            score += 15
            
        # 3. Location Analysis (Extra Weight)
        if location == "PATH":
            score += 10
        elif location == "BODY_JSON":
            score += 5
            
        # Cap score at 100
        return min(score, 100)

    def _is_numeric(self, s):
        return s.isdigit()

    def _is_uuid(self, s):
        uuid_regex = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
        return bool(uuid_regex.match(s))
