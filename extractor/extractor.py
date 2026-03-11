#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import json

try:
    from urllib import unquote
except ImportError:
    from urllib.parse import unquote
from helpers.llm_helper import LLMHelper


class ParameterExtractor:
    def __init__(self, db_manager):
        self.db_manager = db_manager

    def _is_blacklisted(self, param_name):
        """Check if parameter is in blacklist"""
        try:
            extender = getattr(self.db_manager, "extender", None)
            if extender and hasattr(extender, "blacklistParams"):
                blacklist_text = extender.blacklistParams.getText().strip()
                if blacklist_text:
                    blacklist = [p.strip() for p in blacklist_text.split(",")]
                    return param_name in blacklist
        except:
            pass
        return False

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

        # Initialize LLM Helper if enabled
        extender = getattr(self.db_manager, "extender", None)
        llm_helper = None
        if extender:
            try:
                if hasattr(extender, "enableLlm"):
                    if extender.enableLlm.isSelected():
                        llm_helper = LLMHelper(
                            extender.llmBaseUrl.getText(),
                            extender.llmApiKey.getText(),
                            extender.llmModel.getText(),
                        )
                        print("[Extractor] LLM Helper initialized successfully.")
                    else:
                        print("[Extractor] LLM Analysis is DISABLED in configuration.")
                else:
                    print("[Extractor] Error: extender has no enableLlm attribute.")
            except Exception as e_init:
                print("[Extractor] Error initializing LLM Helper: " + str(e_init))
        else:
            print("[Extractor] Warning: extender reference not found in db_manager.")

        # Step 2: Process data without holding an open cursor to the table we are reading from
        for row in rows:
            try:
                (
                    req_id,
                    method,
                    host,
                    url,
                    path,
                    query_params_json,
                    body,
                    user_identifier,
                ) = row

                print(
                    "[Extractor] Processing Request ID: "
                    + str(req_id)
                    + " ("
                    + method
                    + " "
                    + path
                    + ")"
                )

                api_signature = self._generate_api_signature(method, host, path)

                # 1. Extract Query Params
                if query_params_json:
                    try:
                        q_params = json.loads(query_params_json)
                        if q_params:
                            for k, v in q_params.items():
                                self._save_param(
                                    api_signature,
                                    k,
                                    v,
                                    "QUERY",
                                    user_identifier,
                                    req_id,
                                )
                    except Exception as e:
                        print("[Extractor] Error parsing query params: " + str(e))

                # 2. Extract Body Params (JSON)
                # Simple check for JSON content
                if body and body.strip().startswith("{"):
                    try:
                        body_json = json.loads(body)
                        self._extract_json_params(
                            api_signature, body_json, user_identifier, req_id
                        )
                    except ValueError:
                        # Not valid JSON
                        pass
                    except Exception as e:
                        print("[Extractor] Error parsing body params: " + str(e))

                # 3. Extract Path Params (Heuristic: Numeric IDs or UUIDs)
                self._extract_path_params(api_signature, path, user_identifier, req_id)

                # LLM Extraction
                if llm_helper:
                    req_data_for_llm = {
                        "method": method,
                        "path": path,
                        "query": query_params_json,
                        "body": body,
                    }

                    # A. Assist Parameter Extraction
                    if extender.llmExtractParams.isSelected():
                        try:
                            print(
                                "[Extractor] Running LLM Parameter Extraction for Req ID "
                                + str(req_id)
                            )
                            llm_params = llm_helper.extract_params(req_data_for_llm)
                            for p in llm_params:
                                # Ensure correct arg order: api_sig, name, value, location, user, req_id
                                self._save_param(
                                    api_signature,
                                    p["name"],
                                    p["value"],
                                    "LLM_" + p["type"],
                                    user_identifier,
                                    req_id,
                                )
                        except Exception as e_llm_ex:
                            print("[Extractor] LLM Extraction Error: " + str(e_llm_ex))
                            import traceback

                            traceback.print_exc()

                    # B. Generate Parameter Values (Fuzzing)
                    if extender.llmGenerateValues.isSelected():
                        try:
                            print(
                                "[Extractor] Running LLM Value Generation for Req ID "
                                + str(req_id)
                            )
                            fuzzed_values = llm_helper.generate_values(
                                req_data_for_llm, []
                            )
                            for fv in fuzzed_values:
                                # Save with special user "LLM-Fuzzer"
                                self._save_param(
                                    api_signature,
                                    fv["name"],
                                    fv["value"],
                                    "LLM_Gen",
                                    "LLM-Fuzzer",
                                    req_id,
                                )
                        except Exception as e_llm_gen:
                            print("[Extractor] LLM Generation Error: " + str(e_llm_gen))
                            import traceback

                            traceback.print_exc()

                # Mark as analyzed with timestamp
                self.db_manager.execute_query(
                    "UPDATE raw_requests SET is_analyzed = 1, analyzed_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (req_id,),
                )
            except Exception as e:
                print(
                    "[Extractor] Error processing request {}: {}".format(req_id, str(e))
                )
                import traceback

                traceback.print_exc()

    def _generate_api_signature(self, method, host, path):
        # Normalize path to generate a signature
        # e.g. /api/user/123 -> /api/user/{id}
        # e.g. /api/domains/aa5c08daa5154160a95e891506a44184/info -> /api/domains/{md5}/info
        parts = path.split("/")
        normalized_parts = []
        for part in parts:
            if self._is_numeric(part):
                normalized_parts.append("{id}")
            elif self._is_uuid(part):
                normalized_parts.append("{uuid}")
            else:
                hash_type = self._is_hash(part)
                if hash_type:
                    normalized_parts.append("{" + hash_type + "}")
                else:
                    normalized_parts.append(part)

        normalized_path = "/".join(normalized_parts)
        return method + " " + host + normalized_path

    def _extract_path_params(self, api_signature, path, user_identifier, req_id):
        parts = path.split("/")
        for i, part in enumerate(parts):
            param_type = None
            param_value = part

            # Detect parameter type
            if self._is_numeric(part):
                param_type = "id"
            elif self._is_uuid(part):
                param_type = "uuid"
            else:
                hash_type = self._is_hash(part)
                if hash_type:
                    param_type = hash_type

            # If this is a parameter, generate semantic name
            if param_type:
                param_name = self._generate_param_name(parts, i, param_type)
                self._save_param(
                    api_signature,
                    param_name,
                    param_value,
                    "PATH",
                    user_identifier,
                    req_id,
                )
                print(
                    "[Extractor] Extracted path param: {} = {} (type: {})".format(
                        param_name, param_value, param_type
                    )
                )

    def _extract_json_params(
        self, api_signature, json_obj, user_identifier, req_id, prefix=""
    ):
        if isinstance(json_obj, dict):
            for k, v in json_obj.items():
                key_name = prefix + k if prefix else k
                self._extract_json_params(
                    api_signature, v, user_identifier, req_id, key_name + "."
                )
        elif isinstance(json_obj, list):
            # For lists, we can try to extract from items if they are primitives or dicts
            for i, item in enumerate(json_obj):
                key_name = prefix + str(i)
                self._extract_json_params(
                    api_signature, item, user_identifier, req_id, key_name + "."
                )
        else:
            # Leaf node (string, int, bool, etc.)
            # Remove trailing dot from prefix
            param_name = prefix.rstrip(".")
            self._save_param(
                api_signature,
                param_name,
                str(json_obj),
                "BODY_JSON",
                user_identifier,
                req_id,
            )

    def _save_param(
        self, api_signature, name, value, location, user_identifier, req_id
    ):
        # We only care about "interesting" values?
        # For now, save everything that looks like an ID or sensitive data.
        # Or save everything to allow full permutation.
        if not value:
            return

        # Check blacklist
        if self._is_blacklisted(name):
            return

        # Ensure proper encoding for Chinese characters
        try:
            if isinstance(value, str):
                value = value.decode("utf-8") if hasattr(value, "decode") else value
            elif not isinstance(value, unicode):
                value = unicode(str(value), "utf-8", errors="ignore")
        except:
            pass

        # Calculate Risk Score
        risk_score = self.calculate_risk_score(name, value, location)

        sql = """
            INSERT OR REPLACE INTO parameter_pool 
            (api_signature, param_name, param_value, location, user_identifier, risk_score)
            VALUES (?, ?, ?, ?, ?, ?)
        """
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
        high_risk_keywords = [
            "id",
            "user_id",
            "userid",
            "account_id",
            "member_id",
            "profile_id",
            "uuid",
            "guid",
            "oid",
            "pk",
        ]
        for kw in high_risk_keywords:
            if kw == key or key.endswith("_" + kw) or key.endswith(kw):
                score += 40
                break

        # Medium Risk (Business Objects)
        if score == 0:
            medium_risk_keywords = [
                "order_no",
                "invoice",
                "ticket",
                "report",
                "file",
                "document",
                "transaction",
                "role",
                "group",
                "permission",
                "level",
                "admin",
            ]
            for kw in medium_risk_keywords:
                if kw in key:
                    score += 20
                    break

        # 2. Value Analysis (Weight: 30%)
        # UUID
        if self._is_uuid(value):
            score += 30
        # Hash (MD5/SHA1/SHA256)
        elif self._is_hash(value):
            score += 25
        # Numeric ID (length > 3)
        elif self._is_numeric(value) and len(value) > 3:
            score += 20
        # Hash / Token (High entropy string)
        elif len(value) > 20 and not " " in value:  # Rough heuristic for token/hash
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
        uuid_regex = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        return bool(uuid_regex.match(s))

    def _is_hash(self, s):
        """
        Identify common hash formats (MD5, SHA1, SHA256, Base64).
        Returns the hash type string if matched, False otherwise.
        """
        if not s:
            return False

        # Convert to string if needed
        s = str(s)

        # MD5: 32-character hexadecimal
        if re.match(r"^[0-9a-f]{32}$", s, re.IGNORECASE):
            return "md5"

        # SHA1: 40-character hexadecimal
        if re.match(r"^[0-9a-f]{40}$", s, re.IGNORECASE):
            return "sha1"

        # SHA256: 64-character hexadecimal
        if re.match(r"^[0-9a-f]{64}$", s, re.IGNORECASE):
            return "sha256"

        # Base64-like string (length > 20, alphanumeric with +/=)
        # Avoid false positives by checking length and character set
        if len(s) > 20 and re.match(r"^[A-Za-z0-9+/]+=*$", s):
            # Additional check: Base64 length should be multiple of 4 (with padding)
            if len(s) % 4 == 0:
                return "base64"

        return False

    def _is_param_like(self, s):
        """
        Check if a path segment looks like a parameter value.
        Returns True if it's numeric, UUID, or hash.
        """
        if not s:
            return False
        return self._is_numeric(s) or self._is_uuid(s) or bool(self._is_hash(s))

    def _generate_param_name(self, parts, index, param_type):
        """
        Generate semantic parameter name based on preceding path segment.

        Args:
            parts: List of path segments
            index: Current segment index
            param_type: Type of parameter ('id', 'uuid', 'md5', etc.)

        Returns:
            Semantic parameter name like 'users_id', 'domain_id', etc.
        """
        # Find the nearest non-parameter segment before this index
        prefix = "unknown"
        for j in range(index - 1, -1, -1):
            if parts[j] and not self._is_param_like(parts[j]):
                prefix = parts[j]
                break

        # Clean prefix: remove special characters, convert to lowercase
        prefix = re.sub(r"[^a-zA-Z0-9_]", "_", prefix)
        prefix = prefix.strip("_").lower()

        # Handle empty prefix
        if not prefix:
            prefix = "unknown"

        # Generate name: prefix_id
        return "{}_id".format(prefix)

        # Convert to string if needed
        s = str(s)

        # MD5: 32-character hexadecimal
        if re.match(r"^[0-9a-f]{32}$", s, re.IGNORECASE):
            return "md5"

        # SHA1: 40-character hexadecimal
        if re.match(r"^[0-9a-f]{40}$", s, re.IGNORECASE):
            return "sha1"

        # SHA256: 64-character hexadecimal
        if re.match(r"^[0-9a-f]{64}$", s, re.IGNORECASE):
            return "sha256"

        # Base64-like string (length > 20, alphanumeric with +/=)
        # Avoid false positives by checking length and character set
        if len(s) > 20 and re.match(r"^[A-Za-z0-9+/]+=*$", s):
            # Additional check: Base64 length should be multiple of 4 (with padding)
            if len(s) % 4 == 0:
                return "base64"

        return False
